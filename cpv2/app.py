import asyncio
import json
import os
import time
from collections import OrderedDict
from contextlib import asynccontextmanager, suppress
from uuid import UUID, uuid4

import psycopg
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse

from cpv2 import core, delivery, models
from cpv2.auth import Identity, Problem, audit, authenticate, challenge, verifier
from cpv2.db import MIGRATIONS, Database, one, rows
from cpv2.settings import DEFINITIONS, digest

# Indirection so tests can expire the /health cache without patching time.
_health_clock = time.monotonic

# Mutation body caps by path. Everything else stays at 32 KiB; the stats
# ingest route honors the producer outbox contract (1 MiB/event, same as the
# site MAX_BODY) so a full 512-player result is never a 413.
BODY_LIMITS = {"/v2/stats/results": core.STAT_MAX_BODY}


class Limits:
    def __init__(self, budget=1000):
        self.buckets = OrderedDict()
        self.window, self.total = 0, 0
        self.budget = budget

    def check(self, key, *, global_count=True, limit=120):
        window = int(time.monotonic() // 60)
        if self.window != window:
            self.window, self.total = window, 0
            self.buckets.clear()
        count = self.buckets.get(key, 0)
        # The shared budget binds only requests counted against it; health and
        # other uncounted paths draw from per-key limits alone.
        if (global_count and self.total >= self.budget) or count >= limit:
            raise Problem("rate_limit", 429)
        if key in self.buckets:
            self.buckets.move_to_end(key)
        elif len(self.buckets) >= 4096:
            # LRU eviction, never lockout: a flood of distinct keys must not
            # deny new legitimate sessions for the rest of the window.
            self.buckets.popitem(last=False)
        self.total += int(global_count)
        self.buckets[key] = count + 1


def create_app(dsn=None):
    database = Database(dsn or os.environ["CP_DATABASE_URL"])
    wakeups = delivery.Wakeups(dsn or os.environ["CP_DATABASE_URL"])

    @asynccontextmanager
    async def lifespan(app):
        await database.open()
        rebuild_task = None
        try:
            async with database.transaction() as conn:
                role = await one(
                    conn,
                    "SELECT rolsuper,rolcreaterole,rolcreatedb FROM pg_roles WHERE rolname=session_user",
                )
                owner = await one(
                    conn,
                    "SELECT nspowner::regrole::text AS owner FROM pg_namespace WHERE nspname='control'",
                )
                session = await one(conn, "SELECT session_user AS name")
                if (
                    role["rolsuper"]
                    or role["rolcreaterole"]
                    or role["rolcreatedb"]
                    or not owner
                    or owner["owner"] == session["name"]
                ):
                    raise RuntimeError(
                        "CP_DATABASE_URL must use the least-privilege runtime login"
                    )
                for table in (
                    "owner_memberships",
                    "owner_credentials",
                    "clients",
                    "setting_definitions",
                    "schema_migrations",
                ):
                    privilege = await one(
                        conn,
                        "SELECT has_table_privilege(%s,'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER') AS writable",
                        ("control." + table,),
                    )
                    if privilege["writable"]:
                        raise RuntimeError(
                            "runtime role can write protected bootstrap/catalog tables"
                        )
                privilege = await one(
                    conn, "SELECT has_schema_privilege('control','CREATE') AS writable"
                )
                if privilege["writable"]:
                    raise RuntimeError(
                        "runtime role can create protected schema objects"
                    )
                if not await one(conn, "SELECT 1 FROM owner_memberships LIMIT 1"):
                    raise RuntimeError("offline owner bootstrap required")
            await wakeups.start()
            # Rating replays run here, not in the void request: the request
            # only enqueues the season, this loop drains it.
            rebuild_task = asyncio.create_task(core.stat_rebuild_loop(database))
            yield
        finally:
            if rebuild_task is not None:
                rebuild_task.cancel()
                with suppress(asyncio.CancelledError):
                    await rebuild_task
            await wakeups.close()
            await database.close()

    app = FastAPI(
        title="Blockfield control-plane",
        version="2",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
    )
    app.state.db, app.state.wakeups = database, wakeups
    limiter = Limits()
    # Never-authenticated traffic draws from a separate small budget, so garbage
    # bearer strings cannot burn the shared budget that health checks and
    # authenticated agents rely on.
    unauth_limiter = Limits(budget=100)

    @app.exception_handler(Problem)
    async def problem_handler(request, error):
        return JSONResponse({"error": error.code}, status_code=error.status)

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request, error):
        return JSONResponse(
            {
                "error": "invalid_request",
                "fields": [list(e["loc"]) for e in error.errors()],
            },
            status_code=422,
        )

    @app.middleware("http")
    async def pipeline(request, call_next):
        attempt, identity = uuid4(), None
        mutation = request.method not in ("GET", "HEAD", "OPTIONS")
        public = request.url.path in ("/openapi.json", "/v1/openapi.json", "/health")
        auth_header = request.headers.get("authorization", "")
        token = (
            auth_header[7:]
            if auth_header.startswith("Bearer ") and len(auth_header) < 256
            else ""
        )
        request.state.attempt = attempt
        key = (
            verifier(token)
            if token
            else (request.client.host if request.client else "unknown")
        )
        try:
            # Per-key bound only: pre-auth traffic must not burn the shared
            # budget, which counts authenticated requests below.
            limiter.check(key, global_count=False)
            if not public:
                try:
                    async with database.transaction() as conn:
                        identity = await authenticate(conn, token)
                except Problem:
                    # Legacy tokens only retain the temporary read-only compatibility route.
                    if request.method == "GET" and request.url.path == "/v1/gate":
                        async with database.transaction() as conn:
                            legacy = await one(
                                conn,
                                "SELECT 1 FROM legacy_read_tokens WHERE verifier=%s AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>now())",
                                (verifier(token),),
                            )
                        if not legacy:
                            unauth_limiter.check(key)
                            raise
                    else:
                        unauth_limiter.check(key)
                        if mutation:
                            async with database.transaction() as conn:
                                await audit(
                                    conn,
                                    attempt,
                                    None,
                                    request.method,
                                    request.url.path,
                                    "pending",
                                )
                        raise
            if identity:
                if identity.actor:
                    limiter.check(("actor", str(identity.actor)), global_count=False)
                # The shared budget counts authenticated requests only.
                limiter.check(
                    ("client", identity.client["id"]), global_count=True, limit=600
                )
                limiter.check(
                    (
                        "resource",
                        str(identity.actor or identity.client["id"]),
                        request.url.path,
                    ),
                    global_count=False,
                )
            request.state.identity, request.state.token = identity, token
            if mutation:
                async with database.transaction() as conn:
                    await audit(
                        conn,
                        attempt,
                        identity,
                        request.method,
                        request.url.path,
                        "pending",
                    )
                chunks, size = [], 0
                limit = BODY_LIMITS.get(request.url.path, 32768)
                async with asyncio.timeout(5):
                    async for chunk in request.stream():
                        size += len(chunk)
                        if size > limit:
                            raise Problem("body_too_large", 413)
                        chunks.append(chunk)
                request._body = b"".join(chunks)
                if (
                    request._body
                    and request.headers.get("content-type", "").split(";")[0]
                    != "application/json"
                ):
                    raise Problem("json_required", 415)
            if request.url.path.endswith("/events"):
                response = await call_next(request)
            else:
                async with asyncio.timeout(10):
                    response = await call_next(request)
            if mutation and response.status_code >= 400:
                async with database.transaction() as conn:
                    await audit(
                        conn,
                        attempt,
                        identity,
                        request.method,
                        request.url.path,
                        "denied" if response.status_code in (401, 403) else "invalid",
                        {"httpStatus": response.status_code},
                    )
            if (
                mutation
                and response.status_code < 400
                and not getattr(request.state, "completed_audited", False)
            ):
                async with database.transaction() as conn:
                    await audit(
                        conn,
                        attempt,
                        identity,
                        request.method,
                        request.url.path,
                        "completed",
                        {"httpStatus": response.status_code},
                        getattr(request.state, "operation", None),
                    )
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Request-ID"] = str(attempt)
            return response
        except Problem as error:
            if mutation and error.code != "rate_limit":
                async with database.transaction() as conn:
                    await audit(
                        conn,
                        attempt,
                        identity,
                        request.method,
                        request.url.path,
                        "denied",
                        {"code": error.code},
                    )
            return JSONResponse({"error": error.code}, status_code=error.status)
        except (psycopg.Error, TimeoutError):
            return JSONResponse(
                {"error": "control_unavailable", "requestId": str(attempt)},
                status_code=503,
            )

    async def write(request, function, *args, **kwargs):
        async with database.transaction() as conn:
            identity = await authenticate(conn, request.state.token)
            result = await function(
                conn, identity, request.state.attempt, *args, **kwargs
            )
            request.state.operation = (
                UUID(result["operationId"]) if "operationId" in result else None
            )
            audit_identity = identity
            if request.state.operation is not None:
                attributed = await one(
                    conn,
                    "SELECT account_id FROM operations WHERE id=%s",
                    (request.state.operation,),
                )
                if attributed and attributed["account_id"] != identity.actor:
                    # Service staff writes attribute the asserted actor; the
                    # completion audit carries it while credential/client stay
                    # on the record. Identical for every direct call.
                    audit_identity = Identity(
                        identity.credential,
                        identity.client,
                        {"id": attributed["account_id"]},
                        identity.grants,
                        identity.owner,
                    )
            # The completion audit commits atomically with the mutation: a
            # post-commit audit failure rolls the mutation back instead of
            # discarding a one-time response such as a delegation token.
            await audit(
                conn,
                request.state.attempt,
                audit_identity,
                request.method,
                request.url.path,
                "completed",
                None,
                request.state.operation,
            )
            request.state.completed_audited = True
            return result

    def assertion(request):
        try:
            value = request.headers.get("x-cp-owner-assertion")
            return json.loads(value) if value and len(value) <= 8192 else None
        except ValueError:
            raise Problem("invalid_owner_assertion", 422) from None

    health_ok_until = 0.0
    # Last version read from control.schema_migrations; reported when the
    # database is unreachable and no newer read exists.
    health_schema = len(MIGRATIONS)

    @app.get("/health")
    async def health():
        # CP-H5: unauthenticated liveness + readiness. 200 only when the
        # control database answers, the owner bootstrap is present, and the
        # stats migration is applied. Never leak DSNs, errors or gate state.
        nonlocal health_ok_until, health_schema
        # Public route: cache success so probe floods cannot drain the DB pool;
        # failures re-check, since an outage has no pool left to protect.
        if _health_clock() < health_ok_until:
            return {"status": "ok", "schema": health_schema}
        try:
            async with database.transaction() as conn:
                bootstrapped = await one(
                    conn, "SELECT EXISTS(SELECT 1 FROM owner_memberships) AS ok"
                )
                applied = await one(
                    conn, "SELECT MAX(version) AS version FROM schema_migrations"
                )
        except Exception:
            return JSONResponse(
                {"status": "unavailable", "schema": health_schema}, status_code=503
            )
        version = (
            applied["version"] if applied and applied["version"] is not None else 0
        )
        health_schema = version
        if not bootstrapped or not bootstrapped["ok"] or version < len(MIGRATIONS):
            return JSONResponse(
                {"status": "unavailable", "schema": version}, status_code=503
            )
        health_ok_until = _health_clock() + 5
        return {"status": "ok", "schema": version}

    @app.get("/v1/openapi.json")
    async def openapi():
        return app.openapi()

    @app.get("/v2/me")
    async def me(request: Request):
        i = request.state.identity
        return {
            "accountId": str(i.actor) if i.actor else None,
            "client": i.client["id"],
            "via": i.client["via"],
            "owner": i.owner,
            "grants": [
                {
                    k: g[k]
                    for k in (
                        "role",
                        "environment",
                        "backend",
                        "resource",
                        "revision",
                        "expires_at",
                    )
                }
                for g in i.grants
            ],
            "ceiling": sorted(set(i.credential["ceiling"]) & set(i.client["ceiling"])),
        }

    @app.post("/v2/owner/challenges", status_code=201)
    async def owner_challenge(body: models.Challenge, request: Request):
        async with database.transaction() as conn:
            i = await authenticate(conn, request.state.token)
            result = await challenge(conn, i, body.method, body.path, body.body)
            await audit(
                conn,
                request.state.attempt,
                i,
                "owner.challenge",
                body.path,
                "accepted",
                {"actionHash": digest(body.body)},
            )
            return result

    @app.get("/v2/settings/catalog")
    async def catalog(
        request: Request,
        environment: str = "prod",
        backend: str = "game",
        target: str = "*",
    ):
        request.state.identity.require("settings.read", environment, backend, target)
        return {
            name: {
                "schemaVersion": 1,
                "schema": d.model.model_json_schema(),
                "default": d.model().model_dump(),
                "readScope": d.read,
                "writeScope": d.write,
                "ownerPaths": d.owner_paths,
                "timing": d.timing,
                "sensitivity": d.sensitivity,
            }
            for name, d in DEFINITIONS.items()
        }

    @app.get("/v2/settings/{namespace}/{target}", response_model=models.SettingsView)
    async def get_settings(
        namespace: str,
        target: str,
        request: Request,
        environment: str = "prod",
        backend: str = "game",
    ):
        if namespace == "gate" and target == "workshop":
            # The workshop reporter authenticates with the leg's write scope,
            # not the global settings read scope: whoever may report the leg
            # may read it back to report idempotently (no write when unchanged).
            if not request.state.identity.allows(
                "settings.read", environment, backend, target
            ):
                request.state.identity.require(
                    "workshop.gate", environment, backend, target
                )
        else:
            request.state.identity.require(
                "settings.read", environment, backend, target
            )
        async with database.transaction() as conn:
            value = await core.current_settings(
                conn, namespace, environment, backend, target
            )
            return {
                "initialized": value["initialized"],
                "revision": value["revision"],
                "value": value["value"],
                "hash": value["value_hash"],
                "application": "see operation receipts",
            }

    @app.patch(
        "/v2/settings/{namespace}/{target}",
        status_code=202,
        response_model=models.OperationReceipt,
    )
    async def patch_settings(
        namespace: str, target: str, body: models.SettingsChange, request: Request
    ):
        return await write(
            request,
            core.settings_change,
            namespace,
            target,
            body,
            assertion=assertion(request),
            path=request.url.path,
        )

    @app.post("/v2/settings/{namespace}/{target}/validate")
    async def validate_settings(
        namespace: str, target: str, body: models.SettingsChange, request: Request
    ):
        return await write(
            request, core.settings_change, namespace, target, body, validate=True
        )

    @app.post(
        "/v2/gate/toggle", status_code=202, response_model=models.OperationReceipt
    )
    async def gate_toggle(body: models.GateToggle, request: Request):
        return await write(request, core.gate_toggle, body)

    @app.post(
        "/v2/settings/{namespace}/{target}/rollback",
        status_code=202,
        response_model=models.OperationReceipt,
    )
    async def rollback_settings(
        namespace: str, target: str, body: models.Rollback, request: Request
    ):
        return await write(
            request,
            core.settings_change,
            namespace,
            target,
            body,
            assertion=assertion(request),
            path=request.url.path,
            rollback=True,
        )

    @app.get("/v2/staff/grants")
    async def staff_grants(
        request: Request,
        accountId: UUID,
        environment: str = "prod",
        backend: str = "game",
    ):
        # Roster read for the provisioned site service principal: live grants
        # plus the compare-and-set revision for the account the site uses.
        # staff.read lives in no human role or owner scope, so only a service
        # credential provisioned with it passes the require below.
        i = request.state.identity
        i.require("staff.read", environment, backend, "*")
        async with database.transaction() as conn:
            target = await one(
                conn,
                "SELECT id, authorization_epoch FROM accounts WHERE id=%s",
                (accountId,),
            )
            if not target:
                raise Problem("account_not_found", 404)
            grants = await rows(
                conn,
                "SELECT role, environment, backend, resource, revision, expires_at FROM role_grants WHERE account_id=%s AND environment=%s AND backend=%s AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>now()) ORDER BY role, environment, backend, resource",
                (accountId, environment, backend),
            )
            await audit(
                conn,
                request.state.attempt,
                i,
                "staff.grants.read",
                str(accountId),
                "accepted",
            )
            return {
                "accountId": str(accountId),
                "expectedRevision": target["authorization_epoch"],
                "grants": [
                    {
                        "role": g["role"],
                        "environment": g["environment"],
                        "backend": g["backend"],
                        "resource": g["resource"],
                        "revision": g["revision"],
                        "expires_at": g["expires_at"],
                    }
                    for g in grants
                ],
            }

    @app.post(
        "/v2/staff/grants", status_code=202, response_model=models.OperationReceipt
    )
    async def grants(body: models.GrantChange, request: Request):
        return await write(
            request, core.grant_change, body, assertion(request), request.url.path
        )

    @app.post(
        "/v2/accounts/{account_id}/test-status",
        status_code=202,
        response_model=models.OperationReceipt,
    )
    async def account_test(account_id: UUID, body: models.TestStatus, request: Request):
        return await write(
            request,
            core.test_status,
            account_id,
            body,
            assertion(request),
            request.url.path,
        )

    @app.post(
        "/v2/actions/{kind}", status_code=202, response_model=models.OperationReceipt
    )
    async def action(kind: str, body: dict, request: Request):
        # Raw dict: core.action picks the per-kind model (kick/ban keep
        # models.Action, the say/list/... replacements use ModerationAction).
        return await write(request, core.action, kind, body)

    @app.post(
        "/v2/workshop/{kind}",
        status_code=202,
        response_model=models.OperationReceipt,
    )
    async def workshop(kind: str, body: models.WorkshopAction, request: Request):
        return await write(
            request,
            core.workshop_op,
            kind,
            body,
            assertion(request),
            request.url.path,
        )

    @app.post("/v2/delegations", status_code=201)
    async def delegation(body: models.Delegation, request: Request):
        return await write(request, core.delegate, body)

    @app.delete("/v2/sessions/current")
    async def revoke(request: Request):
        async with database.transaction() as conn:
            i = await authenticate(conn, request.state.token, lock_credential=False)
            await one(
                conn,
                "SELECT id FROM credentials WHERE id=%s FOR UPDATE",
                (i.credential["id"],),
            )
            await conn.execute(
                "UPDATE credentials SET revoked_at=now() WHERE id=%s OR parent_id=%s",
                (i.credential["id"], i.credential["id"]),
            )
            await audit(
                conn, request.state.attempt, i, "sessions.revoke", "current", "accepted"
            )
            await conn.execute("SELECT pg_notify('cp_events','')")
            return {"revoked": True}

    @app.post("/v2/stats/results")
    async def stats_ingest(body: dict, request: Request):
        # The producer outbox acknowledges 200/201 JSON carrying inserted and
        # the exact eventId; anything else stays under rejected/ for review.
        # The write path commits the completion audit in the same transaction
        # as the insert, like site sessions.
        result = await write(request, core.stat_ingest, body)
        return JSONResponse(result, status_code=201 if result["inserted"] else 200)

    def stats_query(request, default_period=None):
        # The site read contracts parse raw query strings (limit "007" is
        # valid, "25.0" is a 400): keep them strings and let core.stat_filters
        # apply the same validation.
        params = {}
        for key in ("mode", "season", "period", "sort", "limit", "page"):
            value = request.query_params.get(key)
            if value is not None:
                params[key] = value
        if (
            default_period is not None
            and "season" not in params
            and "period" not in params
        ):
            params["period"] = default_period
        return params

    @app.get("/v2/stats/seasons")
    async def stats_seasons(request: Request):
        request.state.identity.require("stats.read", "prod", "game", "*")
        seasons = core.stat_seasons()
        return {
            "schemaVersion": 1,
            "current": seasons[-1]["id"] if seasons else None,
            "seasons": seasons,
        }

    @app.get("/v2/stats/leaderboard")
    async def stats_leaderboard(request: Request):
        request.state.identity.require("stats.read", "prod", "game", "*")
        query = core.stat_filters(stats_query(request))
        async with database.transaction() as conn:
            return await core.stat_leaderboard(conn, query)

    @app.get("/v2/stats/players/{player_uuid}")
    async def stats_player(player_uuid: str, request: Request):
        request.state.identity.require("stats.read", "prod", "game", "*")
        query = core.stat_filters(stats_query(request))
        async with database.transaction() as conn:
            return await core.stat_player(conn, query, player_uuid)

    @app.get("/v2/stats/hitreg")
    async def stats_hitreg(request: Request):
        request.state.identity.require("stats.read", "prod", "game", "*")
        # Staff-only window like the site admin hit-reg report: the last
        # 7 days unless a season or period is given.
        query = core.stat_filters(stats_query(request, "week"))
        async with database.transaction() as conn:
            return await core.stat_hitreg(conn, query)

    @app.post("/v2/stats/results/void")
    async def stats_void(body: models.StatVoid, request: Request):
        return await write(request, core.stat_void, body)

    @app.post("/v2/site/sessions", status_code=201)
    async def site_session_create(body: models.SiteSessionCreate, request: Request):
        # The write path commits the completion audit in the same transaction
        # as the mutation, so a post-commit audit failure rolls the session
        # back instead of losing its one-time id.
        return await write(request, core.site_session_create, body)

    @app.get("/v2/site/sessions/{session_id}")
    async def site_session_read(session_id: str, request: Request):
        async with database.transaction() as conn:
            identity = await authenticate(conn, request.state.token)
            result = await core.site_session_read(conn, identity, session_id)
        if result is None:
            # Expired (or concurrently revoked): the cleanup above already
            # committed, so 404 here instead of raising inside the transaction
            # and rolling it back.
            raise Problem("session_not_found", 404)
        return result

    @app.delete("/v2/site/sessions/{session_id}")
    async def site_session_revoke(session_id: str, request: Request):
        return await write(request, core.site_session_revoke, session_id)

    @app.delete("/v2/site/users/{player_uuid}/sessions")
    async def site_sessions_revoke_user(player_uuid: str, request: Request):
        return await write(request, core.site_sessions_revoke_user, player_uuid)

    @app.get("/v2/operations/{operation_id}")
    async def operation(operation_id: UUID, request: Request):
        async with database.transaction() as conn:
            return await core.read_operation(conn, request.state.identity, operation_id)

    @app.get("/v2/audit")
    async def get_audit(
        request: Request,
        after: int = 0,
        environment: str = "prod",
        backend: str = "game",
        target: str = "*",
    ):
        i = request.state.identity
        i.require("audit.read", environment, backend, target)
        async with database.transaction() as conn:
            if i.allows("audit.full", environment, backend, target):
                result = await rows(
                    conn,
                    "SELECT * FROM audit_events WHERE sequence>%s AND (%s='*' OR environment=%s) AND (%s='*' OR backend=%s) AND (%s='*' OR resource=%s) ORDER BY sequence LIMIT 100",
                    (after, environment, environment, backend, backend, target, target),
                )
            else:
                # Non-owner audit is restricted to this actor; query parameters cannot widen it.
                result = await rows(
                    conn,
                    "SELECT sequence,attempt_id,operation_id,action,target,outcome,recorded_at FROM audit_events WHERE sequence>%s AND actor=%s AND (%s='*' OR environment=%s) AND (%s='*' OR backend=%s) AND (%s='*' OR resource=%s) ORDER BY sequence LIMIT 100",
                    (
                        after,
                        i.actor,
                        environment,
                        environment,
                        backend,
                        backend,
                        target,
                        target,
                    ),
                )
            await audit(
                conn,
                uuid4(),
                i,
                "audit.read",
                target,
                "allowed",
                {"after": after},
                scope=(environment, backend, target),
            )
            return result

    @app.get("/v1/gate")
    async def legacy_gate(request: Request):
        i = request.state.identity
        if i and not (
            i.allows("gate:read", "prod", "game", "*")
            or i.allows("settings.read", "prod", "game", "*")
        ):
            raise Problem("forbidden")
        async with database.transaction() as conn:
            setting = await core.current_settings(conn, "gate", "prod", "game", "*")
            if not setting["initialized"]:
                raise Problem("gate_not_initialized", 503)
            value = {
                "revision": setting["revision"],
                **setting["value"],
                "since": int(setting["state_since"].timestamp() * 1000),
            }
            return {"schema": 1, **value, "observedAt": int(time.time() * 1000)}

    @app.get("/v2/events")
    async def user_events(
        request: Request,
        after: int = 0,
        environment: str = "prod",
        backend: str = "game",
        target: str = "*",
    ):
        request.state.identity.require("operations.read", environment, backend, target)
        if after < 0:
            raise Problem("invalid_cursor", 422)
        cid = "observer:" + str(request.state.identity.credential["id"])
        waiter = wakeups.subscribe(cid)

        async def stream():
            cursor = after
            try:
                while True:
                    waiter.clear()
                    async with database.transaction() as conn:
                        i = await authenticate(conn, request.state.token)
                        i.require("operations.read", environment, backend, target)
                        records = await rows(
                            conn,
                            "SELECT e.sequence,e.operation_id,e.status,e.detail,e.at FROM operation_events e JOIN operations o ON o.id=e.operation_id WHERE e.sequence>%s AND o.account_id=%s AND o.environment=%s AND o.backend=%s AND (%s='*' OR o.resource=%s) ORDER BY e.sequence LIMIT 64",
                            (cursor, i.actor, environment, backend, target, target),
                        )
                    for record in records:
                        envelope = {
                            "schema": 2,
                            "sequence": record["sequence"],
                            "operationId": str(record["operation_id"]),
                            "status": record["status"],
                            "detail": record["detail"],
                            "at": record["at"].isoformat(),
                        }
                        yield (
                            "id: "
                            + str(record["sequence"])
                            + "\nevent: operation\ndata: "
                            + json.dumps(envelope)
                            + "\n\n"
                        )
                        cursor = record["sequence"]
                    if len(records) == 64:
                        continue
                    try:
                        await asyncio.wait_for(waiter.wait(), 10)
                    except TimeoutError:
                        yield ": heartbeat\n\n"
            except (Problem, psycopg.Error):
                yield 'event: resync\ndata: {"error":"reconnect_required"}\n\n'
            finally:
                wakeups.unsubscribe(cid, waiter)

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"X-Accel-Buffering": "no"},
        )

    @app.get("/v2/agents/{cid}/snapshot")
    async def agent_snapshot(cid: str, request: Request):
        async with database.transaction() as conn:
            result = await delivery.snapshot(conn, request.state.identity, cid)
            await audit(
                conn,
                uuid4(),
                request.state.identity,
                "agents.snapshot",
                cid,
                "allowed",
                {"hash": result["hash"]},
            )
            return result

    @app.post("/v2/agents/{cid}/acks", response_model=models.AckReceipt)
    async def ack(cid: str, body: models.Ack, request: Request):
        return await write(request, delivery.acknowledge, cid, body)

    @app.get("/v2/agents/{cid}/events")
    async def agent_events(cid: str, request: Request, epoch: UUID, cursor: int = 0):
        last = request.headers.get("last-event-id")
        if last:
            try:
                epoch_text, cursor_text = last.split(":")
                epoch, cursor = UUID(epoch_text), int(cursor_text)
            except ValueError:
                raise Problem("invalid_cursor", 422) from None
        async with database.transaction() as conn:
            if last:
                consumer = await delivery.consumer_for(
                    conn, request.state.identity, cid, "agents.events"
                )
                # SSE IDs confirm transmission, not receipt; replay anything
                # beyond the durable ACK cursor after a dropped connection.
                cursor = min(cursor, consumer["received_cursor"])
            await delivery.batch(conn, request.state.identity, cid, epoch, cursor)
        waiter = wakeups.subscribe(cid)

        async def stream():
            nonlocal cursor
            try:
                while True:
                    waiter.clear()
                    async with database.transaction() as conn:
                        i = await authenticate(conn, request.state.token)
                        envelopes = await delivery.batch(
                            conn, i, cid, epoch, cursor, live=True
                        )
                    for envelope in envelopes:
                        yield delivery.sse(envelope)
                        cursor = envelope["sequence"]
                    if len(envelopes) == 64:
                        continue
                    try:
                        await asyncio.wait_for(waiter.wait(), 10)
                    except TimeoutError:
                        yield ": heartbeat\n\n"
            except (Problem, psycopg.Error):
                yield 'event: resync\ndata: {"error":"reconnect_required"}\n\n'
            finally:
                wakeups.unsubscribe(cid, waiter)

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"X-Accel-Buffering": "no"},
        )

    return app
