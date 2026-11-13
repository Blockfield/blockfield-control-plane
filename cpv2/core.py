import hashlib
import json
import math
import re
import secrets
import unicodedata
from datetime import datetime, timedelta, timezone
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from psycopg.types.json import Jsonb
from pydantic import ValidationError

from cpv2.auth import (
    ROLE_SCOPES,
    SITE_SETTINGS_SCOPES,
    Identity,
    Problem,
    audit,
    covers,
    invalidate,
    now,
    step_up,
    verifier,
)
from cpv2 import models
from cpv2.db import one, record, rows
from cpv2.settings import DEFINITIONS, WorkshopGate, changed, digest, merge


def gate_model(namespace, target, definition):
    # The workshop leg lives in the gate namespace at target "workshop" so
    # the proxy consumer (settings.gate, resource *) receives it in the same
    # snapshot/frames as the game leg; its value shape is the controller
    # states the file gate carried, not the game modes.
    if namespace == "gate" and target == "workshop":
        return WorkshopGate
    return definition.model


# Deterministic namespace for service-principal account ids: a service
# credential has no account, so its writes attribute a stable per-client
# principal instead of NULL, never a human account.
SERVICE_PRINCIPAL_NAMESPACE = uuid5(
    NAMESPACE_URL, "https://blockfield/control-plane/service-principal"
)


def service_principal_id(client_id):
    name = f"service:{client_id}"[:128]
    return uuid5(SERVICE_PRINCIPAL_NAMESPACE, name), name


async def service_principal(conn, identity):
    """Stable id attributing a service-credential write.

    settings_revisions.actor is NOT NULL REFERENCES accounts. The row is
    created offline by provision(), which runs privileged; the runtime
    (cp_runtime, no INSERT on accounts) only resolves the id. The display
    name ("service:<client id>") marks the row as a service principal; no
    credential ever points at it (credentials stay account-less by CHECK),
    so it can never authenticate or hold grants.
    """
    principal, _ = service_principal_id(identity.client["id"])
    return principal


async def event(conn, op, state, detail=None):
    await record(
        conn,
        "INSERT INTO operation_events(operation_id,status,detail) VALUES(%s,%s,%s)",
        (op, state, Jsonb(detail or {})),
    )
    await conn.execute("UPDATE operations SET status=%s WHERE id=%s", (state, op))
    await conn.execute(
        "SELECT a.id FROM accounts a JOIN operations o ON o.account_id=a.id WHERE o.id=%s FOR KEY SHARE OF a",
        (op,),
    )
    await conn.execute(
        "SELECT c.id FROM credentials c JOIN operations o ON o.credential_id=c.id WHERE o.id=%s FOR KEY SHARE OF c",
        (op,),
    )
    await record(
        conn,
        "INSERT INTO audit_events(attempt_id,operation_id,actor,credential_id,client_id,via,request_id,action,target,environment,backend,resource,outcome,detail) SELECT id,id,account_id,credential_id,client_id,via,id,kind,target,environment,backend,resource,%s,%s FROM operations WHERE id=%s",
        (state, Jsonb(detail or {}), op),
    )
    await conn.execute("SELECT pg_notify('cp_events','')")


async def operation(
    conn, identity, kind, target, body, scope, seconds=60, generation=None
):
    fingerprint = digest({"kind": kind, "target": target, "body": body})
    # Serialize each credential's idempotency namespace, including simultaneous retries.
    await conn.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
        (str(identity.credential["id"]) + body["idempotencyKey"],),
    )
    prior = await one(
        conn,
        "SELECT * FROM operations WHERE credential_id=%s AND idempotency_key=%s",
        (identity.credential["id"], body["idempotencyKey"]),
    )
    if prior:
        if prior["request_hash"] != fingerprint:
            raise Problem("idempotency_conflict", 409)
        return prior, True
    op = await one(
        conn,
        "INSERT INTO operations(id,account_id,credential_id,client_id,via,kind,target,resource,environment,backend,request_hash,idempotency_key,authorization_epoch,required_scope,expected_revision,generation,deadline,status) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'accepted') RETURNING *",
        (
            uuid4(),
            identity.actor,
            identity.credential["id"],
            identity.client["id"],
            identity.client["via"],
            kind,
            target,
            body.get("resource", target),
            body["environment"],
            body["backend"],
            fingerprint,
            body["idempotencyKey"],
            identity.account["authorization_epoch"] if identity.account else None,
            scope,
            body.get("expectedRevision"),
            generation,
            now() + timedelta(seconds=seconds),
        ),
    )
    await event(conn, op["id"], "accepted")
    return op, False


def receipt(op):
    return {
        "operationId": str(op["id"]),
        "revision": op["revision"],
        "status": op["status"],
        "result": op["result"],
    }


async def finish(conn, attempt, identity, op, detail, *, effective=False):
    await conn.execute(
        "UPDATE operations SET result=%s WHERE id=%s", (Jsonb(detail), op["id"])
    )
    if effective:
        await event(conn, op["id"], "effective")
    await audit(
        conn, attempt, identity, op["kind"], op["target"], "accepted", detail, op["id"]
    )
    return receipt(await one(conn, "SELECT * FROM operations WHERE id=%s", (op["id"],)))


async def current_settings(conn, namespace, environment, backend, target):
    definition = DEFINITIONS.get(namespace)
    if not definition:
        raise Problem("unknown_namespace", 404)
    record = await one(
        conn,
        "SELECT r.* FROM settings_heads h JOIN settings_revisions r USING(namespace,environment,backend,target,revision) WHERE h.namespace=%s AND h.environment=%s AND h.backend=%s AND h.target=%s",
        (namespace, environment, backend, target),
    )
    if record:
        return {**record, "initialized": True}
    if namespace == "gate" and (environment, backend, target) == ("prod", "game", "*"):
        legacy = await one(conn, "SELECT value FROM legacy_gate")
        if legacy:
            value = {k: legacy["value"][k] for k in ("mode", "message")}
            return {
                "initialized": True,
                "revision": legacy["value"]["revision"],
                "value": value,
                "value_hash": digest(value),
                "state_since": datetime.fromtimestamp(
                    legacy["value"]["since"] / 1000, timezone.utc
                ),
            }
    default = gate_model(namespace, target, definition)()
    return {
        "initialized": False,
        "revision": 0,
        "value": default.model_dump(),
        "value_hash": digest(default.model_dump()),
    }


async def enqueue(conn, op, consumers, payload, revision=None):
    for consumer in sorted(consumers, key=lambda c: c["id"]):
        c = await one(
            conn,
            "UPDATE consumers SET next_sequence=next_sequence+1 WHERE id=%s RETURNING *",
            (consumer["id"],),
        )
        await conn.execute(
            "INSERT INTO outbox(consumer_id,sequence,epoch,operation_id,generation,revision,payload,payload_hash) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                c["id"],
                c["next_sequence"] - 1,
                c["epoch"],
                op["id"],
                c["generation"],
                revision,
                Jsonb(payload),
                digest(payload),
            ),
        )
        await conn.execute("SELECT pg_notify('cp_events',%s)", (c["id"],))


async def settings_change(
    conn,
    identity,
    attempt,
    namespace,
    target,
    model,
    *,
    assertion=None,
    path="",
    rollback=False,
    validate=False,
):
    definition = DEFINITIONS.get(namespace)
    if not definition:
        raise Problem("unknown_namespace", 404)
    data = models.request_body(model)
    env, backend = data["environment"], data["backend"]
    # The workshop leg is reported by the workshop service, not toggled by
    # game-entry admins: it carries its own service-holdable write scope.
    scope = (
        "workshop.gate"
        if (namespace, target) == ("gate", "workshop")
        else definition.write
    )
    identity.require(scope, env, backend, target)
    # The game-leg gate (any non-workshop gate target) asserts like gameplay:
    # its moderation.ban write scope would otherwise mint an account-less
    # operation that delivery fences. The workshop leg keeps the
    # stable-principal path below.
    site_asserted = scope in SITE_SETTINGS_SCOPES or (
        namespace == "gate" and target != "workshop"
    )
    if site_asserted and identity.credential["kind"] == "service":
        # The site principal asserts the logged-in admin (like staff/
        # moderation): CP re-resolves that actor's account, live grants and
        # owner membership, then the actor's own grants decide. Only the
        # unbound site principal may assert an actor. The game-leg gate PATCH
        # (moderation.ban at a non-workshop target) asserts the same way, so
        # its operation carries a human account past delivery; other service
        # scopes (workshop.gate, moderation.ban for inbox actions) keep the
        # stable-principal path, and protected paths still fail closed below
        # (owner step-up needs a direct owner session).
        if model.actorAccountId is None:
            raise Problem("service_actor_required")
        # Only the unbound site principal may assert an actor; a scoped
        # consumer would otherwise act as any admin whose grant covers it.
        if identity.credential["resource"] != "*":
            raise Problem("actor_forbidden")
        # FOR SHARE like authenticate(): a concurrent revocation of this actor
        # (FOR UPDATE + invalidate) waits for this change to commit.
        actor = await one(
            conn,
            "SELECT * FROM accounts WHERE id=%s FOR SHARE",
            (model.actorAccountId,),
        )
        if not actor:
            raise Problem("account_not_found", 404)
        if actor["is_test"] or actor["status"] != "active":
            raise Problem("ineligible_account")
        identity = Identity(
            identity.credential,
            identity.client,
            actor,
            await rows(
                conn,
                "SELECT * FROM role_grants WHERE account_id=%s AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>%s)",
                (actor["id"], now()),
            ),
            bool(
                await one(
                    conn,
                    "SELECT 1 FROM owner_memberships WHERE account_id=%s",
                    (actor["id"],),
                )
            ),
        )
        identity.require(scope, env, backend, target)
    elif model.actorAccountId is not None:
        raise Problem("actor_forbidden")
    if scope == "workshop.gate" and identity.account is None and (rollback or validate):
        # The controller reports its leg with PATCH only: rollback/validate
        # under this scope are refused at accept (delivery would reject a
        # non-patch service-issued op anyway, so this only fails fast).
        raise Problem("forbidden")
    op, duplicate = (
        (None, False)
        if validate
        else await operation(
            conn,
            identity,
            f"settings.{namespace}.{'rollback' if rollback else 'patch'}",
            target,
            data,
            scope,
            seconds=86400,
        )
    )
    if duplicate:
        return receipt(op)
    if validate:
        before = await current_settings(conn, namespace, env, backend, target)
        head = {"revision": before["revision"]}
    else:
        await conn.execute(
            "INSERT INTO settings_heads VALUES(%s,%s,%s,%s,0) ON CONFLICT DO NOTHING",
            (namespace, env, backend, target),
        )
        head = await one(
            conn,
            "SELECT * FROM settings_heads WHERE namespace=%s AND environment=%s AND backend=%s AND target=%s FOR UPDATE",
            (namespace, env, backend, target),
        )
        before = await current_settings(conn, namespace, env, backend, target)
    if head["revision"] != data["expectedRevision"]:
        raise Problem("revision_conflict", 409)
    if rollback:
        old = await one(
            conn,
            "SELECT value FROM settings_revisions WHERE namespace=%s AND environment=%s AND backend=%s AND target=%s AND revision=%s",
            (namespace, env, backend, target, data["revision"]),
        )
        if not old:
            raise Problem("revision_not_found", 404)
        candidate = old["value"]
    else:
        # gameplay.ai was removed (coordination#56): the model silently drops it
        # from legacy rows, so an explicit write must be refused, not ignored.
        if namespace == "gameplay" and (data["patch"] or {}).get("ai") is not None:
            raise Problem("invalid_settings", 422)
        candidate = merge(before["value"], data["patch"])
    try:
        after = (
            gate_model(namespace, target, definition)
            .model_validate(candidate)
            .model_dump()
        )
    except ValidationError:
        raise Problem("invalid_settings", 422) from None
    diff = changed(before["value"], after)
    # Paths nest under dict fields (sessions.<uuid>), so a protected subtree
    # matches by prefix.
    protected = any(
        field == path or field.startswith(path + ".")
        for field in diff
        for path in definition.owner_paths
    )
    if protected:
        identity.require("settings.protected.write", env, backend, target)
        if not validate:
            await step_up(
                conn, identity, assertion, "POST" if rollback else "PATCH", path, data
            )
            # The delivery-time recheck must enforce every permission the
            # accepted diff required, not just the strongest one: retain the
            # namespace write scope alongside the protected-write scope.
            await conn.execute(
                "UPDATE operations SET required_scope=%s WHERE id=%s",
                (definition.write + ",settings.protected.write", op["id"]),
            )
    if validate:
        await audit(
            conn,
            attempt,
            identity,
            "settings.validate",
            target,
            "validated",
            {"beforeHash": before["value_hash"], "afterHash": digest(after)},
        )
        return {"value": after, "diff": diff, "ownerApprovalRequired": protected}
    revision = head["revision"] + 1
    if revision > 9223372036854775807:
        raise Problem("revision_exhausted", 409)
    actor = identity.actor
    if actor is None:
        # Service-credential write (the workshop gate leg): attribute the
        # stable service principal instead of failing the NOT NULL actor.
        actor = await service_principal(conn, identity)
    await conn.execute(
        "INSERT INTO settings_revisions(namespace,environment,backend,target,revision,base_revision,value,diff,value_hash,operation_id,actor,rollback_of,state_since) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        (
            namespace,
            env,
            backend,
            target,
            revision,
            head["revision"],
            Jsonb(after),
            Jsonb(diff),
            digest(after),
            op["id"],
            actor,
            data["revision"] if rollback else None,
            before.get("state_since", now())
            if namespace == "gate"
            and before["value"].get("mode", before["value"].get("state"))
            == after.get("mode", after.get("state"))
            else now(),
        ),
    )
    await conn.execute(
        "UPDATE settings_heads SET revision=%s WHERE namespace=%s AND environment=%s AND backend=%s AND target=%s",
        (revision, namespace, env, backend, target),
    )
    await conn.execute(
        "UPDATE operations SET revision=%s WHERE id=%s", (revision, op["id"])
    )
    consumers = await rows(
        conn,
        "SELECT * FROM consumers WHERE environment=%s AND backend=%s AND %s=ANY(capabilities) AND (resource='*' OR resource=%s OR %s='*')",
        (env, backend, f"settings.{namespace}", target, target),
    )
    await enqueue(
        conn,
        op,
        consumers,
        {
            "kind": "settings",
            "namespace": namespace,
            "target": target,
            "value": after,
            "timing": definition.timing,
        },
        revision,
    )
    return await finish(
        conn,
        attempt,
        identity,
        op,
        {
            "beforeHash": before["value_hash"],
            "afterHash": digest(after),
            "diff": diff,
            "revision": revision,
        },
    )


async def gate_toggle(conn, identity, attempt, model):
    # Single-call gate update: server-side read-modify-write, so the site
    # sends one POST instead of GET /v1/gate + PATCH. Audit, auth scope and
    # idempotency match PATCH: the head row is locked first, then the change
    # goes through settings_change. A redelivery reuses the stored
    # expectedRevision, so its idempotency fingerprint matches the original.
    data = models.request_body(model)
    env, backend = data["environment"], data["backend"]
    # Same lock order as operation()/settings_change (idempotency advisory lock,
    # then the head row); the reverse order deadlocks against a concurrent
    # PATCH that reuses this key. Advisory xact locks are re-entrant.
    await conn.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
        (str(identity.credential["id"]) + data["idempotencyKey"],),
    )
    await conn.execute(
        "INSERT INTO settings_heads VALUES(%s,%s,%s,%s,0) ON CONFLICT DO NOTHING",
        ("gate", env, backend, "*"),
    )
    head = await one(
        conn,
        "SELECT * FROM settings_heads WHERE namespace=%s AND environment=%s AND backend=%s AND target=%s FOR UPDATE",
        ("gate", env, backend, "*"),
    )
    prior = await one(
        conn,
        "SELECT * FROM operations WHERE credential_id=%s AND idempotency_key=%s",
        (identity.credential["id"], data["idempotencyKey"]),
    )
    expected = head["revision"]
    if (
        prior is not None
        and prior["kind"] == "settings.gate.patch"
        and prior["expected_revision"] is not None
    ):
        expected = prior["expected_revision"]
    return await settings_change(
        conn,
        identity,
        attempt,
        "gate",
        "*",
        models.SettingsChange(
            idempotencyKey=data["idempotencyKey"],
            environment=env,
            backend=backend,
            expectedRevision=expected,
            patch={"mode": data["mode"], "message": data["message"]},
            actorAccountId=data.get("actorAccountId"),
        ),
    )


async def grant_change(conn, identity, attempt, model, assertion, path):
    data = model.model_dump(mode="json")
    env, backend, target = data["environment"], data["backend"], data["resource"]
    scope = "staff.admin.manage" if data["role"] == "admin" else "staff.lower.manage"
    identity.require(scope, env, backend, target)
    if identity.credential["kind"] == "service":
        # The site principal asserts the logged-in human; the same peer and
        # owner step-up rules below then evaluate that actor like a direct
        # call. role_grants.grantor is NOT NULL, so an actor is always required.
        if model.actorAccountId is None:
            raise Problem("service_actor_required")
        # Only the unbound site principal may assert an actor; a scoped
        # consumer would otherwise act as any admin whose grant covers it.
        if identity.credential["resource"] != "*":
            raise Problem("actor_forbidden")
        # FOR SHARE like authenticate(): a concurrent revocation of this actor
        # (FOR UPDATE + invalidate) waits for this change to commit.
        actor = await one(
            conn,
            "SELECT * FROM accounts WHERE id=%s FOR SHARE",
            (model.actorAccountId,),
        )
        if not actor:
            raise Problem("account_not_found", 404)
        if actor["is_test"] or actor["status"] != "active":
            raise Problem("ineligible_account")
        identity = Identity(
            identity.credential,
            identity.client,
            actor,
            await rows(
                conn,
                "SELECT * FROM role_grants WHERE account_id=%s AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>%s)",
                (actor["id"], now()),
            ),
            bool(
                await one(
                    conn,
                    "SELECT 1 FROM owner_memberships WHERE account_id=%s",
                    (actor["id"],),
                )
            ),
        )
        identity.require(scope, env, backend, target)
    elif model.actorAccountId is not None:
        raise Problem("actor_forbidden")
    if identity.actor == model.accountId:
        raise Problem("self_role_edit")
    op, duplicate = await operation(
        conn, identity, "staff.grants", str(model.accountId), data, scope
    )
    if duplicate:
        return receipt(op)
    if await one(
        conn, "SELECT 1 FROM owner_memberships WHERE account_id=%s", (model.accountId,)
    ):
        raise Problem("protected_owner")
    if not identity.owner and await one(
        conn,
        "SELECT 1 FROM role_grants WHERE account_id=%s AND role='admin' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>now())",
        (model.accountId,),
    ):
        raise Problem("peer_role_edit")
    account = await one(
        conn, "SELECT * FROM accounts WHERE id=%s FOR UPDATE", (model.accountId,)
    )
    if not account:
        raise Problem("account_not_found", 404)
    if await one(
        conn, "SELECT 1 FROM owner_memberships WHERE account_id=%s", (model.accountId,)
    ):
        raise Problem("protected_owner")
    if account["is_test"] or account["status"] != "active":
        raise Problem("ineligible_account")
    existing_admin = await one(
        conn,
        "SELECT 1 FROM role_grants WHERE account_id=%s AND role='admin' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>now())",
        (model.accountId,),
    )
    if existing_admin and not identity.owner:
        raise Problem("peer_role_edit")
    if account["authorization_epoch"] != model.expectedRevision:
        raise Problem("revision_conflict", 409)
    if data["role"] == "admin" or existing_admin:
        await step_up(conn, identity, assertion, "POST", path, data)
    if model.revoke:
        await conn.execute(
            "UPDATE role_grants SET revoked_at=now() WHERE account_id=%s AND role=%s AND environment=%s AND backend=%s AND resource=%s AND revoked_at IS NULL",
            (model.accountId, model.role, env, backend, target),
        )
    else:
        await conn.execute(
            "INSERT INTO role_grants(id,account_id,role,environment,backend,resource,grantor,revision) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                uuid4(),
                model.accountId,
                model.role,
                env,
                backend,
                target,
                identity.actor,
                account["authorization_epoch"] + 1,
            ),
        )
    await invalidate(conn, model.accountId)
    return await finish(
        conn,
        attempt,
        identity,
        op,
        {"authorizationEpoch": account["authorization_epoch"] + 1},
        effective=True,
    )


async def test_status(conn, identity, attempt, account_id, model, assertion, path):
    data = model.model_dump(mode="json")
    identity.require(
        "accounts.test.manage", model.environment, model.backend, str(account_id)
    )
    op, duplicate = await operation(
        conn,
        identity,
        "accounts.test-status",
        str(account_id),
        data,
        "accounts.test.manage",
    )
    if duplicate:
        return receipt(op)
    account = await one(
        conn, "SELECT * FROM accounts WHERE id=%s FOR UPDATE", (account_id,)
    )
    if not account:
        raise Problem("account_not_found", 404)
    if await one(
        conn, "SELECT 1 FROM owner_memberships WHERE account_id=%s", (account_id,)
    ):
        raise Problem("protected_owner")
    if account["authorization_epoch"] != model.expectedRevision:
        raise Problem("revision_conflict", 409)
    await step_up(conn, identity, assertion, "POST", path, data)
    await conn.execute(
        "UPDATE accounts SET is_test=true,test_reason=%s,test_expires_at=%s WHERE id=%s",
        (model.reason, now() + timedelta(seconds=model.expiresInSeconds), account_id),
    )
    await invalidate(conn, account_id)
    return await finish(conn, attempt, identity, op, {"isTest": True}, effective=True)


# Site RCON replacements (admin.ts rconCommand): typed moderation commands the
# mod applies from its SSE stream. Scopes equal kinds; site `moderate`
# maps to the moderator role, site `ban` (pardon) to admin.
MODERATION_COMMANDS = (
    "moderation.say",
    "moderation.list",
    "moderation.pardon",
    "moderation.team-kick",
    "moderation.class-lock",
    "moderation.class-unlock",
    "moderation.range",
    "moderation.stop-room",
    "moderation.maintenance",
    "moderation.announce",
)
MODERATION_MAINTENANCE_OPS = ("status", "drain", "resume", "interrupt")
SERVER_WIDE_KINDS = ("console.run", "moderation.maintenance", "moderation.announce")
# Read-only console lines (scope console.read); anything else needs
# console.run. The game and the agent MCP enforce the same list.
CONSOLE_READ_ONLY = re.compile(
    r"list( uuids)?|tick query|bf maintenance status|banlist( players| ips)?"
    r"|whitelist list|spark (tps|health|gc|tickmonitor)( --?[a-z-]+| [0-9]+)*"
)
MODERATION_PLAYER = re.compile(r"[A-Za-z0-9_]{3,16}")
MODERATION_CLASS = re.compile(r"[a-z0-9_]{1,32}")
MODERATION_ROOM = re.compile(r"[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}")
MODERATION_RANGE_OPS = ("open", "close", "reset")
MODERATION_OUTCOMES = ("none", "draw", "RED", "BLUE")


def _moderation_text(value, *, required=True, problem="invalid_moderation_text"):
    # Same wire rule as the site text(): control characters and § become
    # spaces, runs collapse, and the result is 1-120 chars not starting
    # with `/` (so it can never become a different server command).
    if value is None and not required:
        return ""
    if not isinstance(value, str):
        raise Problem(problem, 422)
    clean = re.sub(
        r" {2,}",
        " ",
        "".join(
            " " if c == "§" or unicodedata.category(c) == "Cc" else c for c in value
        ),
    ).strip()
    if (not clean and required) or len(clean) > 120 or clean.startswith("/"):
        raise Problem(problem, 422)
    return clean


def _moderation_payload(kind, data):
    base = {"kind": kind, "target": data["target"]}
    name = kind[len("moderation.") :]
    if name == "say":
        return base | {"text": _moderation_text(data["text"])}
    if name in ("list", "announce"):
        return base
    if name == "maintenance":
        op = data["op"]
        if op not in MODERATION_MAINTENANCE_OPS:
            raise Problem("invalid_moderation_maintenance", 422)
        if op != "interrupt":
            return base | {"op": op}
        return base | {"op": op, "reason": _moderation_text(data["reason"])}
    if name in ("pardon", "team-kick"):
        player = data["player"]
        if not isinstance(player, str) or MODERATION_PLAYER.fullmatch(player) is None:
            raise Problem("invalid_moderation_player", 422)
        return base | {"player": player}
    if name in ("class-lock", "class-unlock"):
        class_id = data["classId"]
        if (
            not isinstance(class_id, str)
            or MODERATION_CLASS.fullmatch(class_id) is None
        ):
            raise Problem("invalid_moderation_class", 422)
        return base | {"classId": class_id}
    if name == "range":
        if data["op"] not in MODERATION_RANGE_OPS:
            raise Problem("invalid_moderation_range", 422)
        return base | {"op": data["op"]}
    room = data["roomId"]
    if not isinstance(room, str) or MODERATION_ROOM.fullmatch(room) is None:
        raise Problem("invalid_moderation_room", 422)
    if data["outcome"] not in MODERATION_OUTCOMES:
        raise Problem("invalid_moderation_outcome", 422)
    reason = _moderation_text(data["reason"], required=False)
    if data["outcome"] == "none" and re.match(r"^(win|draw)\b", reason):
        raise Problem("invalid_moderation_reason", 422)
    payload = base | {"roomId": room, "outcome": data["outcome"]}
    return payload | {"reason": reason} if reason else payload


async def action(conn, identity, attempt, kind, body):
    if kind in ("moderation.kick", "moderation.ban"):
        try:
            data = models.Action.model_validate(body).model_dump(mode="json")
        except ValidationError:
            raise Problem("invalid_action", 422) from None
        payload = {
            "kind": kind,
            "target": data["target"],
            "playerId": data["playerId"],
            "reason": data["reason"],
        }
    elif kind in MODERATION_COMMANDS:
        try:
            data = models.ModerationAction.model_validate(body).model_dump(mode="json")
        except ValidationError:
            raise Problem("invalid_action", 422) from None
        payload = _moderation_payload(kind, data)
    elif kind == "console.run":
        try:
            data = models.ConsoleRun.model_validate(body).model_dump(mode="json")
        except ValidationError:
            raise Problem("invalid_action", 422) from None
        # One line as typed: a control character could smuggle a second
        # command or forge log lines (same rule as the site console).
        command = data["command"].strip().lstrip("/").strip()
        if not command or any(unicodedata.category(c) == "Cc" for c in command):
            raise Problem("invalid_console_command", 422)
        read_only = CONSOLE_READ_ONLY.fullmatch(command) is not None
        payload = {
            "kind": kind,
            "target": "*",
            "command": command,
            "readOnly": read_only,
        }
    else:
        raise Problem("unknown_action", 404)
    data_target = payload["target"]
    # Console lines, maintenance and the restart notice act on the whole
    # server: a resource-scoped grant or credential must never reach them
    # through a server-wide consumer.
    if kind in SERVER_WIDE_KINDS and data_target != "*":
        raise Problem("server_wide_target", 422)
    scope = (
        ("console.read" if payload["readOnly"] else "console.run")
        if kind == "console.run"
        else kind
    )
    identity.require(scope, data["environment"], data["backend"], data_target)
    # Announce carries no human: its text is fixed in the game. Console lines
    # may come from an owner-provisioned agent token without an actor.
    actorless = kind in ("moderation.announce", "console.run")
    if kind == "moderation.announce" and data["actorAccountId"] is not None:
        raise Problem("actor_forbidden")
    if identity.credential["kind"] == "service" and (
        data["actorAccountId"] is not None or not actorless
    ):
        # The site principal asserts the logged-in human; the same scope,
        # peer and grant rules below then evaluate that actor like a direct
        # call. role_grants-independent moderation still needs an actor, so
        # an unasserted service call is refused before any operation exists.
        if data["actorAccountId"] is None:
            raise Problem("service_actor_required")
        # Only the unbound site principal may assert an actor; a scoped
        # consumer would otherwise act as any moderator whose grant covers it.
        if identity.credential["resource"] != "*":
            raise Problem("actor_forbidden")
        # FOR SHARE like authenticate(): a concurrent revocation of this actor
        # (FOR UPDATE + invalidate) waits for this change to commit.
        actor = await one(
            conn,
            "SELECT * FROM accounts WHERE id=%s FOR SHARE",
            (UUID(data["actorAccountId"]),),
        )
        if not actor:
            raise Problem("account_not_found", 404)
        if actor["is_test"] or actor["status"] != "active":
            raise Problem("ineligible_account")
        identity = Identity(
            identity.credential,
            identity.client,
            actor,
            await rows(
                conn,
                "SELECT * FROM role_grants WHERE account_id=%s AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>%s)",
                (actor["id"], now()),
            ),
            bool(
                await one(
                    conn,
                    "SELECT 1 FROM owner_memberships WHERE account_id=%s",
                    (actor["id"],),
                )
            ),
        )
        identity.require(scope, data["environment"], data["backend"], data_target)
    elif (
        identity.credential["kind"] != "service" and data["actorAccountId"] is not None
    ):
        raise Problem("actor_forbidden")
    op, duplicate = await operation(
        conn,
        identity,
        kind,
        data_target,
        data,
        scope,
        data["expiresInSeconds"],
        data["generation"],
    )
    if duplicate:
        return receipt(op)
    consumer = await one(
        conn, "SELECT * FROM consumers WHERE id=%s FOR UPDATE", (data["consumerId"],)
    )
    if (
        not consumer
        or str(consumer["generation"]) != str(data["generation"])
        or consumer["environment"] != data["environment"]
        or consumer["backend"] != data["backend"]
        or not covers(consumer["resource"], data_target)
        or kind not in consumer["capabilities"]
    ):
        raise Problem("consumer_generation_or_capability", 409)
    unsettled = await one(
        conn,
        "SELECT count(*) AS n FROM outbox o JOIN operations p ON p.id=o.operation_id WHERE o.consumer_id=%s AND (p.kind LIKE 'moderation.%%' OR p.kind='console.run') AND p.deadline>now() AND NOT EXISTS(SELECT 1 FROM consumer_acks a WHERE a.consumer_id=o.consumer_id AND a.sequence=o.sequence AND a.state IN ('effective','rejected','unknown'))",
        (data["consumerId"],),
    )
    if (
        consumer["next_sequence"] - consumer["received_cursor"] > 128
        or unsettled["n"] >= 128
    ):
        raise Problem("consumer_lag", 409)
    await enqueue(
        conn,
        op,
        [consumer],
        payload,
    )
    return await finish(
        conn,
        attempt,
        identity,
        op,
        {
            "payloadHash": digest(payload),
            # The audit row keeps the console line itself, not only its hash.
            **(
                {"command": payload["command"], "readOnly": payload["readOnly"]}
                if kind == "console.run"
                else {}
            ),
        },
    )


async def delegate(conn, identity, attempt, model):
    if (
        not identity.account
        or identity.credential["kind"] != "session"
        or not identity.client["human"]
        or identity.owner
    ):
        raise Problem("delegation_not_allowed")
    lower = set().union(*ROLE_SCOPES.values()) - {"staff.lower.manage", "audit.read"}
    if any(
        scope not in lower
        or not identity.allows(scope, model.environment, model.backend, model.resource)
        for scope in model.scopes
    ):
        raise Problem("delegation_ceiling")
    op, duplicate = await operation(
        conn,
        identity,
        "delegations.create",
        model.resource,
        model.model_dump(mode="json"),
        "operations.read",
    )
    if duplicate:
        return {
            **receipt(op),
            "credentialId": op["result"]["credentialId"],
            "token": None,
        }
    # Tokens are returned once, never retained in operations or audit responses.
    token = "cp2_" + secrets.token_urlsafe(32)
    cid = uuid4()
    await conn.execute(
        "INSERT INTO credentials(id,verifier,account_id,client_id,ceiling,environment,backend,resource,kind,authorization_epoch,parent_id,expires_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,'delegation',%s,%s,%s)",
        (
            cid,
            verifier(token),
            identity.actor,
            identity.client["id"],
            model.scopes,
            model.environment,
            model.backend,
            model.resource,
            identity.account["authorization_epoch"],
            identity.credential["id"],
            min(
                now() + timedelta(seconds=model.expiresInSeconds),
                identity.credential["expires_at"],
            ),
        ),
    )
    result = await finish(
        conn,
        attempt,
        identity,
        op,
        {"credentialId": str(cid), "scopes": model.scopes},
        effective=True,
    )
    return {**result, "credentialId": str(cid), "token": token}


async def read_operation(conn, identity, op_id):
    op = await one(conn, "SELECT * FROM operations WHERE id=%s FOR UPDATE", (op_id,))
    if not op:
        raise Problem("operation_not_found", 404)
    # The issuing credential reads its own operation while it still holds
    # every scope the operation required, at the operation's bounds: a
    # service caller (site, agent MCP) polls console/list output without
    # operations.read or audit.read, but a narrowed credential falls back to
    # the ordinary checks below.
    issuer = op["credential_id"] == identity.credential["id"] and all(
        identity.allows(scope, op["environment"], op["backend"], op["resource"])
        for scope in op["required_scope"].split(",")
    )
    if not issuer:
        identity.require(
            "operations.read", op["environment"], op["backend"], op["resource"]
        )
        if op["account_id"] != identity.actor and not identity.allows(
            "audit.read", op["environment"], op["backend"], op["resource"]
        ):
            raise Problem("forbidden")
    if op["deadline"] <= now() and op["status"] in (
        "accepted",
        "received",
        "validated",
    ):
        # Desired state persists in settings heads; expiry settles delivery.
        # With no outbox rows nothing was ever queued, so there is no failed
        # delivery to declare and the read must not fabricate one.
        if await one(conn, "SELECT 1 FROM outbox WHERE operation_id=%s", (op["id"],)):
            await event(conn, op_id, "expired")
            op["status"] = "expired"
    receipts = await rows(
        conn,
        "SELECT consumer_id,sequence,state,result,actual_at,recorded_at FROM consumer_acks WHERE (consumer_id,sequence) IN (SELECT consumer_id,sequence FROM outbox WHERE operation_id=%s) ORDER BY recorded_at",
        (op_id,),
    )
    result = receipt(op)
    result["receipts"] = receipts
    result["deadline"] = op["deadline"]
    return result


# Workshop operations: the CP-side producer for the op kinds the Workshop
# subscriber applies (members/message/wake/cancel plus release.select).
# Payloads are exactly what the Workshop apply_cp_operation/apply_cp_releases
# consume, plus the authorized target so the consumer can check an operation
# is addressed to itself; enqueue() stores digest(payload) as the frame
# payload hash, the same canonical JSON the Workshop verifies (sort_keys,
# compact separators).
WORKSHOP_SCOPES = {
    "members": "workshop.members",
    "message": "workshop.message",
    "wake": "workshop.wake",
    "cancel": "workshop.cancel",
    "release.select": "workshop.release.select",
    "map": "workshop.map",
    "sessions": "workshop.sessions",
    "ai-key": "workshop.ai-key",
    "mode": "workshop.mode",
}
WORKSHOP_NAME = re.compile(r"[A-Za-z0-9_]{3,16}")
WORKSHOP_ROLES = ("builder", "lead", "admin")
WORKSHOP_RELEASE = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+")
# Same advisory bound the Workshop applies to snapshot release records.
WORKSHOP_MEMBERS_LIMIT = 256


def _workshop_identity(value):
    # Workshop actor: draslId normalizes like the consumer member(), the name
    # follows the same 3-16 [A-Za-z0-9_] rule. Extra keys are dropped: the
    # consumer overrides role itself and rejects anything else.
    if not isinstance(value, dict):
        raise Problem("invalid_workshop_actor", 422)
    drasl = value.get("draslId")
    if not isinstance(drasl, str):
        raise Problem("invalid_workshop_actor", 422)
    normalized = drasl.replace("-", "").lower()
    if len(normalized) != 32 or any(c not in "0123456789abcdef" for c in normalized):
        raise Problem("invalid_workshop_actor", 422)
    name = value.get("name")
    if not isinstance(name, str) or WORKSHOP_NAME.fullmatch(name) is None:
        raise Problem("invalid_workshop_actor", 422)
    return {"draslId": normalized, "name": name}


def _workshop_member(value):
    if not isinstance(value, dict) or set(value) - {
        "draslId",
        "name",
        "role",
        "maps",
    }:
        raise Problem("invalid_workshop_members", 422)
    entry = _workshop_identity(value)
    role = value.get("role", "builder")
    if role not in WORKSHOP_ROLES:
        raise Problem("invalid_workshop_members", 422)
    if role != "builder":
        entry["role"] = role
    maps = value.get("maps")
    if maps is not None:
        if not isinstance(maps, list) or any(
            not isinstance(item, str) for item in maps
        ):
            raise Problem("invalid_workshop_members", 422)
        entry["maps"] = list(maps)
    return entry


def _workshop_message(value):
    # Same wire rule the Workshop enforces: at most 200 chars, no control
    # characters or section signs. Empty text removes the override there.
    if not isinstance(value, str) or len(value) > 200:
        raise Problem("invalid_workshop_message", 422)
    if "§" in value or any(unicodedata.category(char) == "Cc" for char in value):
        raise Problem("invalid_workshop_message", 422)
    return value


# Remaining inbox kinds (map/sessions/ai-key/mode). Bounds mirror the site
# writers (blockfield-site src/lib/admin.ts writeRequest) and the Workshop
# consumer (controller _apply/_map_change/_apply_ai_key); the live catalog
# (known map ids) stays consumer-side, like the members maps rule.
_WORKSHOP_MAP_ID = re.compile(r"^[a-z0-9_]{1,32}$")
_WORKSHOP_NEW_MAP_ID = re.compile(r"^[a-z0-9][a-z0-9_]{0,31}$")
_WORKSHOP_RESERVED_MAP_IDS = ("hub", "lobby", "limbo")
_WORKSHOP_ARENA_MODES = (
    "campaign",
    "room",
    "tdm",
    "snipers",
    "awp",
    "deathmatch",
    "training",
)
_WORKSHOP_BRANCH = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_WORKSHOP_COPY_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_WORKSHOP_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_WORKSHOP_AI_KEY = re.compile(r"[\x21-\x7e]{20,2048}")
_WORKSHOP_PROVIDER_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
_WORKSHOP_AI_PRESETS = ("openrouter", "vercel-gateway")
# Preset key files/statuses a custom provider id must never collide with
# (controller AI_PROVIDER_RESERVED_IDS): openrouter.key, gateway.key,
# ai-key.json, ai-gateway-key.json.
_WORKSHOP_AI_RESERVED = frozenset(
    {"openrouter", "vercel-gateway", "gateway", "ai-key", "ai-gateway-key"}
)


def _workshop_map_title(value):
    if (
        not isinstance(value, str)
        or "§" in value
        or any(unicodedata.category(char) == "Cc" for char in value)
    ):
        raise Problem("invalid_workshop_map", 422)
    name = value.strip()
    if not 1 <= len(name) <= 100:
        raise Problem("invalid_workshop_map", 422)
    return name


def _workshop_map(model):
    # Map ids are outside any scoped grant (same rule as members maps): map
    # operations require a global target; the consumer checks catalog membership.
    if model.target != "*":
        raise Problem("invalid_workshop_map", 422)
    map_op = model.mapOp
    if map_op not in ("map-create", "map-properties"):
        raise Problem("invalid_workshop_map", 422)
    map_id = model.mapId
    if map_op == "map-create":
        if (
            not isinstance(map_id, str)
            or _WORKSHOP_NEW_MAP_ID.fullmatch(map_id) is None
            or map_id in _WORKSHOP_RESERVED_MAP_IDS
        ):
            raise Problem("invalid_workshop_map", 422)
    elif not isinstance(map_id, str) or _WORKSHOP_MAP_ID.fullmatch(map_id) is None:
        raise Problem("invalid_workshop_map", 422)
    name = _workshop_map_title(model.name)
    revision = model.expectedRevision
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise Problem("invalid_workshop_map", 422)
    partial = {
        "mapOp": map_op,
        "mapId": map_id,
        "name": name,
        "expectedRevision": revision,
    }
    if map_op == "map-create":
        modes = model.supportedModes
        if (
            not isinstance(modes, list)
            or not 1 <= len(modes) <= 7
            # str check before set(): unhashable elements must 422, not 500.
            or not all(isinstance(mode, str) for mode in modes)
            or len(set(modes)) != len(modes)
            or any(mode not in _WORKSHOP_ARENA_MODES for mode in modes)
        ):
            raise Problem("invalid_workshop_map", 422)
        partial["supportedModes"] = list(modes)
    else:
        if (
            not isinstance(model.workingCopyId, str)
            or _WORKSHOP_COPY_UUID.fullmatch(model.workingCopyId) is None
        ):
            raise Problem("invalid_workshop_map", 422)
        partial["workingCopyId"] = model.workingCopyId
    return partial


def _workshop_sessions(model):
    if model.target != "*":
        raise Problem("invalid_workshop_sessions", 422)
    offset = model.offset
    if (
        isinstance(offset, bool)
        or not isinstance(offset, int)
        or not 0 <= offset <= 1000000
    ):
        raise Problem("invalid_workshop_sessions", 422)
    limit = 100 if model.limit is None else model.limit
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise Problem("invalid_workshop_sessions", 422)
    return {"offset": offset, "limit": limit}


def _workshop_ai_key(model, fields_set):
    # Keys are write-only like the inbox: validation errors never echo them,
    # and audit/result rows carry no key material (only the payload hash).
    if model.target != "*":
        raise Problem("invalid_workshop_aikey", 422)
    provider = model.provider
    if not isinstance(provider, str) or (
        provider not in _WORKSHOP_AI_PRESETS
        and (
            _WORKSHOP_PROVIDER_ID.fullmatch(provider) is None
            or provider in _WORKSHOP_AI_RESERVED
        )
    ):
        raise Problem("invalid_workshop_aikey", 422)
    if "key" not in fields_set:
        raise Problem("invalid_workshop_aikey", 422)
    key = model.key
    if key is not None and (
        not isinstance(key, str) or _WORKSHOP_AI_KEY.fullmatch(key) is None
    ):
        raise Problem("invalid_workshop_aikey", 422)
    return {"provider": provider, "key": key}


def _workshop_mode_map_id(value):
    return isinstance(value, str) and (
        value == "hub" or _WORKSHOP_MAP_ID.fullmatch(value) is not None
    )


def _workshop_mode(model):
    if model.target != "*":
        raise Problem("invalid_workshop_mode", 422)
    profile = model.profile
    if profile not in ("game", "workshop", "test"):
        raise Problem("invalid_workshop_mode", 422)
    revision = model.expectedRevision
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise Problem("invalid_workshop_mode", 422)
    recover = model.recover is True
    if recover and profile != "game":
        raise Problem("invalid_workshop_mode", 422)
    # Every profile carries only its own fields (mirrors the inbox writer:
    # archived sessionId only toward workshop, modeId only for a test).
    if profile != "workshop" and (
        model.session is not None
        or model.maps is not None
        or model.branches is not None
        or model.sessionId is not None
    ):
        raise Problem("invalid_workshop_mode", 422)
    if profile != "test" and (
        model.candidateId is not None or model.modeId is not None
    ):
        raise Problem("invalid_workshop_mode", 422)
    partial = {"profile": profile, "expectedRevision": revision}
    if recover:
        partial["recover"] = True
    if profile == "workshop":
        session = model.session
        if session not in ("new", "resume"):
            raise Problem("invalid_workshop_mode", 422)
        if session == "new":
            maps = model.maps
            if maps is not None and (
                not isinstance(maps, list)
                or not maps
                # str check before set(): unhashable elements must 422, not 500.
                or not all(isinstance(entry, str) for entry in maps)
                or len(set(maps)) != len(maps)
                or not all(_workshop_mode_map_id(entry) for entry in maps)
            ):
                raise Problem("invalid_workshop_mode", 422)
            partial["session"] = "new"
            if maps is not None:
                partial["maps"] = list(maps)
            # Linear history (workshop#65): sessions track maps only. A stale
            # caller may still send `branches`; it is validated for shape and
            # then dropped — the workshop ignores it the same way.
            branches = model.branches
            if branches is not None:
                if (
                    not isinstance(branches, dict)
                    or not isinstance(maps, list)
                    or set(branches) != set(maps)
                    or any(
                        not isinstance(name, str)
                        or _WORKSHOP_BRANCH.fullmatch(name) is None
                        or name == "main"
                        for name in branches.values()
                    )
                ):
                    raise Problem("invalid_workshop_mode", 422)
        else:
            partial["session"] = "resume"
            if model.sessionId is not None:
                if _WORKSHOP_COPY_UUID.fullmatch(model.sessionId) is None:
                    raise Problem("invalid_workshop_mode", 422)
                partial["sessionId"] = model.sessionId
    elif profile == "test":
        if (
            not isinstance(model.candidateId, str)
            or _WORKSHOP_HEX32.fullmatch(model.candidateId) is None
        ):
            raise Problem("invalid_workshop_mode", 422)
        partial["candidateId"] = model.candidateId
        if model.modeId is not None:
            if model.modeId not in _WORKSHOP_ARENA_MODES:
                raise Problem("invalid_workshop_mode", 422)
            partial["modeId"] = model.modeId
    return partial


async def _workshop_caller(conn, identity, actor):
    # Caller attribution is bound, never caller-supplied. A person session
    # must have exactly one drasl-issuer account_identities row (verified
    # Drasl linking itself belongs to step 3); the payload actor is derived
    # from it and a mismatched supplied actor is rejected. A service
    # principal (site/bot acting for a human over an API-only plane) may
    # supply the actor only with the offline-provisioned workshop.act scope.
    if identity.account is None:
        if actor is None:
            raise Problem("invalid_workshop_actor", 422)
        return _workshop_identity(actor)
    if actor is not None:
        _workshop_identity(actor)
    bound = await rows(
        conn,
        "SELECT player_id, current_name FROM account_identities WHERE account_id=%s",
        (identity.actor,),
    )
    if len(bound) != 1:
        raise Problem("workshop_actor_unbound", 403)
    try:
        expected = _workshop_identity(
            {
                "draslId": str(bound[0]["player_id"]).replace("-", ""),
                "name": bound[0]["current_name"],
            }
        )
    except Problem:
        raise Problem("workshop_actor_unbound", 403) from None
    if actor is not None and _workshop_identity(actor) != expected:
        raise Problem("forbidden")
    return expected


async def workshop_op(conn, identity, attempt, kind, model, assertion=None, path=""):
    if kind not in WORKSHOP_SCOPES:
        raise Problem("unknown_action", 404)
    data = model.model_dump(mode="json")
    if identity.account is None:
        # A service may only supply the actor (workshop.act) for a kind it is
        # also provisioned for: workshop.act alone never authorizes a kind.
        # The admin-only kinds are not service-holdable (see SERVICE_SCOPES),
        # so no service credential can mint them.
        identity.require("workshop.act", model.environment, model.backend, model.target)
        identity.require(
            WORKSHOP_SCOPES[kind], model.environment, model.backend, model.target
        )
        scope = "workshop.act," + WORKSHOP_SCOPES[kind]
    else:
        identity.require(
            WORKSHOP_SCOPES[kind], model.environment, model.backend, model.target
        )
        scope = WORKSHOP_SCOPES[kind]
    if kind == "members":
        entries = model.members
        if (
            not isinstance(entries, list)
            or not 1 <= len(entries) <= WORKSHOP_MEMBERS_LIMIT
        ):
            raise Problem("invalid_workshop_members", 422)
        members = [_workshop_member(entry) for entry in entries]
        if model.target != "*" and any(entry.get("maps") for entry in members):
            # Map ids are outside any scoped grant: scoped issuers cannot
            # attest them. The consumer enforces the same rule on target.
            raise Problem("invalid_workshop_members", 422)
        partial, key = {"members": members}, "grantor"
    elif kind == "message":
        partial = {"message": _workshop_message(model.message)}
        key = "actor"
    elif kind in ("wake", "cancel"):
        partial, key = {}, "actor"
    elif kind == "map":
        partial, key = _workshop_map(model), "actor"
    elif kind == "sessions":
        partial, key = _workshop_sessions(model), "actor"
    elif kind == "ai-key":
        partial, key = _workshop_ai_key(model, model.model_fields_set), "actor"
    elif kind == "mode":
        partial, key = _workshop_mode(model), "actor"
    else:
        release = model.release
        if not isinstance(release, str) or WORKSHOP_RELEASE.fullmatch(release) is None:
            raise Problem("invalid_workshop_release", 422)
        record = model.record
        if record is not None and (
            not isinstance(record, dict) or record.get("release") != release
        ):
            raise Problem("invalid_workshop_record", 422)
        partial = {"release": release}
        if record is not None:
            # Full provenance is verified consumer-side against its catalog.
            partial["record"] = record
        key = "actor"
    caller = await _workshop_caller(conn, identity, model.actor)
    payload = {"kind": kind, "target": model.target, key: caller, **partial}
    op, duplicate = await operation(
        conn,
        identity,
        f"workshop.{kind}",
        model.target,
        data,
        scope,
        model.expiresInSeconds,
        model.generation,
    )
    if duplicate:
        return receipt(op)
    consumer = await one(
        conn, "SELECT * FROM consumers WHERE id=%s FOR UPDATE", (model.consumerId,)
    )
    if (
        not consumer
        or consumer["generation"] != model.generation
        or consumer["environment"] != model.environment
        or consumer["backend"] != model.backend
        or not covers(consumer["resource"], model.target)
        or WORKSHOP_SCOPES[kind] not in consumer["capabilities"]
    ):
        raise Problem("consumer_generation_or_capability", 409)
    unsettled = await one(
        conn,
        "SELECT count(*) AS n FROM outbox o JOIN operations p ON p.id=o.operation_id "
        "WHERE o.consumer_id=%s AND p.kind IN "
        "('workshop.members','workshop.message','workshop.wake','workshop.cancel',"
        "'workshop.release.select','workshop.map','workshop.sessions',"
        "'workshop.ai-key','workshop.mode') AND p.deadline>now() AND NOT EXISTS(SELECT 1 "
        "FROM consumer_acks a WHERE a.consumer_id=o.consumer_id AND "
        "a.sequence=o.sequence AND a.state IN "
        "('effective','rejected','unknown'))",
        (model.consumerId,),
    )
    if (
        consumer["next_sequence"] - consumer["received_cursor"] > 128
        or unsettled["n"] >= 128
    ):
        raise Problem("consumer_lag", 409)
    if kind == "members" and any(entry.get("role") == "admin" for entry in members):
        # Same owner step-up as grant_change: neither a non-owner admin nor
        # a service principal can mint Workshop admins without it.
        await step_up(conn, identity, assertion, "POST", path, data)
    await enqueue(conn, op, [consumer], payload)
    return await finish(
        conn,
        attempt,
        identity,
        op,
        {
            "payloadHash": digest(payload),
            "workshopActor": caller,
            "principal": {
                "credential": str(identity.credential["id"]),
                "account": str(identity.actor) if identity.actor else None,
                "client": identity.client["id"],
            },
        },
    )


# Site player sessions (coordination#29 U1): sealed Drasl tokens live in CP,
# the site is a stateless client. Mirrors site `account.ts` caps: 20 sessions
# per player, 60-day idle expiry, pruning on create.
SITE_SESSION_ID = re.compile(r"^[0-9a-f]{32}$")
SITE_SESSION_USER_CAP = 20
SITE_SESSION_MAX_AGE = timedelta(days=60)


async def _site_player_lock(conn, player_uuid):
    # One lock for every per-player session write (create incl. cap pruning,
    # revoke-all, touch): concurrent writers for the same player wait instead
    # of interleaving. Same pg_advisory_xact_lock pattern as operation().
    await conn.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
        (player_uuid,),
    )


async def site_session_create(conn, identity, attempt, model):
    # attempt is consumed by app.write's completion audit; site sessions
    # carry no operation row.
    identity.require("site.sessions", "prod", "game", "*")
    await _site_player_lock(conn, model.playerUuid)
    sid = secrets.token_hex(16)
    await conn.execute(
        "INSERT INTO site_sessions(id,sealed_token,player_uuid) VALUES(%s,%s,%s)",
        (sid, model.sealedToken, model.playerUuid),
    )
    cutoff = now() - SITE_SESSION_MAX_AGE
    await conn.execute("DELETE FROM site_sessions WHERE last_seen<%s", (cutoff,))
    await conn.execute(
        "DELETE FROM site_sessions WHERE player_uuid=%s AND id NOT IN "
        "(SELECT id FROM site_sessions WHERE player_uuid=%s "
        "ORDER BY created_at DESC, id DESC LIMIT %s)",
        (model.playerUuid, model.playerUuid, SITE_SESSION_USER_CAP),
    )
    return {"sessionId": sid}


async def site_session_read(conn, identity, session_id):
    identity.require("site.sessions", "prod", "game", "*")
    if not SITE_SESSION_ID.fullmatch(session_id or ""):
        raise Problem("session_not_found", 404)
    owner = await one(
        conn, "SELECT player_uuid FROM site_sessions WHERE id=%s", (session_id,)
    )
    if not owner:
        raise Problem("session_not_found", 404)
    await _site_player_lock(conn, owner["player_uuid"])
    # Touch and fetch atomically: a concurrent revoke between the lookup and
    # the touch leaves zero rows instead of returning a revoked token.
    row = await one(
        conn,
        "UPDATE site_sessions SET last_seen=now() WHERE id=%s AND last_seen>%s "
        "RETURNING sealed_token, player_uuid",
        (session_id, now() - SITE_SESSION_MAX_AGE),
    )
    if row:
        return {"sealedToken": row["sealed_token"], "playerUuid": row["player_uuid"]}
    # Expired or concurrently revoked: delete the stale row in this
    # transaction (it commits) and report expiry without raising here, so the
    # route returns 404 after commit instead of rolling the cleanup back.
    await conn.execute("DELETE FROM site_sessions WHERE id=%s", (session_id,))
    return None


async def site_session_revoke(conn, identity, attempt, session_id):
    identity.require("site.sessions", "prod", "game", "*")
    if not SITE_SESSION_ID.fullmatch(session_id or ""):
        raise Problem("session_not_found", 404)
    deleted = await conn.execute("DELETE FROM site_sessions WHERE id=%s", (session_id,))
    return {"revoked": deleted.rowcount > 0}


async def site_sessions_revoke_user(conn, identity, attempt, player_uuid):
    identity.require("site.sessions", "prod", "game", "*")
    if not isinstance(player_uuid, str) or not 1 <= len(player_uuid) <= 128:
        raise Problem("invalid_player", 422)
    await _site_player_lock(conn, player_uuid)
    deleted = await conn.execute(
        "DELETE FROM site_sessions WHERE player_uuid=%s", (player_uuid,)
    )
    return {"revoked": deleted.rowcount}


# Game-producer stats ingest (coordination#29 U1). Mirrors the site
# `stats.ts` ingest contract (validation, normalization, canonical digest,
# idempotency), so the untouched producer cuts over with the same bytes and a
# dual-write reconcile can compare digests. Ratings stay out: no reads need
# them yet, and the stored payloads replay later.
STAT_UUID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
STAT_ID = re.compile(r"^[a-z0-9_.:-]{1,128}$")
STAT_NAME_LIKE_UUID = (
    r"^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$"
)
STAT_MODES = {"room", "campaign", "deathmatch"}
STAT_REASONS = {"completed", "draw", "abandoned", "stopped", "shutdown", "error"}
STAT_TEAMS = {"RED", "BLUE", "NONE"}
STAT_COUNTERS = (
    "kills",
    "deaths",
    "captures",
    "neutralizations",
    "pointSeconds",
    "playSeconds",
    "suicides",
    "teamKills",
    "maxKillstreak",
)
STAT_UTC = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$")
# Producer outbox contract: 1 MiB/event, same as the site MAX_BODY.
STAT_MAX_BODY = 1048576
STAT_MAX_PARTICIPANTS = 512
STAT_MAX_CLASSES = 256
STAT_MAX_ROUNDS = 10000
TELEMETRY_MAX_BYTES = 8192
# Dropped (not failed) invalid telemetry blocks, like the site process counter.
telemetry_dropped = 0


class _DropTelemetry(Exception):
    pass


def _stat_invalid():
    raise Problem("invalid_result", 422)


def _stat_require(condition):
    if not condition:
        _stat_invalid()


def _stat_finite(value):
    # Python keeps arbitrary-precision JSON integers while the site parses
    # every number as an IEEE double (a 400-digit integer is Infinity
    # there): math.isfinite raises OverflowError on such ints, so a bad
    # telemetry block must fail validation, never the whole request.
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _stat_int(value, limit=1000000000):
    return type(value) is int and 0 <= value <= limit


def _stat_utc(value):
    _stat_require(isinstance(value, str) and STAT_UTC.match(value))
    try:
        moment = datetime.strptime(value[:19], "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        _stat_invalid()
    frac = value[19:-1]
    ms = int(frac[1:4].ljust(3, "0")) if frac.startswith(".") else 0
    return int(moment.timestamp() * 1000) + ms


def _js_number(value):
    # ECMA-262 Number::toString for finite doubles: the digest must match the
    # site (JSON.stringify) byte-for-byte, while Python repr differs in
    # [1e-6,1e-4) and [1e16,1e21). -0 serializes as "0" like the site.
    if value == 0:
        return "0"
    if isinstance(value, int):
        # Callers may pass JSON integers; the site holds every number as a double.
        try:
            value = float(value)
        except OverflowError:
            _stat_invalid()
    if not math.isfinite(value):
        _stat_invalid()
    # Below 2**53 an integral double prints its exact digits in both languages;
    # above, JS prints the shortest round-trip digits padded with zeros.
    if value.is_integer() and abs(value) < 2**53:
        return str(int(value))
    sign = "-" if value < 0 else ""
    text = repr(abs(value))
    mantissa, _, exp = text.partition("e")
    exp = int(exp) if exp else 0
    head, _, tail = mantissa.partition(".")
    digits = head + tail
    leading = len(digits) - len(digits.lstrip("0"))
    digits = digits.lstrip("0").rstrip("0") or "0"
    point = exp + len(head) - leading
    total = len(digits)
    if 0 < point <= 21:
        body = (
            digits + "0" * (point - total)
            if point >= total
            else digits[:point] + "." + digits[point:]
        )
    elif point <= 0 and point > -6:
        body = "0." + "0" * -point + digits
    else:
        shift = point - 1
        body = (
            digits[0]
            + ("." + digits[1:] if total > 1 else "")
            + "e"
            + ("+" if shift >= 0 else "")
            + str(shift)
        )
    return sign + body


def _stat_canonical(value):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        # Python keeps arbitrary-precision JSON integers, but the site
        # parses every number as an IEEE double (JSON.parse), so digest
        # parity needs the double: 9007199254740993 becomes ...992.
        try:
            value = float(value)
        except OverflowError:
            _stat_invalid()
    if isinstance(value, float):
        return _js_number(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(_stat_canonical(item) for item in value) + "]"
    if isinstance(value, dict):
        return (
            "{"
            + ",".join(
                _stat_canonical(key) + ":" + _stat_canonical(value[key])
                for key in sorted(value)
            )
            + "}"
        )
    _stat_invalid()


def _stat_telemetry(value):
    _drop = _DropTelemetry()
    try:
        _stat_require(isinstance(value, dict) and len(value) <= 64)
        _stat_require(_stat_int(value.get("shots")))
        share = value.get("fallbackShare")
        _stat_require(
            type(share) in (int, float) and _stat_finite(share) and 0 <= share <= 1
        )
        for key in ("tickMsP50", "tickMsP99"):
            amount = value.get(key)
            _stat_require(
                type(amount) in (int, float)
                and _stat_finite(amount)
                and 0 <= amount <= 1000000
            )
        for key in ("ageTicksP50", "rewindTicksP50"):
            _stat_require(_stat_int(value.get(key)))
        for key in (
            "tickMsP99Overflow",
            "ageTicksP50Overflow",
            "rewindTicksP50Overflow",
        ):
            _stat_require(type(value.get(key)) is bool)
        counters = value.get("counters")
        _stat_require(isinstance(counters, dict) and len(counters) <= 512)
        clean_counters = {}
        for name, count in counters.items():
            _stat_require(
                isinstance(name, str)
                and re.fullmatch(r"[a-zA-Z0-9_.:-]{1,160}", name)
                and _stat_int(count)
            )
            clean_counters[name] = count

        def buckets(raw):
            _stat_require(isinstance(raw, list) and len(raw) <= 32)
            clean = []
            for row in raw:
                _stat_require(isinstance(row, dict))
                bound, count = row.get("le"), row.get("count")
                _stat_require(
                    (type(bound) in (int, float) and _stat_finite(bound) and bound >= 0)
                    or bound == "inf"
                )
                _stat_require(_stat_int(count))
                clean.append({"le": bound, "count": count})
            return clean

        disputes = value.get("disputes")
        _stat_require(isinstance(disputes, list) and len(disputes) <= 8)
        clean_disputes = []
        for sample in disputes:
            _stat_require(isinstance(sample, dict) and 1 <= len(sample) <= 32)
            kept = {}
            for key, entry in sample.items():
                _stat_require(
                    isinstance(key, str) and re.fullmatch(r"[a-zA-Z0-9_.:-]{1,64}", key)
                )
                # Postgres jsonb rejects NUL and lone surrogates; one such
                # value would break every aggregate over the match.
                _stat_require(
                    (
                        isinstance(entry, str)
                        and len(entry) <= 512
                        and not re.search("[\x00-\x1f\x7f-\x9f\ud800-\udfff]", entry)
                    )
                    or (type(entry) in (int, float) and _stat_finite(entry))
                    or type(entry) is bool
                )
                kept[key] = entry
            clean_disputes.append(kept)
        clean = {
            "shots": value["shots"],
            "fallbackShare": value["fallbackShare"],
            "tickMsP50": value["tickMsP50"],
            "tickMsP99": value["tickMsP99"],
            "tickMsP99Overflow": value["tickMsP99Overflow"],
            "ageTicksP50": value["ageTicksP50"],
            "ageTicksP50Overflow": value["ageTicksP50Overflow"],
            "rewindTicksP50": value["rewindTicksP50"],
            "rewindTicksP50Overflow": value["rewindTicksP50Overflow"],
            "counters": clean_counters,
            "tickMsBuckets": buckets(value.get("tickMsBuckets")),
            "ageTickBuckets": buckets(value.get("ageTickBuckets")),
            "rewindTickBuckets": buckets(value.get("rewindTickBuckets")),
            "disputes": clean_disputes,
        }
        _stat_require(
            len(_stat_canonical(clean).encode("utf-8")) <= TELEMETRY_MAX_BYTES
        )
        return clean
    except Problem:
        raise _drop


def validate_stat_result(value, current_ms):
    global telemetry_dropped
    _stat_require(isinstance(value, dict))
    _stat_require(
        value.get("schemaVersion") == 1
        and isinstance(value.get("eventId"), str)
        and STAT_UUID.match(value["eventId"])
        and isinstance(value.get("serverId"), str)
        and STAT_UUID.match(value["serverId"])
    )
    _stat_require(value.get("sessionPurpose") == "gameplay")
    mode = value.get("modeId")
    _stat_require(
        mode in STAT_MODES
        and type(value.get("ranked")) is bool
        and value["ranked"] == (mode == "campaign")
    )
    _stat_require(
        isinstance(value.get("rulesetVersion"), str)
        and STAT_ID.match(value["rulesetVersion"])
    )
    kind = value.get("kind")
    reason = value.get("endReason")
    winner = value.get("winner")
    _stat_require(
        kind in ("match", "campaign")
        and reason in STAT_REASONS
        and winner in STAT_TEAMS
        and (reason == "completed" or winner == "NONE")
    )
    start = _stat_utc(value.get("startedAt"))
    end = _stat_utc(value.get("endedAt"))
    _stat_require(start <= end <= current_ms + 300000)
    rounds = value.get("rounds")
    _stat_require(
        isinstance(rounds, list)
        and len(rounds) <= STAT_MAX_ROUNDS
        and all(isinstance(item, str) and STAT_UUID.match(item) for item in rounds)
        and len(set(rounds)) == len(rounds)
    )
    match_id = value.get("matchId")
    campaign_id = value.get("campaignSessionId")
    if kind == "match":
        _stat_require(
            match_id == value["eventId"]
            and isinstance(value.get("mapId"), str)
            and STAT_ID.match(value["mapId"])
            and (
                campaign_id is None
                or (isinstance(campaign_id, str) and STAT_UUID.match(campaign_id))
            )
            and (not value["ranked"] or campaign_id is not None)
            and not rounds
        )
    else:
        _stat_require(
            mode == "campaign"
            and match_id is None
            and value.get("mapId") is None
            and campaign_id == value["eventId"]
            and (reason != "completed" or rounds)
        )
    participants = value.get("participants")
    _stat_require(
        isinstance(participants, list) and len(participants) <= STAT_MAX_PARTICIPANTS
    )
    seen = set()
    clean_participants = []
    for participant in participants:
        _stat_require(
            isinstance(participant, dict)
            and isinstance(participant.get("uuid"), str)
            and STAT_UUID.match(participant["uuid"])
            and participant["uuid"] not in seen
        )
        seen.add(participant["uuid"])
        _stat_require(
            isinstance(participant.get("name"), str)
            and 1 <= len(participant["name"]) <= 64
            and not re.search(r"[\x00-\x1f\x7f]", participant["name"])
        )
        score = participant.get("score")
        _stat_require(
            participant.get("team") in STAT_TEAMS
            and type(score) in (int, float)
            and _stat_finite(score)
            and abs(score) <= 1000000000
        )
        _stat_require(all(_stat_int(participant.get(key)) for key in STAT_COUNTERS))
        classes = participant.get("classes")
        _stat_require(isinstance(classes, list) and len(classes) <= STAT_MAX_CLASSES)
        kinds = set()
        clean_classes = []
        for entry in classes:
            _stat_require(
                isinstance(entry, dict)
                and isinstance(entry.get("classId"), str)
                and STAT_ID.match(entry["classId"])
                and isinstance(entry.get("variantId"), str)
                and STAT_ID.match(entry["variantId"])
            )
            key = entry["classId"] + "/" + entry["variantId"]
            _stat_require(key not in kinds)
            kinds.add(key)
            _stat_require(
                all(
                    _stat_int(entry.get(key))
                    for key in ("timeSeconds", "kills", "deaths", "pointSeconds")
                )
            )
            clean_classes.append(
                {
                    "classId": entry["classId"],
                    "variantId": entry["variantId"],
                    "timeSeconds": entry["timeSeconds"],
                    "kills": entry["kills"],
                    "deaths": entry["deaths"],
                    "pointSeconds": entry["pointSeconds"],
                }
            )
        clean_classes.sort(key=lambda item: (item["classId"], item["variantId"]))
        clean_participants.append(
            {
                "uuid": participant["uuid"],
                "name": participant["name"],
                "team": participant["team"],
                "score": score,
                **{key: participant[key] for key in STAT_COUNTERS},
                "classes": clean_classes,
            }
        )
    clean_participants.sort(key=lambda item: item["uuid"])
    personal = "winnerUuid" in value
    if personal:
        _stat_require(
            mode == "deathmatch"
            and kind == "match"
            and reason == "completed"
            and winner == "NONE"
            and campaign_id is None
            and isinstance(value.get("winnerUuid"), str)
            and STAT_UUID.match(value["winnerUuid"])
            and value["winnerUuid"] in seen
            and all(item["team"] == "NONE" for item in clean_participants)
        )
    telemetry = None
    if "telemetry" in value:
        try:
            telemetry = _stat_telemetry(value["telemetry"])
        except _DropTelemetry:
            telemetry_dropped += 1
    clean = {
        "schemaVersion": 1,
        "eventId": value["eventId"],
        "serverId": value["serverId"],
        "kind": kind,
        "sessionPurpose": "gameplay",
        "modeId": mode,
        "ranked": value["ranked"],
        "rulesetVersion": value["rulesetVersion"],
        "matchId": match_id,
        "campaignSessionId": campaign_id,
        "mapId": value.get("mapId"),
        "startedAt": value["startedAt"],
        "endedAt": value["endedAt"],
        "endReason": reason,
        "winner": winner,
        **({"winnerUuid": value["winnerUuid"]} if personal else {}),
        **({"telemetry": telemetry} if telemetry is not None else {}),
        "rounds": sorted(rounds),
        "participants": clean_participants,
    }
    try:
        payload = _stat_canonical(clean)
        payload.encode("utf-8")
    except (ValueError, UnicodeError):
        _stat_invalid()
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return clean, digest, end


async def stat_ingest(conn, identity, attempt, body):
    # attempt is consumed by app.write's completion audit; stats carry no
    # operation row, like site sessions.
    current_ms = int(now().timestamp() * 1000)
    clean, digest, ended_ms = validate_stat_result(body, current_ms)
    server_id, event_id = clean["serverId"], clean["eventId"]
    # The credential is bound to its server resource at provision; requiring
    # the scope on the body's server keeps one server from submitting another
    # server's results, like the site 403 rule.
    identity.require("stats.ingest", "prod", "game", server_id)
    # Serialize per result id: a concurrent duplicate POST (producer outbox
    # retry) replays or conflicts inside one transaction, never as a unique
    # violation. Same pg_advisory_xact_lock pattern as operation().
    await conn.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
        (server_id + "/" + event_id,),
    )
    existing = await one(
        conn,
        "SELECT digest FROM stat_results WHERE server_id=%s AND event_id=%s",
        (server_id, event_id),
    )
    if existing is not None:
        if existing["digest"] != digest:
            raise Problem("result_conflict", 409)
        return {"inserted": False, "eventId": event_id}
    ended_at = datetime.fromtimestamp(ended_ms / 1000, tz=timezone.utc)
    await conn.execute(
        "INSERT INTO stat_results(server_id,event_id,kind,mode,campaign_id,ended_at,reason,winner,digest,payload) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        (
            server_id,
            event_id,
            clean["kind"],
            clean["modeId"],
            clean["campaignSessionId"],
            ended_at,
            clean["endReason"],
            clean["winner"],
            digest,
            Jsonb(clean),
        ),
    )
    for participant in clean["participants"]:
        # A real name always wins over a UUID-like one, regardless of order,
        # mirroring the site profiles upsert.
        await conn.execute(
            "INSERT INTO stat_profiles(uuid,name,last_seen) VALUES(%s,%s,%s)"
            " ON CONFLICT(uuid) DO UPDATE SET name=CASE"
            " WHEN excluded.name ~* %s AND stat_profiles.name !~* %s THEN stat_profiles.name"
            " WHEN excluded.last_seen>=stat_profiles.last_seen OR stat_profiles.name ~* %s THEN excluded.name"
            " ELSE stat_profiles.name END,"
            " last_seen=GREATEST(stat_profiles.last_seen,excluded.last_seen)",
            (
                participant["uuid"],
                participant["name"],
                ended_at,
                STAT_NAME_LIKE_UUID,
                STAT_NAME_LIKE_UUID,
                STAT_NAME_LIKE_UUID,
            ),
        )
        await conn.execute(
            "INSERT INTO stat_participants(server_id,event_id,uuid,team,score,kills,deaths,captures,neutralizations,point_seconds,play_seconds,suicides,team_kills,max_streak) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                server_id,
                event_id,
                participant["uuid"],
                participant["team"],
                participant["score"],
                participant["kills"],
                participant["deaths"],
                participant["captures"],
                participant["neutralizations"],
                participant["pointSeconds"],
                participant["playSeconds"],
                participant["suicides"],
                participant["teamKills"],
                participant["maxKillstreak"],
            ),
        )
        for entry in participant["classes"]:
            await conn.execute(
                "INSERT INTO stat_classes(server_id,event_id,uuid,class_id,variant_id,time_seconds,kills,deaths,point_seconds) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    server_id,
                    event_id,
                    participant["uuid"],
                    entry["classId"],
                    entry["variantId"],
                    entry["timeSeconds"],
                    entry["kills"],
                    entry["deaths"],
                    entry["pointSeconds"],
                ),
            )
    # Only a fresh insert rates: outbox replays return above, so one campaign
    # changes MMR at most once, like the site ingest. While a rebuild is
    # pending for this season or an earlier one, the result is stored but not
    # rated inline: the worker's replay covers it to the end of history, and
    # inline rating would wait on the replay's lock. The bump forces a worker
    # re-pass so a campaign committed mid-replay is never lost.
    if _stat_rated(clean):
        season_id = stat_season_at(ended_ms)["id"]
        if await _stat_rebuilding(conn, season_id):
            await _stat_enqueue_rebuild(conn, season_id, server_id, event_id, ended_at)
        else:
            await _stat_rate(conn, clean, ended_ms)
    return {"inserted": True, "eventId": event_id}


# Game-server diagnostics (coordination#29 U4). Mirrors the site
# `src/lib/diagnostics.ts` contract (validation, idempotency, retention caps)
# so the producer cuts over with the same bytes; the site admin health view
# becomes a client of the read route below.
DIAG_SAMPLE_DAYS = 7
DIAG_EVENT_DAYS = 14
DIAG_MAX_SAMPLES = 50000
DIAG_MAX_EVENTS = 5000
DIAG_KINDS = {"freeze", "error", "warning", "crash"}
DIAG_MAX_REPORT_SAMPLES = 120
DIAG_MAX_REPORT_EVENTS = 200
# Producer outbox contract: 1 MiB/report, same as the site MAX_BODY.
DIAG_MAX_BODY = 1048576
DIAG_SKEW_MS = 5 * 60000
_DIAG_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s\"'<>]+", re.IGNORECASE)
_DIAG_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_DIAG_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b")
_DIAG_IPV6_FULL = re.compile(
    r"\[?\b(?:[0-9a-f]{1,4}:){4,7}[0-9a-f]{1,4}\b\]?(?::\d{1,5})?",
    re.IGNORECASE,
)
_DIAG_IPV6_COMP = re.compile(
    r"(?<![\w:])(?:\[?(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?\]?(?::\d{1,5})?)(?![\w:])",
    re.IGNORECASE,
)
_DIAG_BEARER = re.compile(r"\b(bearer)\s+[^\s\"',;\}\]]+", re.IGNORECASE)
_DIAG_SECRET_KV = re.compile(
    r"\b([a-z0-9_-]*(?:authorization|token|password|passwd|secret|api[_-]?key|access[_-]?key))([\"']?\s*[:=]\s*)(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;\}\]]+)",
    re.IGNORECASE,
)
_DIAG_TOKEN_RUN = re.compile(
    r"\b(?![0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b)(?=[\w-]*\d)(?=[\w-]*[A-Za-z])[\w-]{32,}"
)


def _diag_invalid():
    raise Problem("invalid_diagnostics", 400)


def _diag_require(condition):
    if not condition:
        _diag_invalid()


def _diag_redact(text):
    # Log text may carry IPs/URLs/secrets; none of it is stored. Same
    # patterns as the site redact(), so proxied messages stay byte-shaped.
    text = re.sub(r"[^\S\n]*[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f][^\S\n]*", " ", text)
    text = _DIAG_URL.sub("[url]", text)
    text = _DIAG_EMAIL.sub("[email]", text)
    text = _DIAG_IPV4.sub("[ip]", text)
    text = _DIAG_IPV6_FULL.sub("[ip]", text)
    text = _DIAG_IPV6_COMP.sub("[ip]", text)
    text = _DIAG_BEARER.sub(r"\1 [secret]", text)
    text = _DIAG_SECRET_KV.sub(r"\1\2[secret]", text)
    return _DIAG_TOKEN_RUN.sub("[secret]", text)


def _diag_number(value, low, high, whole=False):
    if isinstance(value, bool):
        return None
    if whole:
        if type(value) is not int or not low <= value <= high:
            return None
        return value
    if type(value) not in (int, float) or not math.isfinite(value):
        return None
    if not low <= value <= high:
        return None
    return value


def _diag_at(value, now_ms):
    at = _diag_number(value, 0, now_ms + DIAG_SKEW_MS, whole=True)
    _diag_require(at is not None)
    return at


def _diag_line(value, limit):
    if value is None:
        return None
    _diag_require(isinstance(value, str))
    text = _diag_redact(value).strip()
    return text[:limit] or None


def _diag_validate(body, now_ms):
    _diag_require(isinstance(body, dict))
    _diag_require(
        type(body.get("schemaVersion")) is int and body.get("schemaVersion") == 1
    )
    server_id = body.get("serverId")
    _diag_require(isinstance(server_id, str) and STAT_UUID.match(server_id))
    samples, events = body.get("samples", []), body.get("events", [])
    _diag_require(isinstance(samples, list) and len(samples) <= DIAG_MAX_REPORT_SAMPLES)
    _diag_require(isinstance(events, list) and len(events) <= DIAG_MAX_REPORT_EVENTS)
    clean_samples = []
    for entry in samples:
        _diag_require(isinstance(entry, dict))
        numbers = {
            "tps": _diag_number(entry.get("tps"), 0, 1000),
            "msptAvg": _diag_number(entry.get("msptAvg"), 0, 3600000),
            "msptP95": _diag_number(entry.get("msptP95"), 0, 3600000),
            "msptMax": _diag_number(entry.get("msptMax"), 0, 3600000),
        }
        _diag_require(
            numbers["tps"] is not None
            and numbers["msptAvg"] is not None
            and numbers["msptMax"] is not None
        )
        if numbers["msptP95"] is None and entry.get("msptP95") is not None:
            _diag_invalid()
        for name, limit in (
            ("players", 10000),
            ("heapUsedMb", 1048576),
            ("heapMaxMb", 1048576),
            ("gcPauseMs", 3600000),
        ):
            value = _diag_number(entry.get(name), 0, limit, whole=True)
            if value is None and entry.get(name) is not None:
                _diag_invalid()
            numbers[name] = value
        at = _diag_at(entry.get("at"), now_ms)
        if at >= now_ms - DIAG_SAMPLE_DAYS * 86400000:
            clean_samples.append({"at": at, **numbers})
    clean_events = []
    for entry in events:
        _diag_require(isinstance(entry, dict))
        event_id = entry.get("id")
        _diag_require(isinstance(event_id, str) and STAT_UUID.match(event_id))
        _diag_require(entry.get("kind") in DIAG_KINDS)
        message = _diag_line(entry.get("message"), 4000)
        _diag_require(message)
        if entry.get("kind") == "freeze":
            duration = _diag_number(entry.get("durationMs"), 0, 3600000, whole=True)
            _diag_require(duration is not None)
        else:
            duration = _diag_number(entry.get("durationMs"), 0, 3600000, whole=True)
            if duration is None and entry.get("durationMs") is not None:
                _diag_invalid()
        repeats = entry.get("repeats", 1)
        if type(repeats) is not int or repeats < 1:
            repeats = 1
        at = _diag_at(entry.get("at"), now_ms)
        if at >= now_ms - DIAG_EVENT_DAYS * 86400000:
            clean_events.append(
                {
                    "id": event_id,
                    "at": at,
                    "kind": entry.get("kind"),
                    "durationMs": duration,
                    "source": _diag_line(entry.get("source"), 120),
                    "message": message,
                    "repeats": repeats,
                }
            )
    started = body.get("startedAt")
    started_at = None
    if started is not None:
        started_at = _diag_number(started, 0, now_ms + DIAG_SKEW_MS, whole=True)
        _diag_require(started_at is not None)
    return {
        "serverId": server_id,
        "startedAt": started_at,
        "samples": clean_samples,
        "events": clean_events,
    }


def _diag_ts(ms):
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)


async def stat_diag_ingest(conn, identity, attempt, body):
    # attempt is consumed by app.write's completion audit, like stat_ingest.
    current_ms = int(now().timestamp() * 1000)
    clean = _diag_validate(body, current_ms)
    server_id = clean["serverId"]
    # The credential is bound to its server resource at provision; requiring
    # the scope on the body's server keeps one server from submitting
    # another server's diagnostics, like the site 403 rule.
    identity.require("stats.ingest", "prod", "game", server_id)
    await conn.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
        (server_id + "/diagnostics",),
    )
    for sample in clean["samples"]:
        await conn.execute(
            "INSERT INTO stat_samples(server_id,at,tps,mspt_avg,mspt_p95,mspt_max,players,heap_used_mb,heap_max_mb,gc_pause_ms,started_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
            (
                server_id,
                _diag_ts(sample["at"]),
                sample["tps"],
                sample["msptAvg"],
                sample["msptP95"],
                sample["msptMax"],
                sample["players"],
                sample["heapUsedMb"],
                sample["heapMaxMb"],
                sample["gcPauseMs"],
                _diag_ts(clean["startedAt"])
                if clean["startedAt"] is not None
                else None,
            ),
        )
    for event in clean["events"]:
        await conn.execute(
            "INSERT INTO stat_events(server_id,event_id,at,kind,duration_ms,source,message,repeats) VALUES(%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
            (
                server_id,
                event["id"],
                _diag_ts(event["at"]),
                event["kind"],
                event["durationMs"],
                event["source"],
                event["message"],
                event["repeats"],
            ),
        )
    # Retention mirrors the site saveReport prune (same age caps and the
    # same row-count windows), so the two stores stay comparable.
    await conn.execute(
        "DELETE FROM stat_samples WHERE at < now() - make_interval(days=>%s)",
        (DIAG_SAMPLE_DAYS,),
    )
    await conn.execute(
        "DELETE FROM stat_events WHERE at < now() - make_interval(days=>%s)",
        (DIAG_EVENT_DAYS,),
    )
    await conn.execute(
        "DELETE FROM stat_samples WHERE at < (SELECT at FROM stat_samples ORDER BY at DESC LIMIT 1 OFFSET %s)",
        (DIAG_MAX_SAMPLES,),
    )
    await conn.execute(
        "DELETE FROM stat_events WHERE (server_id,event_id) NOT IN (SELECT server_id,event_id FROM stat_events ORDER BY CASE kind WHEN 'crash' THEN 0 WHEN 'error' THEN 0 WHEN 'freeze' THEN 1 ELSE 2 END, at DESC, server_id, event_id LIMIT %s)",
        (DIAG_MAX_EVENTS,),
    )
    return {"samples": len(clean["samples"]), "events": len(clean["events"])}


def _diag_ms(value):
    return int(value.timestamp() * 1000)


async def stat_diag_read(conn, hours=24, now_ms=None):
    # Same shape as the site readDiagnostics view, so the site admin health
    # page renders CP rows unchanged.
    if now_ms is None:
        now_ms = int(now().timestamp() * 1000)
    if type(hours) is not int or not 1 <= hours <= DIAG_SAMPLE_DAYS * 24:
        raise Problem("invalid_diagnostics", 400)
    cutoff = _diag_ts(now_ms - hours * 3600000)
    sample_rows = await rows(
        conn,
        'SELECT server_id "serverId", at, tps, mspt_avg "msptAvg", mspt_p95 "msptP95", mspt_max "msptMax", players, heap_used_mb "heapUsedMb", heap_max_mb "heapMaxMb", gc_pause_ms "gcPauseMs", started_at "startedAt" FROM stat_samples WHERE at >= %s ORDER BY at LIMIT 5000',
        (cutoff,),
    )
    event_rows = await rows(
        conn,
        'SELECT server_id "serverId", event_id id, at, kind, duration_ms "durationMs", source, message, repeats FROM stat_events ORDER BY at DESC LIMIT 500',
    )
    last = await one(conn, 'SELECT max(at) "last" FROM stat_samples')
    samples = [
        {
            "serverId": row["serverId"],
            "at": _diag_ms(row["at"]),
            "tps": row["tps"],
            "msptAvg": row["msptAvg"],
            "msptP95": row["msptP95"],
            "msptMax": row["msptMax"],
            "players": row["players"],
            "heapUsedMb": row["heapUsedMb"],
            "heapMaxMb": row["heapMaxMb"],
            "gcPauseMs": row["gcPauseMs"],
            "startedAt": _diag_ms(row["startedAt"])
            if row["startedAt"] is not None
            else None,
        }
        for row in sample_rows
    ]
    events = [
        {
            "serverId": row["serverId"],
            "id": row["id"],
            "at": _diag_ms(row["at"]),
            "kind": row["kind"],
            "durationMs": row["durationMs"],
            "source": row["source"],
            "message": row["message"],
            "repeats": row["repeats"],
        }
        for row in event_rows
    ]
    return {
        "schemaVersion": 1,
        "now": now_ms,
        "hours": hours,
        "lastSampleAt": _diag_ms(last["last"]) if last["last"] is not None else None,
        "samples": samples,
        "events": events,
    }


# (`src/lib/stats.ts` seasons/filters/leaderboard/player/hitreg/rate at the
# site ref in .dev/u-sitedb-u3): same filter/sort/rank semantics, same
# Glicko-2, same per-season replay rule. Ratings are never recomputed in two
# places: the site read API becomes a client of these routes.
STAT_RULES_VERSION = "glicko2-v1"
STAT_RATING_PERIOD_MS = 7 * 86400000
STAT_SEASON_ONE_START_MS = int(
    datetime(2026, 9, 14, tzinfo=timezone.utc).timestamp() * 1000
)
STAT_ALPHA_END_MS = int(datetime(2026, 9, 26, tzinfo=timezone.utc).timestamp() * 1000)
STAT_SEASON_THREE_START_MS = int(
    datetime(2027, 1, 1, tzinfo=timezone.utc).timestamp() * 1000
)
STAT_SORTS = {
    "score": "score",
    "kills": "kills",
    "captures": "captures",
    # The aggregates are aliased with camelCase quotes, not snake_case
    # columns: sort by the quoted aliases the GROUP BY actually selects.
    "pointSeconds": '"pointSeconds"',
    "playSeconds": '"playSeconds"',
    "wins": "wins",
    "kd": "kd",
    "rating": "COALESCE(rating,-1)",
}
STAT_HITREG_SCAN_CAP = 5000
STAT_UNKNOWN_PLAYER = "Неизвестный игрок"
STAT_DISPLAY_UUID_LIKE = re.compile(
    r"^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$",
    re.IGNORECASE,
)
# Glicko-2 constants (site `src/lib/glicko2.ts` GLICKO2).
_STAT_G_RATING = 1500.0
_STAT_G_RD = 350.0
_STAT_G_VOLATILITY = 0.06
_STAT_G_TAU = 0.5
_STAT_G_EPSILON = 1e-6
_STAT_G_SCALE = 173.7178


def _stat_iso(ms):
    # Site `Date.toISOString()`: millis + Z, so proxied rows stay byte-shaped.
    dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms % 1000:03d}Z"


def _stat_parse_iso(value):
    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000)


def _stat_dt(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def stat_seasons(now_ms=None):
    # Site seasons(): s1 is the alpha, s2 runs to end of 2026, then UTC
    # calendar quarters. IDs stay numeric; endsAt is inclusive.
    if now_ms is None:
        now_ms = int(now().timestamp() * 1000)
    out, start, n = [], STAT_SEASON_ONE_START_MS, 1
    while start <= now_ms:
        if n == 1:
            following = STAT_ALPHA_END_MS
        elif n == 2:
            following = STAT_SEASON_THREE_START_MS
        else:
            head = datetime.fromtimestamp(start / 1000, tz=timezone.utc)
            month, year = head.month + 3, head.year
            if month > 12:
                month, year = month - 12, year + 1
            following = int(
                datetime(year, month, 1, tzinfo=timezone.utc).timestamp() * 1000
            )
        out.append(
            {
                "id": f"s{n}",
                "name": "Альфа Сезон" if n == 1 else f"Сезон {n - 1}",
                "startsAt": _stat_iso(start),
                "endsAt": _stat_iso(following - 1),
            }
        )
        start, n = following, n + 1
    return out


def stat_season_at(time_ms):
    # Anything before season 1 belongs to season 1, like the site seasonAt.
    return stat_seasons(max(time_ms, STAT_SEASON_ONE_START_MS))[-1]


def _stat_filter_invalid():
    raise Problem("invalid_stats_filter", 400)


def stat_filters(params, now_ms=None):
    # Site filters(): mode/season/period/sort/limit/page with the same 400s.
    if now_ms is None:
        now_ms = int(now().timestamp() * 1000)
    mode, season = params.get("mode"), params.get("season")
    period = params.get("period", "all")
    sort = params.get("sort", "score")
    if mode is not None and mode not in STAT_MODES:
        _stat_filter_invalid()
    if period not in ("all", "week", "month") or sort not in STAT_SORTS:
        _stat_filter_invalid()
    if season is not None and "period" in params:
        _stat_filter_invalid()
    selected = None
    if season is not None:
        selected = next((s for s in stat_seasons(now_ms) if s["id"] == season), None)
        if selected is None:
            _stat_filter_invalid()
    limit_text, page_text = params.get("limit", "25"), params.get("page", "1")
    if not re.fullmatch(r"\d+", limit_text or "") or not re.fullmatch(
        r"\d+", page_text or ""
    ):
        _stat_filter_invalid()
    try:
        limit, page = int(limit_text), int(page_text)
    except ValueError:
        _stat_filter_invalid()
    if not 1 <= limit <= 100 or not 1 <= page <= 1000:
        _stat_filter_invalid()
    mmr_season = season if season is not None else stat_season_at(now_ms)["id"]
    if selected is not None:
        since = _stat_parse_iso(selected["startsAt"])
        until = _stat_parse_iso(selected["endsAt"])
    else:
        since = (
            0
            if period == "all"
            else now_ms - (7 if period == "week" else 30) * 86400000
        )
        until = now_ms + 300000
    return {
        "mode": mode,
        "season": season,
        "mmrSeason": mmr_season,
        "since": since,
        "until": until,
        "sort": sort,
        "limit": limit,
        "page": page,
    }


def _stat_display_name(name):
    # Site displayName: a UUID-like stored name renders as unknown, never raw.
    if not name or STAT_DISPLAY_UUID_LIKE.match(name.strip()):
        return STAT_UNKNOWN_PLAYER
    return name


def _stat_js_round(value):
    # Site Math.round (half up; values here are non-negative): Python round()
    # is banker's rounding and would differ on .5 ratings.
    return math.floor(value + 0.5)


def _stat_num(value):
    # Site JSON has no int/float split (node-pg parses numerics to Number):
    # whole doubles render as ints so proxied bodies stay byte-shaped.
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def _stat_mmr(row):
    if row is None or row["rating"] is None:
        return None
    return {
        "rating": _stat_js_round(row["rating"]),
        "rd": _stat_js_round(row["rd"]),
        "ratedCampaigns": row["ratedCampaigns"],
        "provisional": row["ratedCampaigns"] < 5 or row["rd"] > 150,
    }


def _stat_glicko_g(phi):
    return 1 / math.sqrt(1 + (3 * phi * phi) / (math.pi * math.pi))


def _stat_glicko_expected(mu, muj, phij):
    return 1 / (1 + math.exp(-_stat_glicko_g(phij) * (mu - muj)))


def _stat_glicko_initial():
    return {
        "rating": _STAT_G_RATING,
        "rd": _STAT_G_RD,
        "volatility": _STAT_G_VOLATILITY,
    }


def _stat_glicko_inflate(player, periods):
    phi = player["rd"] / _STAT_G_SCALE
    for _ in range(periods):
        if phi * _STAT_G_SCALE >= _STAT_G_RD:
            break
        phi = math.sqrt(phi * phi + player["volatility"] * player["volatility"])
    return {**player, "rd": min(_STAT_G_RD, phi * _STAT_G_SCALE)}


def _stat_glicko_soft_reset(player, seasons=1):
    # Half the distance to the initial rating per boundary crossed, RD at
    # least 200, volatility kept — site softReset.
    return {
        "rating": _STAT_G_RATING + 0.5**seasons * (player["rating"] - _STAT_G_RATING),
        "rd": max(player["rd"], 200),
        "volatility": player["volatility"],
    }


def _stat_glicko_composite(opponents):
    # One game against a virtual opponent: mean rating, RMS deviation.
    _stat_require(len(opponents) > 0)
    rating = sum(o["rating"] for o in opponents) / len(opponents)
    rd = math.sqrt(sum(o["rd"] * o["rd"] for o in opponents) / len(opponents))
    return {"rating": rating, "rd": rd}


def _stat_glicko_update(player, games, tau=_STAT_G_TAU):
    # Site glicko2.ts update, one rating period. IEEE doubles on both sides.
    scale, epsilon = _STAT_G_SCALE, _STAT_G_EPSILON
    mu = (player["rating"] - _STAT_G_RATING) / scale
    phi = player["rd"] / scale
    sigma = player["volatility"]
    if not games:
        return _stat_glicko_inflate(player, 1)
    inv_v, total = 0.0, 0.0
    for game in games:
        muj = (game["opponent"]["rating"] - _STAT_G_RATING) / scale
        phij = game["opponent"]["rd"] / scale
        gj = _stat_glicko_g(phij)
        expect = _stat_glicko_expected(mu, muj, phij)
        inv_v += gj * gj * expect * (1 - expect)
        total += gj * (game["score"] - expect)
    variance = 1 / inv_v
    delta = variance * total
    a = math.log(sigma * sigma)

    def f(x):
        return (math.exp(x) * (delta * delta - phi * phi - variance - math.exp(x))) / (
            2 * (phi * phi + variance + math.exp(x)) ** 2
        ) - (x - a) / (tau * tau)

    low = a
    if delta * delta > phi * phi + variance:
        high = math.log(delta * delta - phi * phi - variance)
    else:
        k = 1
        while f(a - k * tau) < 0:
            k += 1
        high = a - k * tau
    f_low, f_high = f(low), f(high)
    while abs(high - low) > epsilon:
        mid = low + ((low - high) * f_low) / (f_high - f_low)
        f_mid = f(mid)
        if f_mid * f_high <= 0:
            low, f_low = high, f_high
        else:
            f_low /= 2
        high, f_high = mid, f_mid
    sigma_new = math.exp(low / 2)
    phi_star = math.sqrt(phi * phi + sigma_new * sigma_new)
    phi_new = 1 / math.sqrt(1 / (phi_star * phi_star) + 1 / variance)
    mu_new = mu + phi_new * phi_new * total
    return {
        "rating": _STAT_G_RATING + scale * mu_new,
        "rd": min(_STAT_G_RD, scale * phi_new),
        "volatility": sigma_new,
    }


def _stat_rated(clean):
    # Unlike site `src/lib/stats.ts:1590`, a completed campaign without a
    # winner is stored but not rated: the site scored it as a loss for both
    # sides. Keep in sync with the SQL selections of rated campaigns below.
    return (
        clean["kind"] == "campaign"
        and clean["modeId"] == "campaign"
        and (
            clean["endReason"] == "draw"
            or (
                clean["endReason"] == "completed" and clean["winner"] in ("RED", "BLUE")
            )
        )
    )


def _stat_ms(moment):
    return int(moment.timestamp() * 1000)


async def _stat_rate(conn, clean, ended_ms):
    # One Glicko-2 period per rated player against the composite other side.
    # The season comes from endedAt; late results rate only their own season.
    reds = [p for p in clean["participants"] if p["team"] == "RED"]
    blues = [p for p in clean["participants"] if p["team"] == "BLUE"]
    if not reds or not blues:
        return None
    season = stat_season_at(ended_ms)
    season_number = int(season["id"][1:])
    # Rating updates and rebuilds serialize across replicas, like the site
    # transaction lock (`src/lib/database.ts` pg_advisory_xact_lock(782344, 1)).
    await conn.execute("SELECT pg_advisory_xact_lock(782344, 1)")
    season_start_ms = _stat_parse_iso(season["startsAt"])
    before = {}
    for participant in reds + blues:
        uuid = participant["uuid"]
        row = await one(
            conn,
            "SELECT rating,rd,volatility,rated_campaigns,last_rated_at FROM stat_ratings WHERE season_id=%s AND uuid=%s",
            (season["id"], uuid),
        )
        if row is not None:
            rating = _stat_glicko_inflate(
                {
                    "rating": row["rating"],
                    "rd": row["rd"],
                    "volatility": row["volatility"],
                },
                max(0, ended_ms - _stat_ms(row["last_rated_at"]))
                // STAT_RATING_PERIOD_MS,
            )
            campaigns = row["rated_campaigns"]
        else:
            previous = await one(
                conn,
                "SELECT rating,rd,volatility,CAST(substr(season_id,2) AS INTEGER) AS season_number FROM stat_ratings"
                " WHERE uuid=%s AND CAST(substr(season_id,2) AS INTEGER)<%s ORDER BY season_number DESC LIMIT 1",
                (uuid, season_number),
            )
            if previous is not None:
                rating = _stat_glicko_inflate(
                    _stat_glicko_soft_reset(
                        {
                            "rating": previous["rating"],
                            "rd": previous["rd"],
                            "volatility": previous["volatility"],
                        },
                        season_number - previous["season_number"],
                    ),
                    max(0, ended_ms - season_start_ms) // STAT_RATING_PERIOD_MS,
                )
            else:
                rating = _stat_glicko_initial()
            campaigns = 0
        before[uuid] = (rating, campaigns)
    ended_at = datetime.fromtimestamp(ended_ms / 1000, tz=timezone.utc)
    for team, own, foes in (("RED", reds, blues), ("BLUE", blues, reds)):
        opponent = _stat_glicko_composite([before[o["uuid"]][0] for o in foes])
        # Site `src/lib/stats.ts:908`: a draw splits the point, otherwise the
        # winning team takes it (winner-NONE completions are never rated).
        score = (
            0.5
            if clean["endReason"] == "draw"
            else (1 if clean["winner"] == team else 0)
        )
        for participant in own:
            source, campaigns = before[participant["uuid"]]
            target = _stat_glicko_update(
                source, [{"opponent": opponent, "score": score}]
            )
            await conn.execute(
                "INSERT INTO stat_ratings(season_id,uuid,rating,rd,volatility,rated_campaigns,last_rated_at) VALUES(%s,%s,%s,%s,%s,%s,%s)"
                " ON CONFLICT(season_id,uuid) DO UPDATE SET rating=excluded.rating,rd=excluded.rd,"
                " volatility=excluded.volatility,rated_campaigns=excluded.rated_campaigns,"
                " last_rated_at=GREATEST(stat_ratings.last_rated_at,excluded.last_rated_at)",
                (
                    season["id"],
                    participant["uuid"],
                    target["rating"],
                    target["rd"],
                    target["volatility"],
                    campaigns + 1,
                    ended_at,
                ),
            )
            await conn.execute(
                "INSERT INTO stat_rating_changes(server_id,event_id,uuid,rules_version,team,score,opp_rating,opp_rd,"
                "before_rating,before_rd,before_volatility,after_rating,after_rd,after_volatility,rated_at,season_id)"
                " VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    clean["serverId"],
                    clean["eventId"],
                    participant["uuid"],
                    STAT_RULES_VERSION,
                    team,
                    score,
                    opponent["rating"],
                    opponent["rd"],
                    source["rating"],
                    source["rd"],
                    source["volatility"],
                    target["rating"],
                    target["rd"],
                    target["volatility"],
                    ended_at,
                    season["id"],
                ),
            )
    return season["id"]


async def _stat_rebuild_ratings(conn, season):
    # Deterministic replay of every non-voided rated campaign from the season
    # on, in endedAt/serverId/eventId order; earlier seasons (the carry-over
    # source) stay untouched. Call inside a transaction.
    number = int(season["id"][1:])
    await conn.execute("SELECT pg_advisory_xact_lock(782344, 1)")
    await conn.execute(
        "DELETE FROM stat_rating_changes WHERE CAST(substr(season_id,2) AS INTEGER)>=%s",
        (number,),
    )
    await conn.execute(
        "DELETE FROM stat_ratings WHERE CAST(substr(season_id,2) AS INTEGER)>=%s",
        (number,),
    )
    args: tuple = () if number == 1 else (_stat_dt(season["startsAt"]),)
    matches = await rows(
        conn,
        "SELECT payload,ended_at FROM stat_results WHERE kind='campaign' AND mode='campaign' AND (reason='draw' OR (reason='completed' AND winner IN ('RED','BLUE')))"
        + ("" if number == 1 else " AND ended_at>=%s")
        + " AND NOT EXISTS(SELECT 1 FROM stat_result_voids v WHERE v.server_id=stat_results.server_id AND v.event_id=stat_results.event_id)"
        + " ORDER BY ended_at,server_id,event_id",
        args,
    )
    for match in matches:
        await _stat_rate(conn, match["payload"], _stat_ms(match["ended_at"]))


async def stat_backfill_ratings(conn):
    # One-time replay for results ingested before 005 created the ratings
    # store. Idempotent (the rebuild deletes before replaying); under the same
    # advisory lock ingest uses, so a concurrent ingest serializes behind it.
    first = await one(
        conn,
        "SELECT MIN(ended_at) AS first FROM stat_results WHERE kind='campaign' AND mode='campaign' AND (reason='draw' OR (reason='completed' AND winner IN ('RED','BLUE')))"
        " AND NOT EXISTS(SELECT 1 FROM stat_result_voids v WHERE v.server_id=stat_results.server_id AND v.event_id=stat_results.event_id)",
    )
    if first is None or first["first"] is None:
        return None
    season = stat_season_at(_stat_ms(first["first"]))
    await _stat_rebuild_ratings(conn, season)
    return season["id"]


# At most this many campaigns per rebuild batch: the rating-lock hold is
# bounded by the batch, never by history length.
STAT_REBUILD_BATCH = 200


async def _stat_enqueue_rebuild(conn, season_id, server_id, event_id, from_at):
    # Every rebuild enqueue carries its from-point: the triggering campaign's
    # endedAt, or None for season start (gap scan). Each enqueue also bumps
    # the generation counter, so a worker batch that read the row earlier
    # cannot commit over it (compare-and-swap in stat_rebuild_drain). A
    # re-enqueue never moves the cursor forward past unrated work: a
    # from-point at or behind the cursor restarts the replay from the season
    # start (NULL cursor), otherwise the in-progress cursor is kept and the
    # replay reaches the new campaign on its own. The <= (not <) matters: a
    # void of exactly the cursor campaign must re-rate it, not skip it.
    # Restart (not resume-from-point) is required: re-rating committed
    # campaigns collides with the stat_rating_changes primary key, and a
    # Glicko-2 suffix replay without its prefix state rates wrong.
    await conn.execute(
        "INSERT INTO stat_rating_rebuilds(season_id,server_id,event_id) VALUES(%s,%s,%s)"
        " ON CONFLICT(season_id) DO UPDATE SET server_id=excluded.server_id,"
        " event_id=excluded.event_id,requested_at=now(),"
        " generation=stat_rating_rebuilds.generation+1,"
        " last_ended_at=CASE WHEN stat_rating_rebuilds.last_ended_at IS NULL OR %s::timestamptz IS NULL"
        " OR (%s,%s,%s)<=(stat_rating_rebuilds.last_ended_at,stat_rating_rebuilds.last_server_id,stat_rating_rebuilds.last_event_id)"
        " THEN NULL ELSE stat_rating_rebuilds.last_ended_at END,"
        " last_server_id=CASE WHEN stat_rating_rebuilds.last_ended_at IS NULL OR %s::timestamptz IS NULL"
        " OR (%s,%s,%s)<=(stat_rating_rebuilds.last_ended_at,stat_rating_rebuilds.last_server_id,stat_rating_rebuilds.last_event_id)"
        " THEN NULL ELSE stat_rating_rebuilds.last_server_id END,"
        " last_event_id=CASE WHEN stat_rating_rebuilds.last_ended_at IS NULL OR %s::timestamptz IS NULL"
        " OR (%s,%s,%s)<=(stat_rating_rebuilds.last_ended_at,stat_rating_rebuilds.last_server_id,stat_rating_rebuilds.last_event_id)"
        " THEN NULL ELSE stat_rating_rebuilds.last_event_id END",
        (
            season_id,
            server_id,
            event_id,
            from_at,
            from_at,
            server_id,
            event_id,
            from_at,
            from_at,
            server_id,
            event_id,
            from_at,
            from_at,
            server_id,
            event_id,
        ),
    )


async def _stat_rebuilding(conn, season_id):
    # A rebuild of an earlier season replays every later season too, so any
    # queued season at or before the requested one means stale ratings.
    row = await one(
        conn,
        "SELECT 1 AS pending FROM stat_rating_rebuilds"
        " WHERE season_id~'^s[0-9]+$' AND CAST(substr(season_id,2) AS INTEGER)<=%s",
        (int(season_id[1:]),),
    )
    return row is not None


async def _stat_rebuild_batch(conn, season, cursor):
    # One bounded batch of the season replay inside the caller's transaction.
    # Returns the new cursor, or None when the replay reached the end of
    # history. A NULL cursor starts over: earlier seasons (the carry-over
    # source) stay untouched, like _stat_rebuild_ratings.
    number = int(season["id"][1:])
    await conn.execute("SELECT pg_advisory_xact_lock(782344, 1)")
    if cursor == (None, None, None):
        await conn.execute(
            "DELETE FROM stat_rating_changes WHERE CAST(substr(season_id,2) AS INTEGER)>=%s",
            (number,),
        )
        await conn.execute(
            "DELETE FROM stat_ratings WHERE CAST(substr(season_id,2) AS INTEGER)>=%s",
            (number,),
        )
        # The wipe covers every later season too, so later queued rows restart
        # as well: resuming one from its stale cursor would skip its already
        # replayed prefix and miss ratings. The reset bumps their generation,
        # so no batch that read a later row earlier can commit over it.
        await conn.execute(
            "UPDATE stat_rating_rebuilds SET last_ended_at=NULL,last_server_id=NULL,last_event_id=NULL,"
            "generation=generation+1"
            " WHERE season_id~'^s[0-9]+$' AND CAST(substr(season_id,2) AS INTEGER)>%s",
            (number,),
        )
    where = (
        "kind='campaign' AND mode='campaign' AND (reason='draw' OR (reason='completed' AND winner IN ('RED','BLUE')))"
        " AND NOT EXISTS(SELECT 1 FROM stat_result_voids v WHERE v.server_id=stat_results.server_id AND v.event_id=stat_results.event_id)"
    )
    args: tuple = ()
    if number != 1 and cursor == (None, None, None):
        where += " AND ended_at>=%s"
        args = (_stat_dt(season["startsAt"]),)
    elif cursor != (None, None, None):
        where += " AND (ended_at,server_id,event_id)>(%s,%s,%s)"
        args = cursor
    matches = await rows(
        conn,
        "SELECT payload,ended_at,server_id,event_id FROM stat_results WHERE "
        + where
        + " ORDER BY ended_at,server_id,event_id LIMIT "
        + str(STAT_REBUILD_BATCH),
        args,
    )
    for match in matches:
        await _stat_rate(conn, match["payload"], _stat_ms(match["ended_at"]))
    if not matches:
        return None
    last = matches[-1]
    return (last["ended_at"], last["server_id"], last["event_id"])


async def stat_rebuild_drain(conn):
    # One bounded batch per call, inside the caller's transaction. The queue
    # row is read without locking it, so a concurrent void/ingest enqueue
    # never waits on the replay; the generation compare-and-swap below turns
    # a concurrent enqueue into another pass instead of losing it. Returns
    # the rebuilt season id, or None when idle. The worker always serves the
    # earliest queued season first: a later season's ratings carry over from
    # the earlier one, so a later row waits while an earlier replay is
    # pending. The batch commits only when its guarded write hits: the
    # rating writes and the cursor advance share one transaction, and a
    # generation bump by any concurrent enqueue/reset makes the write miss,
    # so the batch rolls back to the savepoint and the next pass re-reads
    # the fresh row instead of committing stale ratings or a stale cursor.
    row = await one(
        conn,
        "SELECT season_id,generation,last_ended_at,last_server_id,last_event_id"
        " FROM stat_rating_rebuilds ORDER BY CASE WHEN season_id~'^s[0-9]+$'"
        " THEN CAST(substr(season_id,2) AS INTEGER) ELSE 2147483647 END,requested_at LIMIT 1",
    )
    if row is None:
        return None
    season = next((s for s in stat_seasons() if s["id"] == row["season_id"]), None)
    if season is None:
        await conn.execute(
            "DELETE FROM stat_rating_rebuilds WHERE season_id=%s",
            (row["season_id"],),
        )
        return None
    cursor = (
        (None, None, None)
        if row["last_ended_at"] is None
        else (row["last_ended_at"], row["last_server_id"], row["last_event_id"])
    )
    await conn.execute("SAVEPOINT stat_rebuild_batch")
    advanced = await _stat_rebuild_batch(conn, season, cursor)
    if advanced is None:
        # End of history: drop the row only if nobody re-enqueued during the
        # batch, otherwise the new request gets its own pass.
        done = await conn.execute(
            "DELETE FROM stat_rating_rebuilds WHERE season_id=%s AND generation=%s",
            (row["season_id"], row["generation"]),
        )
    else:
        done = await conn.execute(
            "UPDATE stat_rating_rebuilds SET last_ended_at=%s,last_server_id=%s,last_event_id=%s"
            " WHERE season_id=%s AND generation=%s",
            (*advanced, row["season_id"], row["generation"]),
        )
    if done.rowcount == 0:
        await conn.execute("ROLLBACK TO SAVEPOINT stat_rebuild_batch")
    return season["id"]


async def stat_gap_scan(conn):
    # Self-healing gap detection: the earliest rated campaign with no
    # stat_rating_changes row was committed by a path that never rated it
    # (pre-005 rows, an old instance during rollout, or a lost race). Enqueue
    # a rebuild from its season; idempotent, never a duplicate row.
    gap = await one(
        conn,
        "SELECT r.server_id,r.event_id,r.ended_at FROM stat_results r"
        " WHERE r.kind='campaign' AND r.mode='campaign' AND (r.reason='draw' OR (r.reason='completed' AND r.winner IN ('RED','BLUE')))"
        " AND NOT EXISTS(SELECT 1 FROM stat_result_voids v WHERE v.server_id=r.server_id AND v.event_id=r.event_id)"
        " AND NOT EXISTS(SELECT 1 FROM stat_rating_changes c WHERE c.server_id=r.server_id AND c.event_id=r.event_id)"
        " AND EXISTS(SELECT 1 FROM stat_participants p WHERE p.server_id=r.server_id AND p.event_id=r.event_id AND p.team='RED')"
        " AND EXISTS(SELECT 1 FROM stat_participants p WHERE p.server_id=r.server_id AND p.event_id=r.event_id AND p.team='BLUE')"
        " ORDER BY r.ended_at,r.server_id,r.event_id LIMIT 1",
    )
    if gap is None:
        return None
    season = stat_season_at(_stat_ms(gap["ended_at"]))
    busy = await one(
        conn,
        "SELECT 1 AS busy FROM stat_rating_rebuilds"
        " WHERE season_id~'^s[0-9]+$' AND CAST(substr(season_id,2) AS INTEGER)<=%s"
        " AND last_ended_at IS NOT NULL",
        (int(season["id"][1:]),),
    )
    if busy is not None:
        # An earlier-or-equal replay is already progressing: it covers the gap
        # when committed before its cursor passes, and a later scan heals the
        # rest. Enqueuing here would restart the in-flight replay, so the
        # periodic scan would churn replays longer than its own interval.
        return None
    await _stat_enqueue_rebuild(
        conn, season["id"], gap["server_id"], gap["event_id"], None
    )
    return season["id"]


async def _stat_try_worker_lock(conn):
    # One rebuild worker across all CP replicas: the loop holds this
    # session-level lock for its whole life; a replica that cannot take it
    # just sleeps and retries instead of replaying concurrently. Call inside
    # a committing transaction (the session lock survives the commit).
    row = await one(
        conn,
        "SELECT pg_try_advisory_lock(hashtext('stats-rebuild-worker'),1) AS held",
    )
    return bool(row["held"])


async def stat_rebuild_loop(db, interval=0.5, gap_interval=300.0):
    # Background worker: the void request only enqueues (fast commit), this
    # loop replays one bounded batch per poll. A crash between enqueue and
    # replay just leaves the row for the next poll; an unknown season id is
    # dropped, never retried forever. The gap scan on start and every
    # gap_interval heals campaigns committed by paths that never rated them.
    # The loop holds one checked-out connection for its whole life so the
    # session worker lock above survives across batch transactions.
    import asyncio
    import time

    async with db.pool.connection() as conn:
        # The try-lock SELECT must run inside a committing transaction: a
        # bare SELECT would leave an implicit transaction open, and every
        # later batch would nest inside it and never durably commit. The
        # session lock itself survives the commit.
        while True:
            async with conn.transaction():
                if await _stat_try_worker_lock(conn):
                    break
            await asyncio.sleep(interval)
        last_gap = 0.0
        while True:
            try:
                if time.monotonic() - last_gap >= gap_interval:
                    async with conn.transaction():
                        await stat_gap_scan(conn)
                    last_gap = time.monotonic()
                async with conn.transaction():
                    await stat_rebuild_drain(conn)
            except Exception:
                pass
            await asyncio.sleep(interval)


def _stat_window(query):
    return (
        datetime.fromtimestamp(query["since"] / 1000, tz=timezone.utc),
        datetime.fromtimestamp(query["until"] / 1000, tz=timezone.utc),
    )


def _stat_alive():
    return "NOT EXISTS(SELECT 1 FROM stat_result_voids v WHERE v.server_id=r.server_id AND v.event_id=r.event_id)"


async def stat_leaderboard(conn, query, uuid=None):
    # Campaign summaries never count twice: combat metrics come from matches
    # only. Rank is numbered over the whole filtered aggregate before the
    # uuid/page cut, so a player's rank matches the board.
    since, until = _stat_window(query)
    where = (
        "r.kind='match' AND " + _stat_alive() + " AND r.ended_at>=%s AND r.ended_at<=%s"
        " AND (%s::text IS NULL OR r.mode=%s)"
    )
    args = [since, until, query["mode"], query["mode"]]
    found = await rows(
        conn,
        "SELECT * FROM (SELECT *,ROW_NUMBER() OVER (ORDER BY "
        + STAT_SORTS[query["sort"]]
        + ' DESC,uuid ASC) AS "rank" FROM ('
        "SELECT p.uuid,pr.name,SUM(p.score) AS score,SUM(p.kills) AS kills,SUM(p.deaths) AS deaths,"
        "SUM(p.captures) AS captures,SUM(p.neutralizations) AS neutralizations,"
        'SUM(p.point_seconds) AS "pointSeconds",SUM(p.play_seconds) AS "playSeconds",'
        'SUM(p.suicides) AS suicides,SUM(p.team_kills) AS "teamKills",MAX(p.max_streak) AS "maxKillstreak",'
        "COUNT(*) AS matches,SUM(CASE WHEN r.reason='completed' AND ("
        "(r.mode='deathmatch' AND (r.payload->>'winnerUuid')=p.uuid) OR "
        "(r.mode!='deathmatch' AND p.team!='NONE' AND r.winner=p.team)"
        ") THEN 1 ELSE 0 END) AS wins,"
        "ROUND(CAST(SUM(p.kills)*1.0/greatest(1,SUM(p.deaths)) AS NUMERIC),3) AS kd,"
        'MAX(rt.rating) AS rating,MAX(rt.rd) AS rd,MAX(rt.rated_campaigns) AS "ratedCampaigns"'
        " FROM stat_participants p JOIN stat_results r USING(server_id,event_id)"
        " JOIN stat_profiles pr ON pr.uuid=p.uuid"
        " LEFT JOIN stat_ratings rt ON rt.season_id=%s AND rt.uuid=p.uuid"
        " WHERE " + where + " GROUP BY p.uuid,pr.name) aggregate_rows) ranked_rows"
        ' WHERE (%s::text IS NULL OR uuid=%s) ORDER BY "rank" LIMIT %s OFFSET %s',
        (
            query["mmrSeason"],
            *args,
            uuid,
            uuid,
            query["limit"],
            (query["page"] - 1) * query["limit"],
        ),
    )
    total = await one(
        conn,
        "SELECT COUNT(DISTINCT p.uuid) AS total FROM stat_participants p"
        " JOIN stat_results r USING(server_id,event_id) WHERE " + where,
        args,
    )
    players = []
    for row in found:
        players.append(
            {
                "uuid": row["uuid"],
                "name": _stat_display_name(row["name"]),
                "rank": row["rank"],
                "score": _stat_num(float(row["score"])),
                "kills": int(row["kills"]),
                "deaths": int(row["deaths"]),
                "kd": _stat_num(float(row["kd"])),
                "captures": int(row["captures"]),
                "neutralizations": int(row["neutralizations"]),
                "pointSeconds": int(row["pointSeconds"]),
                "playSeconds": int(row["playSeconds"]),
                "suicides": int(row["suicides"]),
                "teamKills": int(row["teamKills"]),
                "maxKillstreak": int(row["maxKillstreak"]),
                "matches": row["matches"],
                "wins": int(row["wins"]),
                "mmr": _stat_mmr(
                    {
                        "rating": row["rating"],
                        "rd": row["rd"],
                        "ratedCampaigns": row["ratedCampaigns"],
                    }
                    if row["rating"] is not None
                    else None
                ),
            }
        )
    return {
        "schemaVersion": 1,
        "checkedAt": _stat_iso(int(now().timestamp() * 1000)),
        "mode": query["mode"],
        "season": query["season"],
        "mmrSeason": query["mmrSeason"],
        "page": query["page"],
        "limit": query["limit"],
        "total": total["total"],
        "ratingStatus": STAT_RULES_VERSION,
        "ratingsRebuilding": await _stat_rebuilding(conn, query["mmrSeason"]),
        "players": players,
    }


async def stat_player(conn, query, player_uuid):
    if not STAT_UUID.match(player_uuid or ""):
        raise Problem("invalid_player", 400)
    profile = await one(
        conn,
        "SELECT uuid,name,last_seen FROM stat_profiles WHERE uuid=%s",
        (player_uuid,),
    )
    if profile is None:
        raise Problem("player_not_found", 404)
    since, until = _stat_window(query)
    totals = (
        await stat_leaderboard(conn, {**query, "page": 1, "limit": 1}, player_uuid)
    )["players"]
    history = await rows(
        conn,
        'SELECT r.event_id AS "eventId",r.server_id AS "serverId",r.kind,r.mode,'
        'r.campaign_id AS "campaignSessionId",r.ended_at,r.reason,r.winner,'
        "(r.payload->>'winnerUuid') AS \"winnerUuid\",p.team,p.score,p.kills,p.deaths"
        " FROM stat_participants p JOIN stat_results r USING(server_id,event_id)"
        " WHERE p.uuid=%s AND "
        + _stat_alive()
        + " AND r.ended_at>=%s AND r.ended_at<=%s"
        " AND (%s::text IS NULL OR r.mode=%s)"
        " ORDER BY r.ended_at DESC,r.server_id,r.event_id LIMIT %s OFFSET %s",
        (
            player_uuid,
            since,
            until,
            query["mode"],
            query["mode"],
            query["limit"],
            (query["page"] - 1) * query["limit"],
        ),
    )
    classes = await rows(
        conn,
        'SELECT c.class_id AS "classId",c.variant_id AS "variantId",'
        'SUM(c.time_seconds) AS "timeSeconds",SUM(c.kills) AS kills,'
        'SUM(c.deaths) AS deaths,SUM(c.point_seconds) AS "pointSeconds"'
        " FROM stat_classes c JOIN stat_results r USING(server_id,event_id)"
        " WHERE r.kind='match' AND " + _stat_alive() + " AND c.uuid=%s"
        " AND r.ended_at>=%s AND r.ended_at<=%s AND (%s::text IS NULL OR r.mode=%s)"
        " GROUP BY c.class_id,c.variant_id"
        ' ORDER BY "timeSeconds" DESC,c.class_id,c.variant_id',
        (player_uuid, since, until, query["mode"], query["mode"]),
    )
    campaigns = await one(
        conn,
        "SELECT COUNT(*) AS completed,COALESCE(SUM(CASE WHEN r.winner=p.team AND p.team!='NONE' THEN 1 ELSE 0 END),0) AS wins"
        " FROM stat_participants p JOIN stat_results r USING(server_id,event_id)"
        " WHERE r.kind='campaign' AND "
        + _stat_alive()
        + " AND r.reason IN ('completed','draw') AND p.uuid=%s"
        " AND r.ended_at>=%s AND r.ended_at<=%s AND (%s::text IS NULL OR r.mode=%s)",
        (player_uuid, since, until, query["mode"], query["mode"]),
    )
    rating = await one(
        conn,
        'SELECT rating,rd,rated_campaigns AS "ratedCampaigns" FROM stat_ratings WHERE season_id=%s AND uuid=%s',
        (query["mmrSeason"], player_uuid),
    )
    changes = await rows(
        conn,
        'SELECT event_id AS "campaignSessionId",rated_at,team,score,'
        "ROUND(before_rating) AS before,ROUND(after_rating) AS after,ROUND(after_rd) AS rd"
        " FROM stat_rating_changes WHERE uuid=%s AND season_id=%s AND rated_at>=%s AND rated_at<=%s"
        " AND (%s::text IS NULL OR %s::text='campaign') ORDER BY rated_at DESC,event_id LIMIT 20",
        (player_uuid, query["mmrSeason"], since, until, query["mode"], query["mode"]),
    )
    return {
        "schemaVersion": 1,
        "checkedAt": _stat_iso(int(now().timestamp() * 1000)),
        "season": query["season"],
        "mmrSeason": query["mmrSeason"],
        "profile": {
            "uuid": profile["uuid"],
            "name": _stat_display_name(profile["name"]),
            "lastSeen": _stat_ms(profile["last_seen"]),
        },
        "totals": totals[0] if totals else None,
        "classes": [
            {
                "classId": row["classId"],
                "variantId": row["variantId"],
                "timeSeconds": int(row["timeSeconds"]),
                "kills": int(row["kills"]),
                "deaths": int(row["deaths"]),
                "pointSeconds": int(row["pointSeconds"]),
            }
            for row in classes
        ],
        "campaigns": {
            "completed": campaigns["completed"],
            "wins": int(campaigns["wins"]),
        },
        "history": [
            {
                "eventId": row["eventId"],
                "serverId": row["serverId"],
                "kind": row["kind"],
                "mode": row["mode"],
                "campaignSessionId": row["campaignSessionId"],
                "endedAt": _stat_ms(row["ended_at"]),
                "reason": row["reason"],
                "winner": row["winner"],
                "winnerUuid": row["winnerUuid"],
                "team": row["team"],
                "score": _stat_num(float(row["score"])),
                "kills": row["kills"],
                "deaths": row["deaths"],
            }
            for row in history
        ],
        "page": query["page"],
        "limit": query["limit"],
        "mmr": _stat_mmr(
            {
                "rating": rating["rating"],
                "rd": rating["rd"],
                "ratedCampaigns": rating["ratedCampaigns"],
            }
            if rating is not None
            else None
        ),
        "ratingHistory": [
            {
                "campaignSessionId": row["campaignSessionId"],
                "ratedAt": _stat_ms(row["rated_at"]),
                "team": row["team"],
                "score": _stat_num(float(row["score"])),
                "before": int(row["before"]),
                "after": int(row["after"]),
                "rd": int(row["rd"]),
            }
            for row in changes
        ],
        "ratingStatus": STAT_RULES_VERSION,
        "ratingsRebuilding": await _stat_rebuilding(conn, query["mmrSeason"]),
    }


async def stat_hitreg(conn, query):
    # Hit-reg telemetry aggregated over a window, straight from PostgreSQL;
    # per-row telemetry is never parsed in Python. The scan stops at the
    # newest STAT_HITREG_SCAN_CAP matches (`truncated` says so).
    if query["mode"] is not None and query["mode"] not in STAT_MODES:
        _stat_filter_invalid()
    since, until = _stat_window(query)
    scan = (
        "SELECT (payload->'telemetry') AS t,"
        "row_number() OVER (ORDER BY ended_at DESC,server_id,event_id) AS rn FROM stat_results r"
        " WHERE kind='match' AND "
        + _stat_alive()
        + " AND ended_at>=%s AND ended_at<=%s"
        " AND (%s::text IS NULL OR mode=%s) LIMIT " + str(STAT_HITREG_SCAN_CAP + 1)
    )
    args = (since, until, query["mode"], query["mode"])

    def tele(expr):
        return "(SELECT " + expr + " FROM tele)"

    def mid(field):
        return (
            "percentile_cont(0.5) WITHIN GROUP (ORDER BY (t->>'"
            + field
            + "')::double precision)"
        )

    def p99(field):
        return (
            "percentile_cont(0.99) WITHIN GROUP (ORDER BY (t->>'"
            + field
            + "')::double precision)"
        )

    agg = await one(
        conn,
        "WITH scan AS (" + scan + "),"
        "capped AS (SELECT t FROM scan WHERE rn<=" + str(STAT_HITREG_SCAN_CAP) + "),"
        "tele AS (SELECT t FROM capped WHERE jsonb_typeof(t)='object')"
        " SELECT (SELECT COUNT(*) FROM capped) AS matches,"
        "(SELECT COUNT(*) FROM scan)>" + str(STAT_HITREG_SCAN_CAP) + " AS truncated,"
        '(SELECT COUNT(*) FROM tele) AS "withTelemetry",'
        + tele("COALESCE(SUM((t->>'shots')::bigint),0)")
        + " AS shots,"
        + tele(
            "COALESCE(SUM((t->>'fallbackShare')::double precision*(t->>'shots')::bigint),0)"
        )
        + ' AS "fallbackShots",'
        + tele("COALESCE(SUM(jsonb_array_length(t->'disputes')),0)")
        + " AS disputes,"
        + tele(mid("tickMsP50"))
        + ' AS "tickMsP50Median",'
        + tele(p99("tickMsP50"))
        + ' AS "tickMsP50P99",'
        + tele(mid("tickMsP99"))
        + ' AS "tickMsP99Median",'
        + tele(p99("tickMsP99"))
        + ' AS "tickMsP99P99",'
        + tele(mid("ageTicksP50"))
        + ' AS "ageTicksP50Median",'
        + tele(p99("ageTicksP50"))
        + ' AS "ageTicksP50P99",'
        + tele(mid("rewindTicksP50"))
        + ' AS "rewindTicksP50Median",'
        + tele(p99("rewindTicksP50"))
        + ' AS "rewindTicksP50P99"',
        args,
    )
    counter_rows = await rows(
        conn,
        "WITH scan AS (" + scan + "),"
        "capped AS (SELECT t FROM scan WHERE rn<="
        + str(STAT_HITREG_SCAN_CAP)
        + " AND jsonb_typeof(t)='object')"
        " SELECT name,SUM(value::bigint) AS total FROM capped"
        " CROSS JOIN LATERAL jsonb_each_text("
        "CASE WHEN jsonb_typeof(t->'counters')='object' THEN t->'counters' ELSE '{}'::jsonb END"
        ") c(name,value) GROUP BY name",
        args,
    )
    shots = int(agg["shots"])

    def median(value):
        return None if value is None else _stat_num(float(value))

    return {
        "schemaVersion": 1,
        "checkedAt": _stat_iso(int(now().timestamp() * 1000)),
        "mode": query["mode"],
        "matches": agg["matches"],
        "withTelemetry": agg["withTelemetry"],
        "telemetryDropped": telemetry_dropped,
        "truncated": agg["truncated"],
        "shots": shots,
        "fallbackShare": _stat_num(float(agg["fallbackShots"]) / shots if shots else 0),
        "disputes": int(agg["disputes"]),
        "counters": {row["name"]: int(row["total"]) for row in counter_rows},
        "tickMsP50Median": median(agg["tickMsP50Median"]),
        "tickMsP50P99": median(agg["tickMsP50P99"]),
        "tickMsP99Median": median(agg["tickMsP99Median"]),
        "tickMsP99P99": median(agg["tickMsP99P99"]),
        "ageTicksP50Median": median(agg["ageTicksP50Median"]),
        "ageTicksP50P99": median(agg["ageTicksP50P99"]),
        "rewindTicksP50Median": median(agg["rewindTicksP50Median"]),
        "rewindTicksP50P99": median(agg["rewindTicksP50P99"]),
    }


async def stat_void(conn, identity, attempt, model):
    # attempt is consumed by app.write's completion audit; voids carry no
    # operation row, like site sessions. Voiding or restoring a rated campaign
    # replays its season and every later season from scratch, which also folds
    # in any earlier late results — the site setVoided contract. The replay
    # must not run inside the 10 s request, nor may the request wait on it:
    # it only commits the void row and enqueues the season (cursor restarts
    # only when the voided campaign sits at or behind it, no rating lock), and the background loop replays it in
    # bounded batches; reads report ratingsRebuilding until it lands.
    identity.require("stats.void", "prod", "game", "*")
    server_id, event_id = str(model.serverId), str(model.eventId)
    await conn.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
        (server_id + "/" + event_id,),
    )
    match = await one(
        conn,
        "SELECT kind,mode,reason,ended_at FROM stat_results WHERE server_id=%s AND event_id=%s",
        (server_id, event_id),
    )
    if match is None:
        raise Problem("result_not_found", 404)
    voided = await one(
        conn,
        "SELECT 1 FROM stat_result_voids WHERE server_id=%s AND event_id=%s",
        (server_id, event_id),
    )
    if model.voided:
        if voided is not None:
            raise Problem("result_void_conflict", 409)
        await conn.execute(
            "INSERT INTO stat_result_voids(server_id,event_id,voided_by) VALUES(%s,%s,%s)",
            (server_id, event_id, str(identity.actor)),
        )
    else:
        if voided is None:
            raise Problem("result_void_conflict", 409)
        await conn.execute(
            "DELETE FROM stat_result_voids WHERE server_id=%s AND event_id=%s",
            (server_id, event_id),
        )
    rebuilt = None
    if (
        match["kind"] == "campaign"
        and match["mode"] == "campaign"
        and match["reason"] in ("completed", "draw")
    ):
        season = stat_season_at(_stat_ms(match["ended_at"]))
        await _stat_enqueue_rebuild(
            conn, season["id"], server_id, event_id, match["ended_at"]
        )
        rebuilt = season["id"]
    return {
        "rebuilt": rebuilt,
        "match": {
            "kind": match["kind"],
            "mode": match["mode"],
            "mapId": None,
            "endedAt": _stat_ms(match["ended_at"]),
        },
    }
