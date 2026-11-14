"""Real PostgreSQL + ASGI tests; no production services or executor effects."""

import asyncio
import base64
import hashlib
import ipaddress
import json
import random
import secrets
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import cbor2
import httpx
import psycopg
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from pgserver import get_server
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg.types.json import Jsonb
from webauthn.helpers import bytes_to_base64url

from cpv2 import app as cpv2_app
from cpv2 import core, delivery
from cpv2.admin import (
    bootstrap,
    enroll_owner,
    main as admin_main,
    provision,
    revoke as revoke_credential,
)
from cpv2.app import create_app, raw_path
from cpv2.auth import (
    OWNER_SCOPES,
    ROLE_SCOPES,
    SERVICE_SCOPES,
    Problem,
    authenticate,
    now,
    verifier,
)
from cpv2.db import MIGRATIONS, migrate, one
from cpv2.legacy import import_u1
from cpv2.settings import canonical, digest

# Frozen U1 fixture builder (replaces the deleted api.py): creates the same
# legacy SQLite tables the v2 import path reads, with no U1 server code.
_U1_DDL = """
CREATE TABLE IF NOT EXISTS tokens(
  id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
  verifier_hash TEXT NOT NULL, scopes TEXT NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER,
  revoked_at INTEGER, last_used_at INTEGER);
CREATE TABLE IF NOT EXISTS gate_state(
  revision INTEGER NOT NULL, mode TEXT NOT NULL,
  message TEXT NOT NULL, since INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS gate_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL UNIQUE,
  idempotency_key TEXT NOT NULL, revision INTEGER NOT NULL,
  mode TEXT NOT NULL, message TEXT NOT NULL,
  actor_id TEXT NOT NULL, actor_role TEXT NOT NULL, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL,
  actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL);
"""


def _u1_now_ms():
    return int(time.time() * 1000)


def _u1_derive_token(secret, name):
    raw = hashlib.sha256(secret.encode() + b"\n" + name.encode()).digest()
    return "cp_" + base64.urlsafe_b64encode(raw).decode().rstrip("=")


class _U1:
    """Minimal legacy-DB writer: bootstrap + one gate write, same rows as U1."""

    def __init__(self, path):
        self.db = sqlite3.connect(str(path))
        self.db.executescript(_U1_DDL)
        if self.db.execute("SELECT COUNT(*) FROM gate_state").fetchone()[0] == 0:
            t = _u1_now_ms()
            self.db.execute("INSERT INTO gate_state VALUES (0,'open','',?,?)", (t, t))
        self.db.commit()

    def bootstrap(self, secret):
        if self.db.execute("SELECT COUNT(*) FROM tokens").fetchone()[0]:
            return {}
        seeds = {"proxy": "gate:read", "site": "gate:read,gate:write"}
        out, t = {}, _u1_now_ms()
        for name, scopes in seeds.items():
            token = _u1_derive_token(secret, name)
            self.db.execute(
                "INSERT INTO tokens VALUES (?,?,?,?,?,?,?,?)",
                (
                    secrets.token_hex(8),
                    name,
                    hashlib.sha256(token.encode()).hexdigest(),
                    scopes,
                    t,
                    None,
                    None,
                    None,
                ),
            )
            out[name] = token
        self.db.commit()
        return out

    def set_gate(self, mode, message, actor_id, actor_role, expected, key):
        message = message.strip()[:500]
        rev, cur, _, since, _ = self.db.execute("SELECT * FROM gate_state").fetchone()
        if expected != rev:
            raise ValueError(f"revision conflict: have {rev}")
        t, op, new_rev = _u1_now_ms(), secrets.token_hex(12), rev + 1
        self.db.execute(
            "INSERT INTO gate_log(operation_id,idempotency_key,revision,mode,"
            "message,actor_id,actor_role,at) VALUES (?,?,?,?,?,?,?,?)",
            (op, key, new_rev, mode, message, actor_id, actor_role, t),
        )
        self.db.execute(
            "UPDATE gate_state SET revision=?,mode=?,message=?,since=?,updated_at=?",
            (new_rev, mode, message, t if mode != cur else since, t),
        )
        self.db.execute(
            "INSERT INTO audit(at,actor,action,detail) VALUES (?,?,?,?)",
            (
                t,
                actor_id + ":" + actor_role,
                "gate:set",
                json.dumps({"revision": new_rev, "mode": mode})[:500],
            ),
        )
        self.db.commit()
        return {"operationId": op, "revision": new_rev}

    def gate(self):
        rev, mode, message, since, _ = self.db.execute(
            "SELECT * FROM gate_state"
        ).fetchone()
        return {
            "schema": 1,
            "revision": rev,
            "mode": mode,
            "message": message,
            "since": since,
            "observedAt": _u1_now_ms(),
        }


def _docker_default_runs_cpv2():
    root = Path(__file__).resolve().parents[1] / "Dockerfile"
    text = root.read_text()
    assert 'CMD ["python", "-m", "cpv2"]' in text, (
        "image default must be python -m cpv2"
    )
    assert "api.py" not in text, "U1 api.py must not ship in the image"


def test_docker_default_runs_cpv2():
    _docker_default_runs_cpv2()


@pytest.fixture(scope="session")
def postgres():
    Path(".cache").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cp-pg-", dir=".cache") as temp:
        server = get_server(Path(temp).resolve(), cleanup_mode="stop")
        try:
            # Fresh task-owned Unix-socket backend; never adopt a shared database.
            assert server.get_pid()
            with psycopg.connect(server.get_uri(), autocommit=True) as conn:
                conn.execute(
                    "CREATE ROLE cp_api LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE"
                )
            yield server.get_uri()
        finally:
            server.cleanup()


@pytest.fixture
async def store(postgres):
    name = "cp_" + uuid4().hex
    async with await psycopg.AsyncConnection.connect(postgres, autocommit=True) as conn:
        await conn.execute(f'CREATE DATABASE "{name}"')
    admin = make_conninfo(postgres, dbname=name)
    runtime = make_conninfo(admin, user="cp_api")
    await migrate(admin, name)
    async with await psycopg.AsyncConnection.connect(admin) as conn:
        await conn.execute("GRANT cp_runtime TO cp_api")
    key = ec.generate_private_key(ec.SECP256R1())
    numbers = key.public_key().public_numbers()
    cose = cbor2.dumps(
        {
            1: 2,
            3: -7,
            -1: 1,
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        }
    )
    credential = {
        "id": bytes_to_base64url(b"test-credential"),
        "publicKey": bytes_to_base64url(cose),
        "origin": "https://control.example.test",
        "rpId": "control.example.test",
    }
    owner = uuid4()
    await bootstrap(admin, owner, "owner", credential)
    accounts, tokens = {"owner": owner}, {}
    for role in ("owner", "admin", "moderator", "builder", "ordinary", "other"):
        account = owner if role == "owner" else uuid4()
        accounts[role] = account
        role_name = "builder" if role == "other" else role
        grants = (
            []
            if role_name not in ROLE_SCOPES
            else [
                {
                    "role": role_name,
                    "environment": "prod",
                    "backend": "game",
                    "resource": "*",
                    "grantor": str(owner),
                }
            ]
        )
        tokens[role] = await provision(
            admin,
            {
                "client": {
                    "id": role,
                    "via": "ui" if role == "owner" else "cli",
                    "human": True,
                    "ceiling": sorted(OWNER_SCOPES),
                },
                "accountId": str(account),
                "displayName": role,
                "ceiling": sorted(OWNER_SCOPES),
                "environment": "prod",
                "backend": "game",
                "resource": "*",
                "grants": grants,
            },
        )
    generation = uuid4()
    for consumer in ("game", "workshop"):
        tokens[consumer + "-agent"] = await provision(
            admin,
            {
                "client": {
                    "id": consumer,
                    "via": "game",
                    "ceiling": ["agents.acks", "agents.events", "gate:read"],
                },
                "ceiling": ["agents.acks", "agents.events", "gate:read"],
                "environment": "prod",
                "backend": "game",
                "resource": "*",
                "consumer": {
                    "id": consumer,
                    "generation": str(generation),
                    "capabilities": [
                        "settings.gameplay",
                        "settings.gate",
                        "moderation.kick",
                        "moderation.ban",
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
                        "console.run",
                        "console.suggest",
                    ]
                    + (
                        [
                            "workshop.members",
                            "workshop.message",
                            "workshop.wake",
                            "workshop.cancel",
                            "workshop.release.select",
                            "workshop.map",
                            "workshop.sessions",
                            "workshop.ai-key",
                            "workshop.mode",
                        ]
                        if consumer == "workshop"
                        else []
                    ),
                },
            },
        )
    app = create_app(runtime)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="https://control.example.test",
        ) as client:
            yield {
                "admin": admin,
                "runtime": runtime,
                "accounts": accounts,
                "tokens": tokens,
                "client": client,
                "app": app,
                "key": key,
                "credential": credential,
                "generation": generation,
                "counter": 0,
            }
    async with await psycopg.AsyncConnection.connect(postgres, autocommit=True) as conn:
        await conn.execute(f'DROP DATABASE "{name}"')


def headers(store, role="admin"):
    return {"Authorization": "Bearer " + store["tokens"][role]}


async def request(store, method, path, body=None, role="admin", extra=None):
    return await store["client"].request(
        method, path, json=body, headers={**headers(store, role), **(extra or {})}
    )


def patch(key="settings", revision=0, value=None):
    return {
        "idempotencyKey": key,
        "environment": "prod",
        "backend": "game",
        "expectedRevision": revision,
        "patch": value or {"lobby": {"pvpEnabled": True}},
    }


async def sql(store, query, args=()):
    async with await psycopg.AsyncConnection.connect(
        store["admin"],
        options="-c search_path=control,pg_catalog",
        row_factory=psycopg.rows.dict_row,
    ) as conn:
        cursor = await conn.execute(query, args)
        return await cursor.fetchall() if cursor.description else []


async def assertion(store, method, path, body, *, origin=None, uv=True):
    response = await request(
        store,
        "POST",
        "/v2/owner/challenges",
        {"method": method, "path": path, "body": body},
        "owner",
    )
    assert response.status_code == 201, response.text
    challenge = response.json()
    client_data = canonical(
        {
            "type": "webauthn.get",
            "challenge": challenge["challenge"],
            "origin": origin or store["credential"]["origin"],
        }
    ).encode()
    store["counter"] += 1
    auth_data = (
        hashlib.sha256(store["credential"]["rpId"].encode()).digest()
        + bytes([5 if uv else 1])
        + struct.pack(">I", store["counter"])
    )
    signature = store["key"].sign(
        auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
    )
    return {
        "X-CP-Owner-Assertion": json.dumps(
            {
                "challengeId": challenge["challengeId"],
                "credential": {
                    "id": store["credential"]["id"],
                    "rawId": store["credential"]["id"],
                    "type": "public-key",
                    "response": {
                        "clientDataJSON": bytes_to_base64url(client_data),
                        "authenticatorData": bytes_to_base64url(auth_data),
                        "signature": bytes_to_base64url(signature),
                    },
                },
            }
        )
    }


async def test_bootstrap_is_independent_one_shot_and_protected(store, monkeypatch):
    monkeypatch.setenv("BLOCKFIELD_OWNER_UUIDS", str(store["accounts"]["admin"]))
    monkeypatch.setenv("CP_BOOTSTRAP_ADMIN_SECRET", "retained-u1-secret")
    assert (await request(store, "GET", "/v2/me")).json()["owner"] is False
    with pytest.raises(ValueError, match="already bootstrapped"):
        await bootstrap(store["admin"], uuid4(), "replacement", store["credential"])
    async with await psycopg.AsyncConnection.connect(
        store["runtime"], options="-c search_path=control,pg_catalog"
    ) as conn:
        for table in (
            "owner_memberships",
            "owner_credentials",
            "clients",
            "setting_definitions",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                async with conn.transaction():
                    await conn.execute(f"DELETE FROM {table}")
        with pytest.raises(psycopg.errors.CheckViolation):
            async with conn.transaction():
                await conn.execute(
                    "INSERT INTO role_grants VALUES(%s,%s,'owner','prod','game','*',%s,1,NULL,NULL)",
                    (uuid4(), store["accounts"]["admin"], store["accounts"]["owner"]),
                )


@pytest.mark.parametrize(
    "role,allowed",
    [
        ("ordinary", False),
        ("builder", False),
        ("moderator", False),
        ("admin", True),
        ("owner", True),
        ("game-agent", False),
    ],
)
async def test_settings_rbac_matrix(store, role, allowed):
    response = await request(
        store, "PATCH", "/v2/settings/gameplay/arena", patch(), role
    )
    assert response.status_code == (202 if allowed else 403), response.text
    count = await sql(store, "SELECT count(*) AS n FROM settings_revisions")
    assert count[0]["n"] == int(allowed)


async def test_admin_cannot_become_owner_by_any_api_route(store):
    target = str(store["accounts"]["admin"])
    grants = {
        "idempotencyKey": "grant",
        "environment": "prod",
        "backend": "game",
        "expectedRevision": 1,
        "accountId": target,
        "resource": "*",
        "role": "owner",
    }
    attempts = [
        ("POST", "/v2/staff/grants", grants),
        ("POST", "/v2/staff/grants", dict(grants, role="admin")),
        ("POST", "/v2/staff/grants", dict(grants, role="builder")),
        (
            "POST",
            "/v2/owner/challenges",
            {"method": "POST", "path": "/v2/staff/grants", "body": grants},
        ),
        ("POST", "/v2/owner/bootstrap", grants),
        (
            "POST",
            "/v2/accounts/" + target + "/test-status",
            {
                "idempotencyKey": "test",
                "expectedRevision": 1,
                "isTest": True,
                "reason": "fake owner",
                "expiresInSeconds": 60,
            },
        ),
        (
            "POST",
            "/v2/delegations",
            {
                "idempotencyKey": "delegate",
                "scopes": ["staff.admin.manage"],
                "resource": "*",
            },
        ),
        (
            "PATCH",
            "/v2/settings/ai-limits/global",
            patch(value={"sessions": {"12345678-1234-1234-1234-1234567890ab": 1000}}),
        ),
        (
            "PATCH",
            "/v2/settings/gameplay/arena",
            dict(patch(), actor={"id": target, "role": "owner"}),
        ),
        ("PATCH", "/v2/settings/gameplay/arena", patch(value={"owner": target})),
        (
            "POST",
            "/v2/actions/console.raw",
            {
                "idempotencyKey": "raw",
                "consumerId": "game",
                "generation": str(store["generation"]),
                "target": "arena",
                "playerId": str(uuid4()),
            },
        ),
        (
            "POST",
            "/v1/gate",
            {"mode": "open", "actor": {"id": target, "role": "owner"}},
        ),
    ]
    for method, path, body in attempts:
        response = await request(store, method, path, body)
        assert response.status_code in (403, 404, 405, 422), (path, response.text)
    owners = await sql(store, "SELECT account_id FROM owner_memberships")
    assert [o["account_id"] for o in owners] == [store["accounts"]["owner"]]
    assert not await sql(store, "SELECT * FROM operations")
    assert not await sql(store, "SELECT * FROM outbox")


async def test_grants_scope_self_peer_higher_and_epoch_revocation(store):
    base = {
        "idempotencyKey": "grant",
        "expectedRevision": 1,
        "accountId": str(store["accounts"]["other"]),
        "role": "moderator",
        "resource": "arena",
    }
    # A lower-role grant succeeds, increments the target epoch and revokes old sessions.
    response = await request(store, "POST", "/v2/staff/grants", base)
    assert response.status_code == 202, response.text
    assert (await request(store, "GET", "/v2/me", role="other")).status_code == 401
    for target, role in (
        ("admin", "builder"),
        ("owner", "builder"),
        ("other", "admin"),
    ):
        value = dict(
            base,
            idempotencyKey="deny-" + target + role,
            accountId=str(store["accounts"][target]),
            role=role,
        )
        assert (
            await request(store, "POST", "/v2/staff/grants", value)
        ).status_code == 403
    # A map-scoped credential cannot widen its own or another subject's resource.
    await sql(
        store,
        "UPDATE credentials SET resource='arena' WHERE account_id=%s",
        (store["accounts"]["admin"],),
    )
    response = await request(store, "PATCH", "/v2/settings/gameplay/other-map", patch())
    assert response.status_code == 403


async def test_owner_stepup_is_action_bound_one_use_user_verified_and_origin_bound(
    store,
):
    path = "/v2/settings/ai-limits/global"
    account = "12345678-1234-1234-1234-1234567890ab"
    body = patch(value={"sessions": {account: 1000}})
    assert (await request(store, "PATCH", path, body, "owner")).status_code == 403
    for opts in ({"origin": "https://site.example.test"}, {"uv": False}):
        proof = await assertion(store, "PATCH", path, body, **opts)
        assert (
            await request(store, "PATCH", path, body, "owner", proof)
        ).status_code == 403
    proof = await assertion(store, "PATCH", path, body)
    changed_body = patch(value={"sessions": {account: 2000}})
    assert (
        await request(store, "PATCH", path, changed_body, "owner", proof)
    ).status_code == 403
    response = await request(store, "PATCH", path, body, "owner", proof)
    assert response.status_code == 202, response.text
    # Idempotent retrieval is allowed; it cannot authorize a second operation.
    assert (
        await request(store, "PATCH", path, body, "owner", proof)
    ).json() == response.json()
    second = patch(key="replay", revision=1, value={"sessions": {account: 3000}})
    assert (
        await request(store, "PATCH", path, second, "owner", proof)
    ).status_code == 403


async def test_protected_rollback_and_normalized_parent_patch(store):
    path = "/v2/settings/ai-limits/global"
    account = "12345678-1234-1234-1234-1234567890ab"
    first = patch(value={"sessions": {account: 1000}})
    assert (
        await request(
            store,
            "PATCH",
            path,
            first,
            "owner",
            await assertion(store, "PATCH", path, first),
        )
    ).status_code == 202
    second = patch("owner-second", 1, {"sessions": {account: 2000}})
    assert (
        await request(
            store,
            "PATCH",
            path,
            second,
            "owner",
            await assertion(store, "PATCH", path, second),
        )
    ).status_code == 202
    body = {"idempotencyKey": "rollback", "expectedRevision": 2, "revision": 1}
    response = await request(store, "POST", path + "/rollback", body)
    assert response.status_code == 403
    for value in (
        {"sessions": {"not-a-uuid": 100}},
        {"sessions": None},
        {"mode": "bogus"},
    ):
        assert (
            await request(store, "PATCH", path, patch("parent", 2, value))
        ).status_code in (403, 422)
    assert (await request(store, "GET", path)).json()["revision"] == 2


async def test_settings_validate_no_effect_cas_concurrency_and_idempotency(store):
    path = "/v2/settings/gameplay/arena"
    assert (
        await request(store, "POST", path + "/validate", patch())
    ).status_code == 200
    assert not await sql(store, "SELECT * FROM settings_revisions")
    assert not await sql(store, "SELECT * FROM settings_heads")
    responses = await asyncio.gather(
        request(store, "PATCH", path, patch("one")),
        request(store, "PATCH", path, patch("two")),
    )
    assert sorted(r.status_code for r in responses) == [202, 409]
    key = "one" if responses[0].status_code == 202 else "two"
    again = await request(store, "PATCH", path, patch(key))
    assert again.status_code == 202
    assert (
        await request(
            store, "PATCH", path, patch(key, value={"match": {"maxPlayers": 64}})
        )
    ).status_code == 409
    assert len(await sql(store, "SELECT * FROM settings_revisions")) == 1
    assert len(await sql(store, "SELECT * FROM outbox")) == 2
    assert (
        await request(
            store, "PATCH", path, patch("invalid", 1, {"match": {"maxPlayers": 999}})
        )
    ).status_code == 422


@pytest.mark.parametrize("stage", ["enqueue", "audit"])
async def test_audit_pending_first_verified_actor_via_and_atomic_failure(
    store, monkeypatch, stage
):
    async def fail(*args, **kwargs):
        # The committed pending attempt is visible from an independent connection.
        attempts = await sql(
            store, "SELECT outcome FROM audit_events WHERE action='PATCH'"
        )
        assert any(row["outcome"] == "pending" for row in attempts)
        raise psycopg.OperationalError("synthetic audit/outbox outage")

    monkeypatch.setattr(core, stage, fail)
    response = await request(store, "PATCH", "/v2/settings/gameplay/arena", patch())
    assert response.status_code == 503
    assert not await sql(store, "SELECT * FROM operations")
    assert not await sql(store, "SELECT * FROM settings_revisions")
    assert not await sql(store, "SELECT * FROM outbox")
    pending = await sql(
        store, "SELECT * FROM audit_events WHERE action='PATCH' AND outcome='pending'"
    )
    assert pending[0]["actor"] == store["accounts"]["admin"]
    assert pending[0]["client_id"] == "admin" and pending[0]["via"] == "cli"
    async with await psycopg.AsyncConnection.connect(
        store["runtime"], options="-c search_path=control,pg_catalog"
    ) as conn:
        for query in (
            "DELETE FROM audit_events",
            "UPDATE audit_events SET outcome='effective'",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                async with conn.transaction():
                    await conn.execute(query)


async def test_denials_invalid_bodies_and_unauthenticated_attempts_are_audited(store):
    path = "/v2/settings/gameplay/arena"
    assert (
        await request(
            store, "PATCH", path, dict(patch(), actor="sensitive-do-not-store")
        )
    ).status_code == 422
    assert (await request(store, "PATCH", path, patch(), "builder")).status_code == 403
    assert (await store["client"].patch(path, json=patch())).status_code == 401
    events = await sql(
        store, "SELECT * FROM audit_events WHERE action='PATCH' ORDER BY sequence"
    )
    assert {e["outcome"] for e in events} >= {"pending", "invalid", "denied"}
    assert "sensitive-do-not-store" not in str(events)
    for actor in (store["accounts"]["admin"], store["accounts"]["builder"]):
        attempt = [e for e in events if e["actor"] == actor]
        assert attempt[0]["outcome"] == "pending" and len(attempt) == 2


async def test_test_flag_is_owner_only_permanent_and_revokes_privileges(store):
    account = store["accounts"]["other"]
    path = f"/v2/accounts/{account}/test-status"
    body = {
        "idempotencyKey": "mark-test",
        "environment": "prod",
        "backend": "game",
        "expectedRevision": 1,
        "isTest": True,
        "reason": "isolated smoke",
        "expiresInSeconds": 60,
    }
    proof = await assertion(store, "POST", path, body)
    response = await request(store, "POST", path, body, "owner", proof)
    assert response.status_code == 202, response.text
    assert (await request(store, "GET", "/v2/me", role="other")).status_code == 401
    with pytest.raises(psycopg.Error):
        await sql(store, "UPDATE accounts SET is_test=false WHERE id=%s", (account,))
    with pytest.raises(psycopg.Error):
        await sql(
            store, "INSERT INTO owner_memberships(account_id) VALUES(%s)", (account,)
        )
    with pytest.raises(ValueError, match="ineligible"):
        await provision(
            store["admin"],
            {
                "accountId": str(account),
                "displayName": "test",
                "client": {"id": "other", "via": "cli", "ceiling": []},
                "ceiling": [],
                "environment": "prod",
                "backend": "game",
                "resource": "*",
            },
        )


async def test_service_cannot_impersonate_human_or_owner_and_delegation_ceiling(store):
    for path, value in (
        ("/v2/staff/grants", {}),
        (
            "/v2/owner/challenges",
            {"method": "POST", "path": "/v2/staff/grants", "body": {}},
        ),
        (
            "/v2/delegations",
            {"idempotencyKey": "x", "scopes": ["settings.read"], "resource": "*"},
        ),
    ):
        assert (
            await request(store, "POST", path, value, "game-agent")
        ).status_code in (403, 422)
    body = {
        "idempotencyKey": "delegate",
        "scopes": ["settings.read"],
        "resource": "arena",
    }
    response = await request(store, "POST", "/v2/delegations", body)
    assert response.status_code == 201, response.text
    token = response.json()["token"]
    repeat = await request(store, "POST", "/v2/delegations", body)
    assert repeat.status_code == 201 and repeat.json()["token"] is None
    assert repeat.json()["credentialId"] == response.json()["credentialId"]
    assert repeat.json()["operationId"] == response.json()["operationId"]
    assert (
        await store["client"].get(
            "/v2/settings/gameplay/arena", headers={"Authorization": "Bearer " + token}
        )
    ).status_code == 200
    assert (
        await store["client"].get(
            "/v2/settings/gameplay/other", headers={"Authorization": "Bearer " + token}
        )
    ).status_code == 403
    assert token not in str(await sql(store, "SELECT * FROM audit_events"))
    assert (await request(store, "DELETE", "/v2/sessions/current")).status_code == 200
    assert (
        await store["client"].get(
            "/v2/me", headers={"Authorization": "Bearer " + token}
        )
    ).status_code == 401


async def queued(store, key="action", role="moderator", consumer="game"):
    model = {
        "idempotencyKey": key,
        "environment": "prod",
        "backend": "game",
        "consumerId": consumer,
        "generation": str(store["generation"]),
        "target": "arena",
        "playerId": str(uuid4()),
        "expiresInSeconds": 60,
    }
    response = await request(store, "POST", "/v2/actions/moderation.kick", model, role)
    assert response.status_code == 202, response.text
    return response.json()


async def envelopes(store, *, cid="game", cursor=0, epoch=None):
    async with store["app"].state.db.transaction() as conn:
        identity = await authenticate(conn, store["tokens"][cid + "-agent"])
        consumer = await one(conn, "SELECT * FROM consumers WHERE id=%s", (cid,))
        return await delivery.batch(
            conn, identity, cid, epoch or consumer["epoch"], cursor
        )


def ack_body(envelope, state="received"):
    return {
        key: envelope[key]
        for key in ("epoch", "sequence", "generation", "revision", "payloadHash")
    } | {"state": state, "actualAt": now().isoformat(), "result": "ok"}


async def test_delivery_order_ack_states_duplicates_and_reconnect_cursor(store):
    op1, op2 = await queued(store, "one"), await queued(store, "two")
    values = await envelopes(store)
    assert [v["sequence"] for v in values] == [1, 2]
    assert [v["operationId"] for v in values] == [
        op1["operationId"],
        op2["operationId"],
    ]
    assert await envelopes(store, cid="workshop") == []
    assert (
        await request(
            store, "POST", "/v2/agents/game/acks", ack_body(values[1]), "game-agent"
        )
    ).status_code == 409
    assert (
        await request(
            store,
            "POST",
            "/v2/agents/game/acks",
            ack_body(values[0], "applied"),
            "game-agent",
        )
    ).status_code == 409
    for state in delivery.STATES:
        body = ack_body(values[0], state)
        response = await request(
            store, "POST", "/v2/agents/game/acks", body, "game-agent"
        )
        assert response.status_code == 200, response.text
        assert (
            await request(store, "POST", "/v2/agents/game/acks", body, "game-agent")
        ).json() == response.json()
        assert (
            await request(
                store,
                "POST",
                "/v2/agents/game/acks",
                dict(body, result="apply_failed"),
                "game-agent",
            )
        ).status_code == 409
    remaining = await envelopes(store, cursor=1)
    assert [v["sequence"] for v in remaining] == [2]
    completed = await request(
        store, "GET", "/v2/operations/" + op1["operationId"], role="moderator"
    )
    assert completed.json()["status"] == "effective"
    assert len(completed.json()["receipts"]) == 4
    with pytest.raises(Problem):
        await envelopes(store, cursor=2)
    with pytest.raises(Problem):
        await envelopes(store, epoch=uuid4())


async def test_ack_identity_hash_generation_and_audit(store):
    await queued(store)
    value = (await envelopes(store))[0]
    for changed in (
        {"generation": str(uuid4())},
        {"epoch": str(uuid4())},
        {"payloadHash": "0" * 64},
        {"revision": 1},
    ):
        response = await request(
            store,
            "POST",
            "/v2/agents/game/acks",
            ack_body(value) | changed,
            "game-agent",
        )
        assert response.status_code == 409, response.text
    assert (
        await request(
            store, "POST", "/v2/agents/game/acks", ack_body(value), "workshop-agent"
        )
    ).status_code == 403
    assert (
        await request(
            store, "POST", "/v2/agents/game/acks", ack_body(value), "game-agent"
        )
    ).status_code == 200
    audit = await sql(store, "SELECT * FROM audit_events WHERE action='agents.ack'")
    assert (
        audit[0]["via"] == "game"
        and audit[0]["actor"] is None
        and audit[0]["outcome"] == "received"
    )


async def test_moderation_commands_validate_rbac_push_and_ack(store):
    room = "12345678-1234-1234-1234-123456789012"
    bodies = {
        "moderation.say": {"text": "Hello players"},
        "moderation.list": {},
        "moderation.pardon": {"player": "Steve_01"},
        "moderation.team-kick": {"player": "Steve_01"},
        "moderation.class-lock": {"classId": "drone"},
        "moderation.class-unlock": {"classId": "drone"},
        "moderation.range": {"op": "open"},
        "moderation.stop-room": {"roomId": room, "outcome": "draw"},
    }
    for kind, extra in bodies.items():
        body = {
            "idempotencyKey": f"cpc0-{kind}",
            "environment": "prod",
            "backend": "game",
            "consumerId": "game",
            "generation": str(store["generation"]),
            "target": "arena",
            **extra,
        }
        role = "admin" if kind == "moderation.pardon" else "moderator"
        assert (
            await request(store, "POST", f"/v2/actions/{kind}", body, "builder")
        ).status_code == 403
        if kind == "moderation.pardon":
            assert (
                await request(store, "POST", f"/v2/actions/{kind}", body, "moderator")
            ).status_code == 403
        response = await request(store, "POST", f"/v2/actions/{kind}", body, role)
        assert response.status_code == 202, (kind, response.text)
        again = await request(store, "POST", f"/v2/actions/{kind}", body, role)
        assert again.json()["operationId"] == response.json()["operationId"]
    frames = await envelopes(store)
    assert [f["payload"]["kind"] for f in frames] == list(bodies), [
        f["payload"] for f in frames
    ]
    say = next(f for f in frames if f["payload"]["kind"] == "moderation.say")
    assert say["payload"] == {
        "kind": "moderation.say",
        "target": "arena",
        "text": "Hello players",
    }
    stop = next(f for f in frames if f["payload"]["kind"] == "moderation.stop-room")
    assert stop["payload"] == {
        "kind": "moderation.stop-room",
        "target": "arena",
        "roomId": room,
        "outcome": "draw",
    }
    for state in ("received", "validated", "applied"):
        acked = await request(
            store, "POST", "/v2/agents/game/acks", ack_body(say, state), "game-agent"
        )
        assert acked.status_code == 200, (state, acked.text)
    read = await request(
        store, "GET", f"/v2/operations/{say['operationId']}", role="moderator"
    )
    assert read.status_code == 200, read.text
    assert read.json()["status"] == "applied"
    assert [r["state"] for r in read.json()["receipts"]] == [
        "received",
        "validated",
        "applied",
    ]


async def test_moderation_commands_reject_bad_shapes(store):
    room = "12345678-1234-1234-1234-123456789012"
    bad = [
        ("moderation.say", {"text": "/not-a-chat"}, 422),
        ("moderation.say", {"text": "x" * 121}, 422),
        ("moderation.say", {}, 422),
        ("moderation.say", {"text": "a\x00b"}, 422),
        ("moderation.pardon", {"player": "ab"}, 422),
        ("moderation.team-kick", {"player": "has space"}, 422),
        ("moderation.class-lock", {"classId": "Drone"}, 422),
        ("moderation.range", {"op": "half"}, 422),
        ("moderation.stop-room", {"roomId": "nope", "outcome": "none"}, 422),
        ("moderation.stop-room", {"roomId": room, "outcome": "maybe"}, 422),
        (
            "moderation.stop-room",
            {"roomId": room, "outcome": "none", "reason": "win fast"},
            422,
        ),
        ("moderation.fly", {}, 404),
    ]
    for kind, extra, status in bad:
        body = {
            "idempotencyKey": f"cpc0-bad-{kind}-{status}-{len(extra)}",
            "environment": "prod",
            "backend": "game",
            "consumerId": "game",
            "generation": str(store["generation"]),
            "target": "arena",
            **extra,
        }
        response = await request(store, "POST", f"/v2/actions/{kind}", body, "admin")
        assert response.status_code == status, (kind, extra, response.text)
    assert not await sql(store, "SELECT * FROM operations")
    assert not await sql(store, "SELECT * FROM outbox")


def console_body(store, key, command, **extra):
    return {
        "idempotencyKey": key,
        "environment": "prod",
        "backend": "game",
        "consumerId": "game",
        "generation": str(store["generation"]),
        "command": command,
        **extra,
    }


async def service_token(store, client, ceiling, via="game"):
    store["tokens"][client] = await provision(
        store["admin"],
        {
            "client": {"id": client, "via": via, "ceiling": ceiling},
            "ceiling": ceiling,
            "environment": "prod",
            "backend": "game",
            "resource": "*",
        },
    )


async def ack_chain(store, frame, *, output=None, last="effective"):
    states = ["received", "validated", "applied", "effective"]
    if last == "rejected":
        states = ["received", "rejected"]
    for state in states:
        body = ack_body(frame, state)
        if state == last and output is not None:
            body["output"] = output
        acked = await request(store, "POST", "/v2/agents/game/acks", body, "game-agent")
        assert acked.status_code == 200, (state, acked.text)


async def test_maintenance_kinds_and_ack_output_round_trip(store):
    base = {
        "environment": "prod",
        "backend": "game",
        "consumerId": "game",
        "generation": str(store["generation"]),
        "target": "*",
    }
    status = base | {"idempotencyKey": "mnt-status", "op": "status"}
    assert (
        await request(
            store, "POST", "/v2/actions/moderation.maintenance", status, "moderator"
        )
    ).status_code == 403
    for body, code in (
        (base | {"idempotencyKey": "mnt-bad", "op": "pause"}, 422),
        (base | {"idempotencyKey": "mnt-noreason", "op": "interrupt"}, 422),
        (base | {"idempotencyKey": "mnt-arena", "op": "drain", "target": "arena"}, 422),
    ):
        response = await request(
            store, "POST", "/v2/actions/moderation.maintenance", body, "admin"
        )
        assert response.status_code == code, response.text
    accepted = await request(
        store, "POST", "/v2/actions/moderation.maintenance", status, "admin"
    )
    assert accepted.status_code == 202, accepted.text
    interrupt = base | {
        "idempotencyKey": "mnt-int",
        "op": "interrupt",
        "reason": "hotfix",
    }
    assert (
        await request(
            store, "POST", "/v2/actions/moderation.maintenance", interrupt, "admin"
        )
    ).status_code == 202
    frames = await envelopes(store)
    assert [f["payload"] for f in frames] == [
        {"kind": "moderation.maintenance", "target": "*", "op": "status"},
        {
            "kind": "moderation.maintenance",
            "target": "*",
            "op": "interrupt",
            "reason": "hotfix",
        },
    ]
    line = "draining=false rooms=2 drained=false"
    for state in ("received", "validated", "applied"):
        acked = await request(
            store,
            "POST",
            "/v2/agents/game/acks",
            ack_body(frames[0], state),
            "game-agent",
        )
        assert acked.status_code == 200, (state, acked.text)
    effective = ack_body(frames[0], "effective") | {"output": line}
    for body in (effective, {k: v for k, v in effective.items() if k != "output"}):
        # The same receipt resent without its text still matches.
        acked = await request(store, "POST", "/v2/agents/game/acks", body, "game-agent")
        assert acked.status_code == 200, acked.text
    read = await request(
        store, "GET", f"/v2/operations/{accepted.json()['operationId']}", role="admin"
    )
    assert read.json()["status"] == "effective"
    assert read.json()["receipts"][-1]["result"] == {"code": "ok", "output": line}
    oversized = ack_body(frames[1], "received") | {"output": "x" * 16385}
    assert (
        await request(store, "POST", "/v2/agents/game/acks", oversized, "game-agent")
    ).status_code == 422


async def test_console_run_scopes_allowlist_and_audit(store):
    assert core.CONSOLE_READ_ONLY.fullmatch("spark health --memory")
    for unsafe in (
        "op Steve",
        "list; stop",
        "listx",
        "spark profiler start",
        "stop",
        "spark tickmonitor --stop",
        "spark health --upload",
    ):
        assert not core.CONSOLE_READ_ONLY.fullmatch(unsafe), unsafe
    # Admins hold only console.read; moderators no console scope at all.
    assert (
        await request(
            store,
            "POST",
            "/v2/actions/console.run",
            console_body(store, "c0", "op Steve"),
        )
    ).status_code == 403
    assert (
        await request(
            store,
            "POST",
            "/v2/actions/console.run",
            console_body(store, "c0m", "list"),
            "moderator",
        )
    ).status_code == 403
    # Console lines are server-wide: no target field, so no scoped target.
    scoped = await request(
        store,
        "POST",
        "/v2/actions/console.run",
        console_body(store, "c-arena", "list", target="arena"),
        "owner",
    )
    assert scoped.status_code == 422, scoped.text
    for command in ("say hi\nstop", "   ", "/"):
        response = await request(
            store,
            "POST",
            "/v2/actions/console.run",
            console_body(store, f"c-bad-{len(command)}", command),
            "owner",
        )
        assert response.status_code == 422, (command, response.text)
    read = await request(
        store,
        "POST",
        "/v2/actions/console.run",
        console_body(store, "c1", "/list"),
        "owner",
    )
    run = await request(
        store,
        "POST",
        "/v2/actions/console.run",
        console_body(store, "c2", "op Steve"),
        "owner",
    )
    assert read.status_code == run.status_code == 202, (read.text, run.text)
    frames = await envelopes(store)
    assert [f["payload"] for f in frames] == [
        {"kind": "console.run", "target": "*", "command": "list", "readOnly": True},
        {
            "kind": "console.run",
            "target": "*",
            "command": "op Steve",
            "readOnly": False,
        },
    ]
    assert all(f["executable"] for f in frames)
    audited = await sql(
        store,
        "SELECT required_scope, result FROM operations WHERE kind='console.run' ORDER BY created_at",
    )
    assert [(a["required_scope"], a["result"]["command"]) for a in audited] == [
        ("console.read", "list"),
        ("console.run", "op Steve"),
    ]
    trail = await sql(
        store,
        "SELECT detail FROM audit_events WHERE action='console.run' AND outcome='accepted' AND detail ? 'command'",
    )
    assert {row["detail"]["command"] for row in trail} == {"list", "op Steve"}
    # Receipts are contiguous: the first frame settles before the second.
    await ack_chain(
        store, frames[0], output="There are 0 of a max of 40 players online:"
    )
    await ack_chain(store, frames[1], output="Made Steve a server operator")
    result = await request(
        store, "GET", f"/v2/operations/{run.json()['operationId']}", role="owner"
    )
    assert result.json()["receipts"][-1]["result"]["output"] == (
        "Made Steve a server operator"
    )


async def test_console_service_tokens_read_only_and_owner_assertion(store):
    await service_token(store, "agent-read", ["console.read"])
    tick = await request(
        store,
        "POST",
        "/v2/actions/console.run",
        console_body(store, "a1", "tick query"),
        "agent-read",
    )
    assert tick.status_code == 202, tick.text
    denied = await request(
        store,
        "POST",
        "/v2/actions/console.run",
        console_body(store, "a2", "stop"),
        "agent-read",
    )
    assert denied.status_code == 403, denied.text
    # The issuing credential reads its own operation without operations.read.
    own = await request(
        store, "GET", f"/v2/operations/{tick.json()['operationId']}", role="agent-read"
    )
    assert own.status_code == 200, own.text
    await service_token(store, "agent-run", ["console.read", "console.run"], via="mcp")
    stop = await request(
        store,
        "POST",
        "/v2/actions/console.run",
        console_body(store, "a3", "save-all"),
        "agent-run",
    )
    assert stop.status_code == 202, stop.text
    # Site console principal: asserts the logged-in user, who must be an owner.
    await service_token(store, "site-console", ["console.read", "console.run"])
    as_admin = await request(
        store,
        "POST",
        "/v2/actions/console.run",
        console_body(
            store, "s1", "save-all", actorAccountId=str(store["accounts"]["admin"])
        ),
        "site-console",
    )
    assert as_admin.status_code == 403, as_admin.text
    admin_tick = await request(
        store,
        "POST",
        "/v2/actions/console.run",
        console_body(
            store, "s1t", "tick query", actorAccountId=str(store["accounts"]["admin"])
        ),
        "site-console",
    )
    assert admin_tick.status_code == 202, admin_tick.text
    as_owner = await request(
        store,
        "POST",
        "/v2/actions/console.run",
        console_body(
            store, "s2", "save-all", actorAccountId=str(store["accounts"]["owner"])
        ),
        "site-console",
    )
    assert as_owner.status_code == 202, as_owner.text
    frames = await envelopes(store)
    # Service-issued and owner-asserted lines both survive the delivery recheck.
    assert [(f["payload"]["command"], f["executable"]) for f in frames] == [
        ("tick query", True),
        ("save-all", True),
        ("tick query", True),
        ("save-all", True),
    ]
    await ack_chain(store, frames[0], output="The game is running normally")
    polled = await request(
        store, "GET", f"/v2/operations/{tick.json()['operationId']}", role="agent-read"
    )
    assert polled.json()["status"] == "effective"
    assert polled.json()["receipts"][-1]["result"]["output"].startswith("The game")
    # A narrowed issuer loses the exception (no operations.read to fall back on).
    issued_by = (
        await sql(
            store,
            "SELECT credential_id FROM operations WHERE id=%s",
            (tick.json()["operationId"],),
        )
    )[0]["credential_id"]
    await sql(
        store, "UPDATE credentials SET resource='arena' WHERE id=%s", (issued_by,)
    )
    assert (
        await request(
            store,
            "GET",
            f"/v2/operations/{tick.json()['operationId']}",
            role="agent-read",
        )
    ).status_code == 403
    # Another service credential cannot read it.
    assert (
        await request(
            store,
            "GET",
            f"/v2/operations/{tick.json()['operationId']}",
            role="agent-run",
        )
    ).status_code == 403


async def test_announce_is_service_only_without_actor(store):
    await service_token(store, "deploy", ["moderation.announce"])
    body = {
        "idempotencyKey": "announce-1",
        "environment": "prod",
        "backend": "game",
        "consumerId": "game",
        "generation": str(store["generation"]),
        "target": "*",
    }
    assert (
        await request(store, "POST", "/v2/actions/moderation.announce", body, "admin")
    ).status_code == 403
    asserted = await request(
        store,
        "POST",
        "/v2/actions/moderation.announce",
        body | {"actorAccountId": str(store["accounts"]["admin"])},
        "deploy",
    )
    assert asserted.json()["error"] == "actor_forbidden", asserted.text
    accepted = await request(
        store, "POST", "/v2/actions/moderation.announce", body, "deploy"
    )
    assert accepted.status_code == 202, accepted.text
    [frame] = await envelopes(store)
    assert frame["executable"]
    assert frame["payload"] == {"kind": "moderation.announce", "target": "*"}


async def test_console_migration_extends_game_consumers_only(store):
    generation = str(store["generation"])
    for cid, caps in (
        ("legacy-game", ["settings.gameplay", "moderation.say", "moderation.kick"]),
        ("legacy-proxy", ["settings.gate"]),
    ):
        await provision(
            store["admin"],
            {
                "client": {
                    "id": cid,
                    "via": "game",
                    "ceiling": ["agents.acks", "agents.events"],
                },
                "ceiling": ["agents.acks", "agents.events"],
                "environment": "prod",
                "backend": "game",
                "resource": "*",
                "consumer": {"id": cid, "generation": generation, "capabilities": caps},
            },
        )
    migration = (
        Path(__file__).resolve().parents[1] / "migrations/010_console_capabilities.sql"
    ).read_text()
    # The helper connection already sets search_path; one statement per call.
    migration = "\n".join(
        line
        for line in migration.splitlines()
        if not line.startswith("SET search_path")
    )
    for _ in range(2):  # idempotent: no duplicate capabilities
        await sql(store, migration)
    rows_ = {
        r["id"]: r["capabilities"]
        for r in await sql(
            store,
            "SELECT id, capabilities FROM consumers WHERE id LIKE 'legacy-%%'",
        )
    }
    assert rows_["legacy-proxy"] == ["settings.gate"]
    assert rows_["legacy-game"] == [
        "settings.gameplay",
        "moderation.say",
        "moderation.kick",
        "moderation.maintenance",
        "moderation.announce",
        "console.run",
    ]


async def test_service_moderation_asserts_actor_and_executes(store):
    # Site moderation principal: service credential with a moderation.*
    # ceiling; every call asserts the logged-in site user, and that actor's
    # own grants decide exactly like a direct call.
    token = await provision(
        store["admin"],
        {
            "client": {
                "id": "modsite",
                "via": "game",
                "ceiling": ["agents.events", "moderation.kick", "moderation.say"],
            },
            "ceiling": ["agents.events", "moderation.kick", "moderation.say"],
            "environment": "prod",
            "backend": "game",
            "resource": "*",
            "consumer": {
                "id": "modsite",
                "generation": str(store["generation"]),
                "capabilities": ["moderation.kick", "moderation.say"],
            },
        },
    )
    store["tokens"]["modsite-agent"] = token
    moderator = store["accounts"]["moderator"]
    kick = {
        "idempotencyKey": "modsite-kick",
        "environment": "prod",
        "backend": "game",
        "consumerId": "modsite",
        "generation": str(store["generation"]),
        "target": "arena",
        "playerId": str(uuid4()),
        "actorAccountId": str(moderator),
    }
    response = await request(
        store, "POST", "/v2/actions/moderation.kick", kick, "modsite-agent"
    )
    assert response.status_code == 202, response.text
    operation = response.json()["operationId"]
    attributed = await sql(
        store,
        "SELECT account_id, client_id FROM operations WHERE id=%s",
        (operation,),
    )
    assert attributed == [{"account_id": moderator, "client_id": "modsite"}]
    frames = await envelopes(store, cid="modsite")
    frame = next(item for item in frames if item["operationId"] == operation)
    assert frame["executable"] and frame["payload"]["kind"] == "moderation.kick"
    # The ModerationAction model carries the same assertion.
    say = {
        "idempotencyKey": "modsite-say",
        "environment": "prod",
        "backend": "game",
        "consumerId": "modsite",
        "generation": str(store["generation"]),
        "target": "arena",
        "text": "Hello players",
        "actorAccountId": str(moderator),
    }
    response = await request(
        store, "POST", "/v2/actions/moderation.say", say, "modsite-agent"
    )
    assert response.status_code == 202, response.text


async def test_service_moderation_refusals_and_direct_actor_forbidden(store):
    store["tokens"]["modsite"] = await provision(
        store["admin"],
        {
            "client": {
                "id": "modsite",
                "via": "game",
                "ceiling": ["moderation.kick", "moderation.pardon"],
            },
            "ceiling": ["moderation.kick", "moderation.pardon"],
            "environment": "prod",
            "backend": "game",
            "resource": "*",
            "consumer": {
                "id": "modsite",
                "generation": str(store["generation"]),
                "capabilities": ["moderation.kick", "moderation.pardon"],
            },
        },
    )
    moderator = store["accounts"]["moderator"]
    ordinary = store["accounts"]["ordinary"]

    def kick(key, actor=None):
        body = {
            "idempotencyKey": key,
            "environment": "prod",
            "backend": "game",
            "consumerId": "modsite",
            "generation": str(store["generation"]),
            "target": "arena",
            "playerId": str(uuid4()),
        }
        if actor is not None:
            body["actorAccountId"] = str(actor)
        return body

    denied = await request(
        store, "POST", "/v2/actions/moderation.kick", kick("no-actor"), "modsite"
    )
    assert denied.status_code == 403
    assert denied.json()["error"] == "service_actor_required", denied.text
    unknown = await request(
        store,
        "POST",
        "/v2/actions/moderation.kick",
        kick("unknown-actor", uuid4()),
        "modsite",
    )
    assert unknown.status_code == 404
    assert unknown.json()["error"] == "account_not_found", unknown.text
    # The asserted actor holds no moderation grant.
    unscoped = await request(
        store,
        "POST",
        "/v2/actions/moderation.kick",
        kick("unscoped-actor", ordinary),
        "modsite",
    )
    assert unscoped.status_code == 403, unscoped.text
    # Admin-only kind under a moderator actor: the actor's grants decide.
    pardon = {
        "idempotencyKey": "pardon-peer",
        "environment": "prod",
        "backend": "game",
        "consumerId": "modsite",
        "generation": str(store["generation"]),
        "target": "arena",
        "player": "Steve_01",
        "actorAccountId": str(moderator),
    }
    refused = await request(
        store, "POST", "/v2/actions/moderation.pardon", pardon, "modsite"
    )
    assert refused.status_code == 403, refused.text
    # An admin actor reaches the admin-only kind through the same assertion.
    pardon["idempotencyKey"] = "pardon-admin"
    pardon["actorAccountId"] = str(store["accounts"]["admin"])
    assert (
        await request(store, "POST", "/v2/actions/moderation.pardon", pardon, "modsite")
    ).status_code == 202
    # Direct callers are authenticated and must never send an actor.
    forged = await request(
        store,
        "POST",
        "/v2/actions/moderation.kick",
        kick("direct-actor", moderator),
        "moderator",
    )
    assert forged.status_code == 403
    assert forged.json()["error"] == "actor_forbidden", forged.text
    # A scoped consumer could act as any covered moderator, so only the
    # unbound site principal may assert an actor.
    store["tokens"]["modscoped"] = await provision(
        store["admin"],
        {
            "client": {
                "id": "modscoped",
                "via": "game",
                "ceiling": ["moderation.kick"],
            },
            "ceiling": ["moderation.kick"],
            "environment": "prod",
            "backend": "game",
            "resource": "arena",
            "consumer": {
                "id": "modscoped",
                "generation": str(store["generation"]),
                "capabilities": ["moderation.kick"],
            },
        },
    )
    scoped = kick("scoped-actor", moderator) | {"consumerId": "modscoped"}
    bound = await request(
        store, "POST", "/v2/actions/moderation.kick", scoped, "modscoped"
    )
    assert bound.status_code == 403
    assert bound.json()["error"] == "actor_forbidden", bound.text


async def test_service_settings_actor_grant_decides_and_scoped_refused(store):
    # Site settings travel like staff/moderation: the unbound site principal
    # asserts the acting admin, and the actor's own grants decide.
    store["tokens"]["sitesettings"] = await provision(
        store["admin"],
        {
            "client": {
                "id": "sitesettings",
                "via": "game",
                "ceiling": ["settings.read", "settings.gameplay.write"],
            },
            "ceiling": ["settings.read", "settings.gameplay.write"],
            "environment": "prod",
            "backend": "game",
            "resource": "*",
        },
    )

    def change(key, revision=0, actor=None, value=None):
        body = {
            "idempotencyKey": key,
            "environment": "prod",
            "backend": "game",
            "expectedRevision": revision,
            "patch": value or {"lobby": {"pvpEnabled": True}},
        }
        if actor is not None:
            body["actorAccountId"] = str(actor)
        return body

    denied = await request(
        store, "PATCH", "/v2/settings/gameplay/*", change("no-actor"), "sitesettings"
    )
    assert denied.status_code == 403
    assert denied.json()["error"] == "service_actor_required", denied.text
    unknown = await request(
        store,
        "PATCH",
        "/v2/settings/gameplay/*",
        change("unknown-actor", actor=uuid4()),
        "sitesettings",
    )
    assert unknown.status_code == 404
    assert unknown.json()["error"] == "account_not_found", unknown.text
    # The asserted actor holds no gameplay-write grant.
    ordinary = store["accounts"]["ordinary"]
    unscoped = await request(
        store,
        "PATCH",
        "/v2/settings/gameplay/*",
        change("unscoped-actor", actor=ordinary),
        "sitesettings",
    )
    assert unscoped.status_code == 403, unscoped.text
    # A moderator actor reads settings but cannot write gameplay: the actor's
    # grants decide, not the service ceiling.
    moderator = store["accounts"]["moderator"]
    peer = await request(
        store,
        "PATCH",
        "/v2/settings/gameplay/*",
        change("moderator-actor", actor=moderator),
        "sitesettings",
    )
    assert peer.status_code == 403, peer.text
    # An admin actor reaches the write through the same assertion.
    admin = store["accounts"]["admin"]
    accepted = await request(
        store,
        "PATCH",
        "/v2/settings/gameplay/*",
        change("admin-actor", actor=admin),
        "sitesettings",
    )
    assert accepted.status_code == 202, accepted.text
    operation = accepted.json()["operationId"]
    attributed = await sql(
        store,
        "SELECT account_id FROM operations WHERE id=%s",
        (operation,),
    )
    assert attributed == [{"account_id": admin}]
    revised = await sql(
        store,
        "SELECT actor, revision FROM settings_revisions WHERE namespace=%s AND revision=1",
        ("gameplay",),
    )
    assert revised == [{"actor": admin, "revision": 1}]
    # Reads ride the same token without an actor: no attribution needed.
    view = await request(store, "GET", "/v2/settings/gameplay/*", None, "sitesettings")
    assert view.status_code == 200, view.text
    assert view.json()["revision"] == 1
    # Direct callers are authenticated and must never send an actor.
    forged = await request(
        store,
        "PATCH",
        "/v2/settings/gameplay/*",
        change("direct-actor", revision=1, actor=admin),
        "admin",
    )
    assert forged.status_code == 403
    assert forged.json()["error"] == "actor_forbidden", forged.text
    # Only the unbound site principal may assert an actor: narrowing the
    # credential resource fences even a covered target (faithful admins keep
    # working through the unbound credential above).
    await sql(
        store,
        "UPDATE credentials SET resource='arena' WHERE verifier=%s",
        (hashlib.sha256(store["tokens"]["sitesettings"].encode()).hexdigest(),),
    )
    bound = await request(
        store,
        "PATCH",
        "/v2/settings/gameplay/arena",
        change("scoped-actor", actor=admin),
        "sitesettings",
    )
    assert bound.status_code == 403
    assert bound.json()["error"] == "actor_forbidden", bound.text


async def test_site_settings_scopes_only_on_unbound_site_credential(store):
    # A resource-bound consumer credential holding settings scopes could
    # assert any covered admin as the acting account, so provision refuses.
    with pytest.raises(ValueError, match="unbound site credential"):
        await provision(
            store["admin"],
            {
                "client": {
                    "id": "arena-settings",
                    "via": "game",
                    "ceiling": ["settings.gameplay.write"],
                },
                "ceiling": ["settings.gameplay.write"],
                "environment": "prod",
                "backend": "game",
                "resource": "arena",
            },
        )


async def test_workshop_gate_scope_is_patch_only_for_service(store):
    store["tokens"]["reporter"] = await provision(
        store["admin"],
        {
            "client": {
                "id": "reporter",
                "via": "game",
                "ceiling": ["workshop.gate"],
            },
            "ceiling": ["workshop.gate"],
            "environment": "prod",
            "backend": "game",
            "resource": "*",
        },
    )
    leg = patch("reporter-leg-1", 0, {"state": "builders"})
    assert (
        await request(store, "PATCH", "/v2/settings/gate/workshop", leg, "reporter")
    ).status_code == 202
    rollback = {
        "idempotencyKey": "reporter-rollback",
        "environment": "prod",
        "backend": "game",
        "expectedRevision": 1,
        "revision": 1,
    }
    refused = await request(
        store, "POST", "/v2/settings/gate/workshop/rollback", rollback, "reporter"
    )
    assert refused.status_code == 403
    assert refused.json()["error"] == "forbidden", refused.text
    preview = await request(
        store, "POST", "/v2/settings/gate/workshop/validate", leg, "reporter"
    )
    assert preview.status_code == 403
    assert preview.json()["error"] == "forbidden", preview.text


async def test_provision_ttl_cap_is_30d_for_service_24h_for_human(store):
    service = {
        "client": {"id": "ttl-service", "via": "game", "ceiling": ["gate:read"]},
        "ceiling": ["gate:read"],
        "environment": "prod",
        "backend": "game",
        "resource": "*",
    }
    await provision(store["admin"], {**service, "expiresInSeconds": 30 * 86400})
    with pytest.raises(ValueError, match="invalid credential lifetime"):
        await provision(store["admin"], {**service, "expiresInSeconds": 30 * 86400 + 1})
    human = {
        "accountId": str(uuid4()),
        "displayName": "ttl-human",
        "client": {
            "id": "ttl-human",
            "via": "cli",
            "human": True,
            "ceiling": ["settings.read"],
        },
        "ceiling": ["settings.read"],
        "environment": "prod",
        "backend": "game",
        "resource": "*",
    }
    await provision(store["admin"], {**human, "expiresInSeconds": 86400})
    with pytest.raises(ValueError, match="invalid credential lifetime"):
        await provision(store["admin"], {**human, "expiresInSeconds": 86401})


async def test_admin_cli_provision_receipt_and_revoke(
    store, tmp_path, monkeypatch, capsys
):
    db_file = tmp_path / "dsn"
    db_file.write_text(store["admin"])
    db_file.chmod(0o600)
    spec = {
        "client": {"id": "cli-site", "via": "game", "ceiling": ["gate:read"]},
        "ceiling": ["gate:read"],
        "environment": "prod",
        "backend": "game",
        "resource": "*",
    }
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(spec))
    spec_file.chmod(0o600)
    token_file = tmp_path / "bearer"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cpv2.admin",
            "--database-file",
            str(db_file),
            "provision",
            "--spec-file",
            str(spec_file),
            "--token-file",
            str(token_file),
        ],
    )
    await admin_main()
    out, _ = capsys.readouterr()
    receipt = json.loads(out.strip())
    assert set(receipt) == {"credentialId", "fingerprint"}
    token = token_file.read_text().strip()
    assert receipt["fingerprint"] == verifier(token)[:16]
    assert token not in out
    credential_id = UUID(receipt["credentialId"])
    # Revoke is offline, audited and idempotent; unknown ids are refused.
    with pytest.raises(ValueError, match="unknown credential"):
        await revoke_credential(store["admin"], uuid4())
    assert await revoke_credential(store["admin"], credential_id) == credential_id
    assert await revoke_credential(store["admin"], credential_id) == credential_id
    audits = await sql(
        store,
        "SELECT outcome, detail FROM audit_events WHERE action=%s ORDER BY sequence",
        ("credentials.revoke",),
    )
    assert [row["outcome"] for row in audits] == ["accepted", "accepted"]
    assert [row["detail"]["alreadyRevoked"] for row in audits] == [False, True]
    assert (
        await request(
            store,
            "GET",
            "/v2/me",
            None,
            "admin",
            {"Authorization": f"Bearer {token}"},
        )
    ).status_code == 401


async def test_c7_consumer_credential_rotates_without_gap(store):
    generation = str(uuid4())

    def rot_spec():
        return {
            "client": {
                "id": "rot",
                "via": "game",
                "ceiling": ["agents.acks", "agents.events"],
            },
            "ceiling": ["agents.acks", "agents.events"],
            "environment": "prod",
            "backend": "game",
            "resource": "*",
            "consumer": {
                "id": "rot",
                "generation": generation,
                "capabilities": ["settings.gameplay", "settings.gate"],
            },
        }

    old_token = await provision(store["admin"], rot_spec())
    store["tokens"]["rot-agent"] = old_token
    old_id = (await sql(store, "SELECT id FROM credentials WHERE client_id='rot'"))[0][
        "id"
    ]
    before = (
        await sql(
            store,
            "SELECT epoch, generation, credential_id FROM consumers WHERE id='rot'",
        )
    )[0]
    # A frame queued before the rotation must survive the rebind.
    accepted = await request(
        store, "PATCH", "/v2/settings/gameplay/*", patch("global", 0)
    )
    assert accepted.status_code == 202, accepted.text

    new_token = await provision(store["admin"], rot_spec())
    row = (
        await sql(
            store,
            "SELECT epoch, generation, credential_id, previous_credential_id"
            " FROM consumers WHERE id='rot'",
        )
    )[0]
    assert row["epoch"] == before["epoch"]
    assert row["generation"] == before["generation"]
    assert row["credential_id"] != before["credential_id"]
    assert row["previous_credential_id"] == before["credential_id"]

    async def batch_as(token):
        async with store["app"].state.db.transaction() as conn:
            return await delivery.batch(
                conn, await authenticate(conn, token), "rot", row["epoch"], 0
            )

    # Overlap: both tokens pull delivery until the old one is revoked.
    assert len(await batch_as(old_token)) == 1
    assert len(await batch_as(new_token)) == 1

    # A different generation is a different consumer: refused, not rebound.
    bad = rot_spec()
    bad["consumer"] = {**bad["consumer"], "generation": str(uuid4())}
    with pytest.raises(ValueError, match="mismatch"):
        await provision(store["admin"], bad)

    assert await revoke_credential(store["admin"], old_id) == old_id
    assert (
        await request(
            store,
            "GET",
            "/v2/agents/rot/snapshot",
            None,
            "admin",
            {"Authorization": f"Bearer {old_token}"},
        )
    ).status_code == 401
    # The redeployed consumer keeps pulling and ACKing on the new credential.
    store["tokens"]["rot-agent"] = new_token
    snapshot = await request(store, "GET", "/v2/agents/rot/snapshot", None, "rot-agent")
    assert snapshot.status_code == 200, snapshot.text
    frames = await envelopes(store, cid="rot")
    assert len(frames) == 1
    ack = await request(
        store, "POST", "/v2/agents/rot/acks", ack_body(frames[0]), "rot-agent"
    )
    assert ack.status_code == 200, ack.text


async def test_c7_rebind_refuses_capability_or_client_change(store):
    generation = str(uuid4())

    def rot_spec(**over):
        spec = {
            "client": {
                "id": "rot2",
                "via": "game",
                "ceiling": ["agents.acks", "agents.events"],
            },
            "ceiling": ["agents.acks", "agents.events"],
            "environment": "prod",
            "backend": "game",
            "resource": "*",
            "consumer": {
                "id": "rot2",
                "generation": generation,
                "capabilities": ["settings.gameplay", "settings.gate"],
            },
        }
        spec.update(over)
        return spec

    await provision(store["admin"], rot_spec())
    first = (await sql(store, "SELECT credential_id FROM consumers WHERE id='rot2'"))[
        0
    ]["credential_id"]
    # Narrowed capabilities are a different consumer: refused, not rebound.
    bad = rot_spec()
    bad["consumer"] = {**bad["consumer"], "capabilities": ["settings.gameplay"]}
    with pytest.raises(ValueError, match="mismatch"):
        await provision(store["admin"], bad)
    # Another client's credential must not steal the consumer id.
    stolen = rot_spec()
    stolen["client"] = {**stolen["client"], "id": "rot2-attacker"}
    with pytest.raises(ValueError, match="client mismatch"):
        await provision(store["admin"], stolen)
    row = (await sql(store, "SELECT credential_id FROM consumers WHERE id='rot2'"))[0]
    assert row["credential_id"] == first
    # A migration appended console kinds after the spec was written: the old
    # spec still rotates, and the stored set keeps the migrated kinds.
    await sql(
        store,
        "UPDATE consumers SET capabilities=array_append(capabilities,'console.suggest') WHERE id='rot2'",
    )
    await provision(store["admin"], rot_spec())
    row = (
        await sql(
            store, "SELECT credential_id,capabilities FROM consumers WHERE id='rot2'"
        )
    )[0]
    assert row["credential_id"] != first
    assert "console.suggest" in row["capabilities"]


async def test_c7_second_rotation_refused_while_previous_valid(store):
    generation = str(uuid4())

    def rot_spec():
        return {
            "client": {
                "id": "rot3",
                "via": "game",
                "ceiling": ["agents.acks", "agents.events"],
            },
            "ceiling": ["agents.acks", "agents.events"],
            "environment": "prod",
            "backend": "game",
            "resource": "*",
            "consumer": {
                "id": "rot3",
                "generation": generation,
                "capabilities": ["settings.gameplay", "settings.gate"],
            },
        }

    await provision(store["admin"], rot_spec())
    c1 = (await sql(store, "SELECT credential_id FROM consumers WHERE id='rot3'"))[0][
        "credential_id"
    ]
    await provision(store["admin"], rot_spec())
    # Rotating again before revoking C1 must not silently drop it.
    with pytest.raises(ValueError, match="still valid"):
        await provision(store["admin"], rot_spec())
    assert await revoke_credential(store["admin"], c1) == c1
    await provision(store["admin"], rot_spec())
    row = (
        await sql(
            store,
            "SELECT credential_id, previous_credential_id"
            " FROM consumers WHERE id='rot3'",
        )
    )[0]
    assert row["previous_credential_id"] != c1


async def test_renew_crash_before_confirm_replays_and_confirm_revokes_old(store):
    generation = str(uuid4())
    spec = {
        "client": {
            "id": "ren",
            "via": "game",
            "ceiling": ["agents.acks", "agents.events"],
        },
        "ceiling": ["agents.acks", "agents.events"],
        "environment": "prod",
        "backend": "game",
        "resource": "*",
        "expiresInSeconds": 600,
        "consumer": {
            "id": "ren",
            "generation": generation,
            "capabilities": ["settings.gameplay", "settings.gate"],
        },
    }
    old = await provision(store["admin"], spec)
    auth = lambda t: {"Authorization": f"Bearer {t}"}  # noqa: E731
    client = store["client"]
    me = (await client.get("/v2/me", headers=auth(old))).json()
    lifetime = datetime.fromisoformat(me["expiresAt"]) - datetime.fromisoformat(
        me["issuedAt"]
    )
    assert abs(lifetime - timedelta(seconds=600)) < timedelta(seconds=5)

    first = await client.post("/v2/credentials/renew", headers=auth(old))
    assert first.status_code == 201, first.text
    new = first.json()["token"]
    assert new != old
    # Crash before confirm: the old token still works and a retry returns the
    # same pending successor instead of minting a second one.
    assert (await client.get("/v2/me", headers=auth(old))).status_code == 200
    again = await client.post("/v2/credentials/renew", headers=auth(old))
    assert again.status_code == 201, again.text
    assert again.json() == first.json()
    assert len(await sql(store, "SELECT 1 FROM credentials WHERE client_id='ren'")) == 2
    # Same client, scopes, lifetime and consumer binding.
    me_new = (await client.get("/v2/me", headers=auth(new))).json()
    assert me_new["client"] == "ren" and me_new["ceiling"] == me["ceiling"]
    assert (
        datetime.fromisoformat(me_new["expiresAt"])
        - datetime.fromisoformat(me_new["issuedAt"])
        == lifetime
    )
    row = (await sql(store, "SELECT * FROM consumers WHERE id='ren'"))[0]
    assert str(row["credential_id"]) == me_new["credentialId"]
    assert str(row["previous_credential_id"]) == me["credentialId"]
    # The successor may not renew while the earlier renewal is unconfirmed.
    refused = await client.post("/v2/credentials/renew", headers=auth(new))
    assert (
        refused.status_code == 409 and refused.json()["error"] == "renewal_unconfirmed"
    )
    # Only the successor confirms.
    assert (
        await client.post("/v2/credentials/renew/confirm", headers=auth(old))
    ).status_code == 404
    done = await client.post("/v2/credentials/renew/confirm", headers=auth(new))
    assert done.status_code == 200, done.text
    assert (await client.get("/v2/me", headers=auth(old))).status_code == 401
    assert (
        await client.get("/v2/agents/ren/snapshot", headers=auth(new))
    ).status_code == 200
    # Confirm is idempotent; the next cycle renews from the successor.
    assert (
        await client.post("/v2/credentials/renew/confirm", headers=auth(new))
    ).status_code == 200
    nxt = await client.post("/v2/credentials/renew", headers=auth(new))
    assert nxt.status_code == 201
    # The intermediate credential no longer confirms its own (already confirmed) row.
    assert (
        await client.post("/v2/credentials/renew/confirm", headers=auth(new))
    ).status_code == 404
    actions = [
        r["action"]
        for r in await sql(
            store,
            "SELECT action FROM audit_events WHERE client_id='ren' AND outcome IN ('accepted','replayed') ORDER BY sequence",
        )
    ]
    assert actions == [
        "credentials.renew",
        "credentials.renew",
        "credentials.renew.confirm",
        "credentials.renew",
    ]


async def test_renew_grace_expires_old_and_refuses_humans_and_floods(store):
    spec = {
        "client": {"id": "ren2", "via": "game", "ceiling": ["gate:read"]},
        "ceiling": ["gate:read"],
        "environment": "prod",
        "backend": "game",
        "resource": "*",
        "expiresInSeconds": 30 * 86400,
    }
    old = await provision(store["admin"], spec)
    client = store["client"]
    renewed = await client.post(
        "/v2/credentials/renew", headers={"Authorization": f"Bearer {old}"}
    )
    assert renewed.status_code == 201, renewed.text
    left = (
        await sql(
            store,
            "SELECT expires_at - now() AS left FROM credentials WHERE client_id='ren2' ORDER BY created_at LIMIT 1",
        )
    )[0]["left"]
    # Unconfirmed, the old credential lives at most the grace hour.
    assert left <= timedelta(hours=1)
    human = await request(store, "POST", "/v2/credentials/renew", None, "admin")
    assert human.status_code == 403 and human.json()["error"] == "renew_service_only"
    codes = [
        (
            await client.post(
                "/v2/credentials/renew", headers={"Authorization": f"Bearer {old}"}
            )
        ).status_code
        for _ in range(8)
    ]
    assert 429 in codes


def test_suggest_waiters_do_not_consume_stream_slots():
    # No database: the waiter namespaces are in-memory. With both agent
    # stream slots taken, completions still get their own namespace.
    wakeups = delivery.Wakeups("dbname=unused")
    first, second = wakeups.subscribe("game"), wakeups.subscribe("game")
    with pytest.raises(Problem):
        wakeups.subscribe("game")
    suggest = wakeups.subscribe_suggest("game")
    wakeups.unsubscribe_suggest("game", suggest)
    assert not wakeups.suggest_waiters
    wakeups.unsubscribe("game", first)
    wakeups.unsubscribe("game", second)
    assert not wakeups.waiters


async def test_notify_wakeup_and_durable_recovery_without_listener(store):
    wakeups = store["app"].state.wakeups
    waiter = wakeups.subscribe("game")
    try:
        await queued(store)
        await asyncio.wait_for(waiter.wait(), 2)
    finally:
        wakeups.unsubscribe("game", waiter)
    await wakeups.close()
    await queued(store, "lost-notify")
    assert len(await envelopes(store)) == 2
    await wakeups.start()
    assert len(await envelopes(store)) == 2
    snapshot = await request(
        store, "GET", "/v2/agents/game/snapshot", role="game-agent"
    )
    assert snapshot.status_code == 200 and snapshot.json()["cursor"] == 0
    assert (
        await request(store, "GET", "/v2/agents/workshop/snapshot", role="game-agent")
    ).status_code == 403


async def test_revocation_expiry_generation_and_superseded_config_do_not_execute(store):
    await queued(store)
    await sql(
        store,
        "UPDATE accounts SET authorization_epoch=authorization_epoch+1 WHERE id=%s",
        (store["accounts"]["moderator"],),
    )
    value = (await envelopes(store))[0]
    assert value["executable"] is False and value["payload"] is None
    # Post-policy received/validated are recorded as historical facts; the
    # frame above stays non-executable, which is the actual safety property.
    assert (
        await request(
            store, "POST", "/v2/agents/game/acks", ack_body(value), "game-agent"
        )
    ).status_code == 200
    assert (
        await request(
            store,
            "POST",
            "/v2/agents/game/acks",
            ack_body(value, "rejected"),
            "game-agent",
        )
    ).status_code == 200
    await queued(store, "expiry", role="admin")
    await sql(
        store,
        "UPDATE operations SET deadline=now()-interval '1 second' WHERE idempotency_key='expiry'",
    )
    assert (await envelopes(store))[1]["reason"] == "expired"
    await request(store, "PATCH", "/v2/settings/gameplay/arena", patch("s1"))
    await request(
        store,
        "PATCH",
        "/v2/settings/gameplay/arena",
        patch("s2", 1, {"match": {"maxPlayers": 64}}),
    )
    settings = (await envelopes(store))[2:]
    assert settings[0]["reason"] == "superseded" and settings[0]["payload"] is None
    assert settings[1]["executable"] is True
    # Historical receipts upload in cursor order: the expired frame first,
    # then the obsolete revision. Batch still fences execution, so nothing
    # here authorizes the old revision.
    assert (
        await request(
            store,
            "POST",
            "/v2/agents/game/acks",
            ack_body((await envelopes(store))[1]),
            "game-agent",
        )
    ).status_code == 200
    assert (
        await request(
            store, "POST", "/v2/agents/game/acks", ack_body(settings[0]), "game-agent"
        )
    ).status_code == 200


async def test_unknown_effect_is_terminal_and_multi_consumer_settings_are_partial(
    store,
):
    op = await queued(store)
    frame = (await envelopes(store))[0]
    body = ack_body(frame, "unknown") | {"result": "effect_uncertain"}
    assert (
        await request(store, "POST", "/v2/agents/game/acks", body, "game-agent")
    ).status_code == 200
    assert (
        await request(
            store, "GET", "/v2/operations/" + op["operationId"], role="moderator"
        )
    ).json()["status"] == "unknown"
    assert (await envelopes(store))[0]["executable"] is False
    setting = await request(store, "PATCH", "/v2/settings/gameplay/arena", patch())
    frames = await envelopes(store)
    for state in delivery.STATES:
        assert (
            await request(
                store,
                "POST",
                "/v2/agents/game/acks",
                ack_body(frames[1], state),
                "game-agent",
            )
        ).status_code == 200
    operation = await request(
        store, "GET", "/v2/operations/" + setting.json()["operationId"]
    )
    assert operation.json()["status"] == "partial"
    workshop = (await envelopes(store, cid="workshop"))[0]
    assert (
        await request(
            store,
            "POST",
            "/v2/agents/workshop/acks",
            ack_body(workshop, "rejected"),
            "workshop-agent",
        )
    ).status_code == 200
    operation = await request(
        store, "GET", "/v2/operations/" + setting.json()["operationId"]
    )
    assert operation.json()["status"] == "partial"


async def test_operation_reads_are_scoped_and_owner_read_is_auditable(store):
    op = await queued(store)
    path = "/v2/operations/" + op["operationId"]
    assert (await request(store, "GET", path, role="builder")).status_code == 403
    assert (await request(store, "GET", path, role="moderator")).status_code == 200
    assert (await request(store, "GET", "/v2/audit", role="builder")).status_code == 403
    response = await request(store, "GET", "/v2/audit", role="owner")
    assert response.status_code == 200
    assert await sql(store, "SELECT * FROM audit_events WHERE action='audit.read'")


async def test_import_preserves_counts_hashes_gate_revision_and_read_only_tokens(
    store, tmp_path
):
    path = tmp_path / "u1.sqlite"
    legacy = _U1(str(path))
    tokens = legacy.bootstrap("legacy-test")
    legacy.set_gate("maintenance", "migration", "forwarded-owner", "owner", 0, "one")
    legacy.db.close()
    manifest = await import_u1(store["admin"], path)
    assert manifest["gate_log"]["count"] == manifest["audit"]["count"] == 1
    assert await import_u1(store["admin"], path) == manifest
    response = await store["client"].get(
        "/v1/gate", headers={"Authorization": "Bearer " + tokens["proxy"]}
    )
    assert response.status_code == 200, response.text
    assert (
        response.json()["revision"] == 1 and response.json()["message"] == "migration"
    )
    assert (
        await store["client"].get(
            "/v2/me", headers={"Authorization": "Bearer " + tokens["site"]}
        )
    ).status_code == 401
    assert (
        await store["client"].post(
            "/v1/gate", json={}, headers={"Authorization": "Bearer " + tokens["site"]}
        )
    ).status_code == 401
    response = await request(
        store,
        "PATCH",
        "/v2/settings/gate/*",
        patch("new-gate", 1, {"mode": "draining"}),
    )
    assert response.status_code == 202 and response.json()["revision"] == 2, (
        response.text
    )
    # Changed sources cannot overwrite an imported domain or reuse the same source manifest.
    source = sqlite3.connect(path)
    source.execute("UPDATE gate_state SET revision=9")
    source.commit()
    source.close()
    with pytest.raises(ValueError, match="unused staging"):
        await import_u1(store["admin"], path)


async def test_uninitialized_service_and_migration_checksums_fail_closed(
    store, postgres
):
    await migrate(store["admin"], conninfo_to_dict(store["admin"])["dbname"])
    await sql(store, "UPDATE schema_migrations SET checksum='tampered'")
    with pytest.raises(RuntimeError, match="checksum"):
        await migrate(store["admin"], conninfo_to_dict(store["admin"])["dbname"])
    # Production startup must refuse powerful credentials even after bootstrap.
    app = create_app(store["admin"])
    with pytest.raises(RuntimeError, match="least-privilege"):
        async with app.router.lifespan_context(app):
            pass


async def test_v1_database_with_original_checksum_migrates_cleanly(postgres):
    # Applied migrations are immutable: an existing v1 database carrying the
    # original 001 checksum must re-migrate without a mismatch.
    name = "cp_" + uuid4().hex
    async with await psycopg.AsyncConnection.connect(postgres, autocommit=True) as conn:
        await conn.execute(f'CREATE DATABASE "{name}"')
    try:
        admin = make_conninfo(postgres, dbname=name)
        await migrate(admin, name)
        original = hashlib.sha256(
            Path("migrations/001_core.sql").read_bytes()
        ).hexdigest()
        async with await psycopg.AsyncConnection.connect(admin) as conn:
            recorded = await (
                await conn.execute(
                    "SELECT checksum FROM control.schema_migrations WHERE version=1"
                )
            ).fetchone()
        assert recorded[0] == original
        await migrate(admin, name)
        async with await psycopg.AsyncConnection.connect(admin) as conn:
            again = await (
                await conn.execute(
                    "SELECT checksum FROM control.schema_migrations WHERE version=1"
                )
            ).fetchone()
        assert again[0] == original
    finally:
        async with await psycopg.AsyncConnection.connect(
            postgres, autocommit=True
        ) as conn:
            await conn.execute(f'DROP DATABASE "{name}"')


async def test_service_principal_row_provisioned_offline_needs_no_runtime_insert(
    store,
):
    # provision() runs privileged and creates the service principal row, so
    # the runtime (cp_runtime, no INSERT on accounts) only resolves its id.
    await provision(
        store["admin"],
        {
            "client": {
                "id": "offline-principal",
                "via": "game",
                "ceiling": ["workshop.gate"],
            },
            "ceiling": ["workshop.gate"],
            "environment": "prod",
            "backend": "game",
            "resource": "*",
        },
    )
    assert await sql(
        store,
        "SELECT display_name FROM accounts WHERE display_name=%s",
        ("service:offline-principal",),
    ) == [{"display_name": "service:offline-principal"}]
    async with await psycopg.AsyncConnection.connect(
        store["runtime"], options="-c search_path=control,pg_catalog"
    ) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            async with conn.transaction():
                await conn.execute(
                    "INSERT INTO accounts(id,display_name) VALUES(%s,%s)",
                    (uuid4(), "runtime-probe"),
                )


async def test_actual_sse_frames_disconnect_and_socket_flush_is_not_execution(store):
    op = await queued(store)
    epoch = (await sql(store, "SELECT epoch FROM consumers WHERE id='game'"))[0][
        "epoch"
    ]
    messages, disconnected = [], asyncio.Event()
    initial = True

    async def receive():
        nonlocal initial
        if initial:
            initial = False
            return {"type": "http.request", "body": b"", "more_body": False}
        await disconnected.wait()
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)
        if message["type"] == "http.response.body" and b"event: control" in message.get(
            "body", b""
        ):
            disconnected.set()

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": "/v2/agents/game/events",
        "raw_path": b"/v2/agents/game/events",
        "query_string": f"epoch={epoch}&cursor=0".encode(),
        "root_path": "",
        "headers": [
            (b"authorization", headers(store, "game-agent")["Authorization"].encode())
        ],
        "client": ("127.0.0.1", 12345),
        "server": ("control.example.test", 443),
    }
    async with asyncio.timeout(3):
        await store["app"](scope, receive, send)
    assert messages[0]["status"] == 200
    frame = b"".join(m.get("body", b"") for m in messages)
    assert f"id: {epoch}:1".encode() in frame and b'"executable":true' in frame
    assert not store["app"].state.wakeups.waiters
    status = await request(
        store, "GET", "/v2/operations/" + op["operationId"], role="moderator"
    )
    assert status.json()["status"] == "accepted"
    assert not status.json()["receipts"]


async def test_backup_restore_preserves_authority_revisions_audit_and_outbox(
    store, postgres, tmp_path
):
    from pgserver._commands import POSTGRES_BIN_PATH

    response = await request(store, "PATCH", "/v2/settings/gameplay/arena", patch())
    assert response.status_code == 202
    backup = tmp_path / "backup.sql"
    subprocess.run(
        [
            str(POSTGRES_BIN_PATH / "pg_dump"),
            "--dbname",
            store["admin"],
            "--file",
            str(backup),
        ],
        check=True,
        capture_output=True,
        timeout=10,
    )
    restore_name = "restore_" + uuid4().hex
    async with await psycopg.AsyncConnection.connect(postgres, autocommit=True) as conn:
        await conn.execute(f'CREATE DATABASE "{restore_name}"')
    restore_dsn = make_conninfo(postgres, dbname=restore_name)
    try:
        subprocess.run(
            [
                str(POSTGRES_BIN_PATH / "psql"),
                "--dbname",
                restore_dsn,
                "--set",
                "ON_ERROR_STOP=1",
                "--file",
                str(backup),
            ],
            check=True,
            capture_output=True,
            timeout=10,
        )
        await migrate(restore_dsn, restore_name)
        for table in (
            "owner_memberships",
            "owner_credentials",
            "settings_revisions",
            "audit_events",
            "outbox",
        ):
            original = await sql(store, f"SELECT count(*) AS n FROM {table}")
            async with await psycopg.AsyncConnection.connect(restore_dsn) as conn:
                restored = await (
                    await conn.execute(f"SELECT count(*) FROM control.{table}")
                ).fetchone()
            assert restored[0] == original[0]["n"]
        app = create_app(make_conninfo(restore_dsn, user="cp_api"))
        async with app.router.lifespan_context(app):
            async with app.state.db.transaction() as conn:
                identity = await authenticate(conn, store["tokens"]["game-agent"])
                epoch = (
                    await one(conn, "SELECT epoch FROM consumers WHERE id='game'")
                )["epoch"]
                assert len(await delivery.batch(conn, identity, "game", epoch, 0)) == 1
    finally:
        async with await psycopg.AsyncConnection.connect(
            postgres, autocommit=True
        ) as conn:
            await conn.execute(f'DROP DATABASE "{restore_name}"')


async def test_empty_bootstrap_database_refuses_privileged_startup(store):
    await sql(store, "DELETE FROM owner_credentials")
    await sql(store, "DELETE FROM owner_memberships")
    app = create_app(store["runtime"])
    with pytest.raises(RuntimeError, match="bootstrap required"):
        async with app.router.lifespan_context(app):
            pass


async def test_cross_admin_role_edits_deny_without_lock_upgrade_deadlock(
    store, monkeypatch
):
    second = uuid4()
    store["accounts"]["second-admin"] = second
    store["tokens"]["second-admin"] = await provision(
        store["admin"],
        {
            "accountId": str(second),
            "displayName": "second",
            "client": {
                "id": "second-admin",
                "via": "cli",
                "human": True,
                "ceiling": sorted(OWNER_SCOPES),
            },
            "ceiling": sorted(OWNER_SCOPES),
            "environment": "prod",
            "backend": "game",
            "resource": "*",
            "grants": [
                {
                    "role": "admin",
                    "environment": "prod",
                    "backend": "game",
                    "resource": "*",
                    "grantor": str(store["accounts"]["owner"]),
                }
            ],
        },
    )
    original, barrier, count = core.operation, asyncio.Event(), 0

    async def simultaneous(*args, **kwargs):
        nonlocal count
        result = await original(*args, **kwargs)
        count += 1
        if count == 2:
            barrier.set()
        await asyncio.wait_for(barrier.wait(), 2)
        return result

    monkeypatch.setattr(core, "operation", simultaneous)

    def body(account):
        return {
            "idempotencyKey": "peer",
            "expectedRevision": 1,
            "accountId": str(account),
            "role": "builder",
            "resource": "*",
        }

    responses = await asyncio.gather(
        request(store, "POST", "/v2/staff/grants", body(second)),
        request(
            store,
            "POST",
            "/v2/staff/grants",
            body(store["accounts"]["admin"]),
            "second-admin",
        ),
    )
    assert [r.status_code for r in responses] == [403, 403]


async def test_nonhuman_owner_session_never_acquires_owner_authority(store):
    token = await provision(
        store["admin"],
        {
            "accountId": str(store["accounts"]["owner"]),
            "displayName": "owner",
            "client": {
                "id": "unattended",
                "via": "mcp",
                "human": False,
                "ceiling": sorted(OWNER_SCOPES),
            },
            "ceiling": sorted(OWNER_SCOPES),
            "environment": "prod",
            "backend": "game",
            "resource": "*",
        },
    )
    h = {"Authorization": "Bearer " + token}
    assert (await store["client"].get("/v2/me", headers=h)).json()["owner"] is False
    response = await store["client"].post(
        "/v2/owner/challenges",
        headers=h,
        json={
            "method": "PATCH",
            "path": "/v2/settings/gameplay/arena",
            "body": patch(value={"match": {"maxPlayers": 64}}),
        },
    )
    assert response.status_code == 403


async def test_body_limits_and_malformed_json_fail_without_effects(store):
    path = "/v2/settings/gameplay/arena"
    h = headers(store) | {"Content-Type": "application/json"}
    assert (
        await store["client"].patch(path, content=b"{" + b" " * 33000, headers=h)
    ).status_code == 413
    assert (
        await store["client"].patch(path, content=b"{invalid", headers=h)
    ).status_code == 422
    assert not await sql(store, "SELECT * FROM operations")
    assert (
        len(
            await sql(
                store,
                "SELECT * FROM audit_events WHERE outcome='pending' AND action='PATCH'",
            )
        )
        == 2
    )


async def test_scoped_grant_operation_and_audit_use_resource_not_subject_identity(
    store,
):
    await sql(
        store,
        "UPDATE credentials SET resource='arena' WHERE account_id=%s",
        (store["accounts"]["admin"],),
    )
    body = {
        "idempotencyKey": "scoped",
        "expectedRevision": 1,
        "accountId": str(store["accounts"]["other"]),
        "role": "builder",
        "resource": "arena",
    }
    response = await request(store, "POST", "/v2/staff/grants", body)
    assert response.status_code == 202, response.text
    operation = await request(
        store, "GET", "/v2/operations/" + response.json()["operationId"]
    )
    assert operation.status_code == 200, operation.text
    audit_response = await request(store, "GET", "/v2/audit?target=arena")
    assert audit_response.status_code == 200 and audit_response.json()
    assert (await request(store, "GET", "/v2/audit?target=other")).status_code == 403


async def test_startup_rejects_an_unowned_runtime_role_that_can_write_owner_tables(
    store,
):
    # Inheriting another powerful role must not bypass protected-table bootstrap.
    await sql(store, "GRANT INSERT ON owner_memberships TO cp_api")
    app = create_app(store["runtime"])
    with pytest.raises(RuntimeError, match="protected"):
        async with app.router.lifespan_context(app):
            pass


async def test_observer_cursor_never_skips_a_late_commit(store):
    from types import SimpleNamespace

    first_op, second_op = await queued(store, "slow"), await queued(store, "fast")
    initial = (await sql(store, "SELECT max(sequence) AS n FROM operation_events"))[0][
        "n"
    ]
    async with store["app"].state.db.transaction() as conn:
        identity = await authenticate(conn, store["tokens"]["moderator"])
    endpoint = next(
        route.endpoint for route in store["app"].routes if route.path == "/v2/events"
    )
    req = SimpleNamespace(
        state=SimpleNamespace(identity=identity, token=store["tokens"]["moderator"])
    )
    response = await endpoint(
        req, after=initial, environment="prod", backend="game", target="arena"
    )
    iterator = response.body_iterator
    try:
        async with store["app"].state.db.transaction() as slow:
            await core.event(slow, UUID(first_op["operationId"]), "received")
            async with store["app"].state.db.transaction() as fast:
                await core.event(fast, UUID(second_op["operationId"]), "validated")
            first = await asyncio.wait_for(anext(iterator), 2)
            assert '"status": "validated"' in first
        second = await asyncio.wait_for(anext(iterator), 2)
        assert '"status": "received"' in second
        assert int(second.split("\n")[0][4:]) > int(first.split("\n")[0][4:])
    finally:
        await iterator.aclose()


async def test_received_but_unapplied_action_backlog_blocks_new_dangerous_work(store):
    credential = (
        await sql(
            store,
            "SELECT id,authorization_epoch FROM credentials WHERE account_id=%s",
            (store["accounts"]["admin"],),
        )
    )[0]
    # Persisted received receipts alone must not let an executor accumulate effects forever.
    await sql(
        store,
        "INSERT INTO operations(id,account_id,credential_id,client_id,via,kind,target,resource,environment,backend,request_hash,idempotency_key,authorization_epoch,required_scope,generation,deadline,status) SELECT gen_random_uuid(),%s,%s,'admin','cli','moderation.kick','arena','arena','prod','game',repeat('0',64),'seed-'||n,%s,'moderation.kick',%s,now()+interval '60 seconds','received' FROM generate_series(1,128) n",
        (
            store["accounts"]["admin"],
            credential["id"],
            credential["authorization_epoch"],
            store["generation"],
        ),
    )
    await sql(
        store,
        "INSERT INTO outbox(consumer_id,sequence,epoch,operation_id,generation,payload,payload_hash) SELECT 'game',row_number() OVER(ORDER BY p.id),c.epoch,p.id,c.generation,'{}',repeat('0',64) FROM operations p CROSS JOIN consumers c WHERE c.id='game'",
    )
    await sql(
        store,
        "INSERT INTO consumer_acks(consumer_id,sequence,state,receipt_hash,result,actual_at) SELECT consumer_id,sequence,'received',repeat('0',64),'{}',now() FROM outbox",
    )
    await sql(
        store,
        "UPDATE consumers SET next_sequence=129,received_cursor=128 WHERE id='game'",
    )
    body = {
        "idempotencyKey": "blocked",
        "consumerId": "game",
        "generation": str(store["generation"]),
        "target": "arena",
        "playerId": str(uuid4()),
    }
    response = await request(store, "POST", "/v2/actions/moderation.kick", body)
    assert response.status_code == 409 and response.json()["error"] == "consumer_lag"
    assert len(await sql(store, "SELECT * FROM outbox")) == 128


async def test_client_ceiling_and_expired_grants_recheck_queued_authority(store):
    await queued(store, role="admin")
    await sql(
        store, "UPDATE clients SET ceiling=ARRAY['settings.read'] WHERE id='admin'"
    )
    assert (
        await request(store, "PATCH", "/v2/settings/gameplay/arena", patch())
    ).status_code == 403
    frame = (await envelopes(store))[0]
    assert frame["executable"] is False and frame["reason"] == "rejected"
    await sql(
        store,
        "UPDATE role_grants SET expires_at=now()-interval '1 second' WHERE account_id=%s",
        (store["accounts"]["admin"],),
    )
    assert (await request(store, "GET", "/v2/me")).json()["grants"] == []


async def test_c3_terminal_receipt_never_skips_a_missing_sequence(store):
    for key in ("cursor-one", "cursor-two", "cursor-three"):
        await queued(store, key)
    frames = await envelopes(store)
    assert (
        await request(
            store, "POST", "/v2/agents/game/acks", ack_body(frames[0]), "game-agent"
        )
    ).status_code == 200
    # Reconcile persisted receipts conservatively even if a restored cursor trails them.
    await sql(
        store,
        "INSERT INTO consumer_acks(consumer_id,sequence,state,receipt_hash,result,actual_at) SELECT consumer_id,sequence,'received',repeat('0',64),'{}',now() FROM outbox WHERE consumer_id='game' AND sequence=3",
    )
    response = await request(
        store,
        "POST",
        "/v2/agents/game/acks",
        ack_body(frames[2], "rejected"),
        "game-agent",
    )
    assert response.status_code == 200, response.text
    cursor = (
        await sql(store, "SELECT received_cursor FROM consumers WHERE id='game'")
    )[0]["received_cursor"]
    assert cursor == 1, (
        "a terminal receipt above a hole must not move the reconnect cursor"
    )
    assert (
        await request(
            store, "POST", "/v2/agents/game/acks", ack_body(frames[1]), "game-agent"
        )
    ).status_code == 200
    cursor = (
        await sql(store, "SELECT received_cursor FROM consumers WHERE id='game'")
    )[0]["received_cursor"]
    assert cursor == 3


@pytest.mark.parametrize("policy_change", ["revocation", "deadline", "new_revision"])
async def test_c3_factual_effect_receipts_survive_later_policy_changes(
    store, monkeypatch, policy_change
):
    await sql(store, "UPDATE consumers SET capabilities='{}' WHERE id='workshop'")
    accepted = await request(store, "PATCH", "/v2/settings/gameplay/arena", patch())
    assert accepted.status_code == 202
    frame = (await envelopes(store))[0]
    for state in ("received", "validated"):
        response = await request(
            store, "POST", "/v2/agents/game/acks", ack_body(frame, state), "game-agent"
        )
        assert response.status_code == 200, response.text
    effect_at = now()
    if policy_change == "revocation":
        await sql(
            store,
            "UPDATE credentials SET revoked_at=now() WHERE account_id=%s",
            (store["accounts"]["admin"],),
        )
    elif policy_change == "deadline":
        await sql(
            store,
            "UPDATE operations SET deadline=%s WHERE id=%s",
            (effect_at + timedelta(seconds=1), UUID(accepted.json()["operationId"])),
        )
        monkeypatch.setattr(delivery, "now", lambda: effect_at + timedelta(seconds=2))
    else:
        newer = await request(
            store,
            "PATCH",
            "/v2/settings/gameplay/arena",
            patch("newer", 1, {"match": {"maxPlayers": 64}}),
        )
        assert newer.status_code == 202
    for state in ("applied", "effective"):
        body = ack_body(frame, state) | {"actualAt": effect_at.isoformat()}
        response = await request(
            store, "POST", "/v2/agents/game/acks", body, "game-agent"
        )
        assert response.status_code == 200, response.text
    operation = (
        await sql(
            store,
            "SELECT status FROM operations WHERE id=%s",
            (UUID(accepted.json()["operationId"]),),
        )
    )[0]
    assert operation["status"] == "effective"
    assert [
        a["state"]
        for a in await sql(
            store,
            "SELECT state FROM consumer_acks WHERE consumer_id='game' AND sequence=1 ORDER BY recorded_at",
        )
    ] == list(delivery.STATES)


@pytest.mark.parametrize("revision", [0, 1])
async def test_c3_imported_gate_is_in_the_consumer_snapshot(store, tmp_path, revision):
    path = tmp_path / "imported-gate.sqlite"
    legacy = _U1(str(path))
    if revision:
        legacy.set_gate(
            "maintenance", "imported gate", "legacy-admin", "admin", 0, "legacy-change"
        )
    expected = legacy.gate()
    legacy.db.close()
    await import_u1(store["admin"], path)
    response = await request(
        store, "GET", "/v2/agents/game/snapshot", role="game-agent"
    )
    assert response.status_code == 200
    gates = [
        value for value in response.json()["settings"] if value["namespace"] == "gate"
    ]
    assert gates == [
        {
            "namespace": "gate",
            "target": "*",
            "revision": revision,
            "value": {key: expected[key] for key in ("mode", "message")},
            "value_hash": digest({key: expected[key] for key in ("mode", "message")}),
        }
    ]
    assert (
        await request(store, "GET", "/v2/agents/workshop/snapshot", role="game-agent")
    ).status_code == 403


async def test_c3_gate_initialization_is_explicit_at_imported_revision_zero(
    store, tmp_path
):
    view = await request(store, "GET", "/v2/settings/gate/*")
    assert view.json()["initialized"] is False
    assert (
        await request(store, "GET", "/v1/gate", role="game-agent")
    ).status_code == 503
    path = tmp_path / "revision-zero.sqlite"
    legacy = _U1(str(path))
    legacy.db.execute("UPDATE gate_state SET mode='maintenance'")
    legacy.db.commit()
    legacy.db.close()
    await import_u1(store["admin"], path)
    view = await request(store, "GET", "/v2/settings/gate/*")
    assert view.json()["initialized"] is True and view.json()["revision"] == 0
    compat = await request(store, "GET", "/v1/gate", role="game-agent")
    assert compat.status_code == 200 and compat.json()["mode"] == "maintenance"
    first = await request(
        store, "PATCH", "/v2/settings/gate/*", patch("first-v2", 0, {"mode": "open"})
    )
    assert first.status_code == 202 and first.json()["revision"] == 1
    compat = await request(store, "GET", "/v1/gate", role="game-agent")
    assert (
        compat.status_code == 200
        and compat.json()["revision"] == 1
        and compat.json()["mode"] == "open"
    )


async def test_gate_toggle_is_a_single_server_side_read_modify_write(store):
    # admin50-D: one POST replaces GET /v1/gate + PATCH; same auth scope,
    # audit and idempotency as PATCH, visible via the proxy snapshot and
    # the /v1/gate compat read.
    def toggle(key, mode, message=""):
        return {
            "idempotencyKey": key,
            "environment": "prod",
            "backend": "game",
            "mode": mode,
            "message": message,
        }

    assert (await request(store, "GET", "/v2/settings/gate/*")).json()[
        "initialized"
    ] is False
    first = await request(
        store, "POST", "/v2/gate/toggle", toggle("t1", "maintenance", "db")
    )
    assert first.status_code == 202, first.text
    assert first.json()["revision"] == 1
    view = (await request(store, "GET", "/v2/settings/gate/*")).json()
    assert view["initialized"] is True and view["revision"] == 1
    assert view["value"] == {"mode": "maintenance", "message": "db"}
    compat = (await request(store, "GET", "/v1/gate", role="game-agent")).json()
    assert compat["mode"] == "maintenance" and compat["revision"] == 1
    # Same key redelivered (e.g. a site timeout retry) dedupes to the receipt.
    again = await request(
        store, "POST", "/v2/gate/toggle", toggle("t1", "maintenance", "db")
    )
    assert again.status_code == 202
    assert again.json()["operationId"] == first.json()["operationId"]
    assert again.json()["revision"] == 1
    assert (
        len(await sql(store, "SELECT * FROM settings_revisions WHERE namespace='gate'"))
        == 1
    )
    # Key reuse with a different body conflicts, like PATCH.
    assert (
        await request(store, "POST", "/v2/gate/toggle", toggle("t1", "open"))
    ).status_code == 409
    # A second toggle advances the revision in one call.
    second = await request(store, "POST", "/v2/gate/toggle", toggle("t2", "open"))
    assert second.status_code == 202 and second.json()["revision"] == 2
    assert (await request(store, "GET", "/v1/gate", role="game-agent")).json()[
        "mode"
    ] == "open"
    # Auth scope and validation match PATCH: moderators cannot toggle, a bad
    # mode is 422.
    assert (
        await request(
            store, "POST", "/v2/gate/toggle", toggle("t3", "open"), "moderator"
        )
    ).status_code == 403
    assert (
        await request(store, "POST", "/v2/gate/toggle", toggle("t4", "half-open"))
    ).status_code == 422


async def test_gate_toggle_and_patch_with_one_key_never_deadlock(store):
    # Toggle and PATCH must take the idempotency lock and the head row in the
    # same order; the reverse order deadlocked when both raced on one key.
    for round_ in range(10):
        key = f"race-{round_}"
        toggle = request(
            store,
            "POST",
            "/v2/gate/toggle",
            {
                "idempotencyKey": key,
                "environment": "prod",
                "backend": "game",
                "mode": "open",
                "message": "",
            },
        )
        head = (await request(store, "GET", "/v2/settings/gate/*")).json()
        patch_ = request(
            store,
            "PATCH",
            "/v2/settings/gate/*",
            {
                "idempotencyKey": key,
                "environment": "prod",
                "backend": "game",
                "expectedRevision": head["revision"],
                "patch": {"mode": "open", "message": ""},
            },
        )
        results = await asyncio.gather(toggle, patch_)
        assert all(r.status_code < 500 for r in results), [r.text for r in results]


async def test_site_gate_toggle_asserts_actor_and_delivers_to_game_leg(store):
    # control-plane#52: the site principal asserts the logged-in admin on the
    # gate toggle and the game-leg gate PATCH; the operation stores
    # account_id=actor + authorization_epoch, so the proxy frame executes
    # instead of fencing as account-less.
    store["tokens"]["sitegate"] = await provision(
        store["admin"],
        {
            "client": {
                "id": "sitegate",
                "via": "game",
                "ceiling": ["settings.read", "moderation.ban"],
            },
            "ceiling": ["settings.read", "moderation.ban"],
            "environment": "prod",
            "backend": "game",
            "resource": "*",
        },
    )
    admin = store["accounts"]["admin"]

    def toggle(key, actor=None):
        body = {
            "idempotencyKey": key,
            "environment": "prod",
            "backend": "game",
            "mode": "maintenance",
            "message": "db",
        }
        if actor is not None:
            body["actorAccountId"] = str(actor)
        return body

    denied = await request(
        store, "POST", "/v2/gate/toggle", toggle("gate-no-actor"), "sitegate"
    )
    assert denied.status_code == 403
    assert denied.json()["error"] == "service_actor_required", denied.text
    # The asserted actor must hold the scope: moderators cannot toggle.
    peer = await request(
        store,
        "POST",
        "/v2/gate/toggle",
        toggle("gate-peer", store["accounts"]["moderator"]),
        "sitegate",
    )
    assert peer.status_code == 403, peer.text
    accepted = await request(
        store, "POST", "/v2/gate/toggle", toggle("gate-admin", admin), "sitegate"
    )
    assert accepted.status_code == 202, accepted.text
    assert accepted.json()["revision"] == 1
    operation = accepted.json()["operationId"]
    stored = await sql(
        store,
        "SELECT o.account_id, o.authorization_epoch, a.authorization_epoch AS epoch FROM operations o JOIN accounts a ON a.id=o.account_id WHERE o.id=%s",
        (operation,),
    )
    assert [r["account_id"] for r in stored] == [admin]
    assert stored[0]["authorization_epoch"] == stored[0]["epoch"]
    frames = await envelopes(store)
    frame = next(item for item in frames if item["operationId"] == operation)
    assert frame["executable"] and frame["reason"] is None
    assert frame["payload"]["namespace"] == "gate" and frame["payload"]["target"] == "*"
    # Direct callers are authenticated and must never send an actor.
    forged = await request(
        store, "POST", "/v2/gate/toggle", toggle("gate-direct", admin)
    )
    assert forged.status_code == 403
    assert forged.json()["error"] == "actor_forbidden", forged.text
    # Only the unbound site principal may assert an actor.
    store["tokens"]["sitegate-scoped"] = await provision(
        store["admin"],
        {
            "client": {
                "id": "sitegate-scoped",
                "via": "game",
                "ceiling": ["moderation.ban"],
            },
            "ceiling": ["moderation.ban"],
            "environment": "prod",
            "backend": "game",
            "resource": "arena",
        },
    )
    bound = await request(
        store,
        "POST",
        "/v2/gate/toggle",
        toggle("gate-scoped", admin),
        "sitegate-scoped",
    )
    assert bound.status_code == 403
    # The toggle target is always "*": a scoped credential cannot cover it,
    # so the scope require fences before the actor branch. The scoped-actor
    # rule itself fires on a covered target (mirrors grant_change).
    assert bound.json()["error"] == "forbidden", bound.text
    scoped_patch = await request(
        store,
        "PATCH",
        "/v2/settings/gate/arena",
        {
            "idempotencyKey": "gate-scoped-patch",
            "environment": "prod",
            "backend": "game",
            "expectedRevision": 0,
            "patch": {"mode": "open", "message": ""},
            "actorAccountId": str(admin),
        },
        "sitegate-scoped",
    )
    assert scoped_patch.status_code == 403
    assert scoped_patch.json()["error"] == "actor_forbidden", scoped_patch.text
    # The game-leg gate PATCH asserts the same way through settings_change.
    view = (await request(store, "GET", "/v2/settings/gate/*")).json()
    refused = await request(
        store,
        "PATCH",
        "/v2/settings/gate/*",
        {
            "idempotencyKey": "gate-patch-no-actor",
            "environment": "prod",
            "backend": "game",
            "expectedRevision": view["revision"],
            "patch": {"mode": "open", "message": ""},
        },
        "sitegate",
    )
    assert refused.status_code == 403
    assert refused.json()["error"] == "service_actor_required", refused.text
    patched = await request(
        store,
        "PATCH",
        "/v2/settings/gate/*",
        {
            "idempotencyKey": "gate-patch-admin",
            "environment": "prod",
            "backend": "game",
            "expectedRevision": view["revision"],
            "patch": {"mode": "open", "message": ""},
            "actorAccountId": str(admin),
        },
        "sitegate",
    )
    assert patched.status_code == 202, patched.text
    patched_frames = await envelopes(store)
    patched_frame = next(
        item
        for item in patched_frames
        if item["operationId"] == patched.json()["operationId"]
    )
    assert patched_frame["executable"] and patched_frame["reason"] is None


@pytest.mark.parametrize("credential_scope", ["*", "arena"])
async def test_c3_owner_audit_respects_requested_and_credential_scope(
    store, credential_scope
):
    accepted = await request(
        store, "PATCH", "/v2/settings/gameplay/arena", patch("allowed"), "owner"
    )
    assert accepted.status_code == 202
    unrelated = await request(
        store, "PATCH", "/v2/settings/gameplay/other", patch("other"), "owner"
    )
    assert unrelated.status_code == 202
    for environment, backend in (("qa", "game"), ("prod", "workshop")):
        role = environment + "-" + backend
        store["tokens"][role] = await provision(
            store["admin"],
            {
                "accountId": str(store["accounts"]["owner"]),
                "displayName": "owner",
                "client": {
                    "id": "owner",
                    "via": "ui",
                    "human": True,
                    "ceiling": sorted(OWNER_SCOPES),
                },
                "ceiling": sorted(OWNER_SCOPES),
                "environment": environment,
                "backend": backend,
                "resource": "*",
            },
        )
        result = await request(
            store,
            "PATCH",
            "/v2/settings/gameplay/arena",
            patch(role) | {"environment": environment, "backend": backend},
            role,
        )
        assert result.status_code == 202
    await sql(
        store,
        "UPDATE credentials SET resource=%s WHERE verifier=%s",
        (credential_scope, verifier(store["tokens"]["owner"])),
    )
    response = await request(
        store,
        "GET",
        "/v2/audit?environment=prod&backend=game&target=arena",
        role="owner",
    )
    assert response.status_code == 200
    ids = {row["operation_id"] for row in response.json() if row["operation_id"]}
    assert ids == {accepted.json()["operationId"]}, (
        "owner role must not bypass resource/environment/backend filters"
    )
    assert all(
        (row["environment"], row["backend"], row["resource"])
        == ("prod", "game", "arena")
        for row in response.json()
    )
    assert (
        await request(
            store, "GET", "/v2/audit?environment=*&backend=*&target=*", role="owner"
        )
    ).status_code == 403
    if credential_scope == "*":
        await sql(
            store,
            "UPDATE credentials SET environment='*',backend='*' WHERE verifier=%s",
            (verifier(store["tokens"]["owner"]),),
        )
        assert (
            await store["client"].patch(
                "/v2/settings/gameplay/arena", json=patch("unauthenticated")
            )
        ).status_code == 401
        full = await request(
            store, "GET", "/v2/audit?environment=*&backend=*&target=*", role="owner"
        )
        assert full.status_code == 200
        assert any(row["action"] == "owner.bootstrap" for row in full.json())
        assert any(
            row["actor"] is None and row["outcome"] == "denied" for row in full.json()
        )


async def test_c3_expiry_read_locks_the_operation_before_deciding(store, monkeypatch):
    op = await queued(store)
    frame = (await envelopes(store))[0]
    for state in ("received", "validated"):
        assert (
            await request(
                store,
                "POST",
                "/v2/agents/game/acks",
                ack_body(frame, state),
                "game-agent",
            )
        ).status_code == 200
    future = now() + timedelta(seconds=120)
    monkeypatch.setattr(core, "now", lambda: future)
    selected, release = asyncio.Event(), asyncio.Event()
    original, paused = core.one, False

    async def pause_after_read(conn, query, args=()):
        nonlocal paused
        row = await original(conn, query, args)
        if query.startswith("SELECT * FROM operations WHERE id=") and not paused:
            paused = True
            selected.set()
            await asyncio.wait_for(release.wait(), 5)
        return row

    monkeypatch.setattr(core, "one", pause_after_read)
    reader = asyncio.create_task(
        request(store, "GET", "/v2/operations/" + op["operationId"], role="moderator")
    )
    try:
        await asyncio.wait_for(selected.wait(), 5)
        blocked = False
        try:
            await sql(
                store,
                "SELECT id FROM operations WHERE id=%s FOR UPDATE NOWAIT",
                (UUID(op["operationId"]),),
            )
        except psycopg.errors.LockNotAvailable:
            blocked = True
        assert blocked, (
            "a final ACK must not be able to update a row already read for expiry"
        )
    finally:
        release.set()
        await asyncio.wait_for(reader, 5)
    for state in ("applied", "effective"):
        response = await request(
            store, "POST", "/v2/agents/game/acks", ack_body(frame, state), "game-agent"
        )
        assert response.status_code == 200, response.text
    assert (
        await sql(
            store,
            "SELECT status FROM operations WHERE id=%s",
            (UUID(op["operationId"]),),
        )
    )[0]["status"] == "effective"


async def test_c4_garbage_bearer_flood_cannot_starve_authenticated_traffic(store):
    assert (await request(store, "GET", "/v2/me")).status_code == 200
    for i in range(1000):
        await store["client"].get(
            "/v2/me", headers={"Authorization": f"Bearer garbage-{i}"}
        )
    assert (await request(store, "GET", "/v2/me")).status_code == 200, (
        "distinct unauthenticated bearer strings must not burn the shared budget"
    )
    assert (await store["client"].get("/health")).status_code == 200


async def test_c4_completed_audit_failure_cannot_strand_a_delegation_token(
    store, monkeypatch
):
    import cpv2.app

    real_audit = cpv2.app.audit

    async def fail_completed(*args, **kwargs):
        if (args[5] if len(args) > 5 else kwargs.get("outcome")) == "completed":
            raise psycopg.OperationalError("synthetic post-commit audit outage")
        return await real_audit(*args, **kwargs)

    monkeypatch.setattr(cpv2.app, "audit", fail_completed)
    body = {
        "idempotencyKey": "stranded",
        "scopes": ["settings.read"],
        "resource": "arena",
    }
    assert (await request(store, "POST", "/v2/delegations", body)).status_code == 503
    assert not await sql(store, "SELECT * FROM credentials WHERE kind='delegation'"), (
        "a failed completion audit must roll the delegation back, not strand it"
    )
    assert not await sql(
        store, "SELECT * FROM operations WHERE kind='delegations.create'"
    )
    monkeypatch.undo()
    retry = await request(store, "POST", "/v2/delegations", body)
    assert retry.status_code == 201, retry.text
    assert retry.json()["token"], "the retry must deliver a usable one-time token"


async def test_c4_expired_operation_emits_one_settlement(store, monkeypatch):
    op = await queued(store)
    monkeypatch.setattr(delivery, "now", lambda: now() + timedelta(seconds=61))
    first = await envelopes(store)
    assert first[0]["reason"] == "expired" and first[0]["executable"] is False
    second = await envelopes(store)
    assert second[0]["reason"] == "expired"
    events = await sql(
        store,
        "SELECT status FROM operation_events WHERE operation_id=%s ORDER BY sequence",
        (UUID(op["operationId"]),),
    )
    assert [event["status"] for event in events] == ["accepted", "expired"]


async def test_c5_stale_generation_never_rejects_the_shared_operation(store):
    accepted = await request(
        store, "PATCH", "/v2/settings/gameplay/arena", patch("fanout")
    )
    assert accepted.status_code == 202
    await sql(store, "UPDATE consumers SET generation=%s WHERE id='game'", (uuid4(),))
    game = await envelopes(store)
    assert game[0]["reason"] == "rejected" and game[0]["executable"] is False
    status = (
        await sql(
            store,
            "SELECT status FROM operations WHERE id=%s",
            (UUID(accepted.json()["operationId"]),),
        )
    )[0]["status"]
    assert status == "accepted", "a stale consumer must not reject the shared operation"
    workshop = await envelopes(store, cid="workshop")
    assert workshop[0]["executable"] is True and workshop[0]["reason"] is None


async def test_c5_migration_refuses_an_unexpected_database(store):
    with pytest.raises(RuntimeError, match="expected the dedicated control database"):
        await migrate(store["admin"], "wrong-database-name")
    await migrate(store["admin"], conninfo_to_dict(store["admin"])["dbname"])


async def test_c5_bootstrap_revokes_pre_existing_sessions(store, postgres):
    name = "cp_" + uuid4().hex
    async with await psycopg.AsyncConnection.connect(postgres, autocommit=True) as conn:
        await conn.execute(f'CREATE DATABASE "{name}"')
    admin = make_conninfo(postgres, dbname=name)
    try:
        await migrate(admin, name)
        account = uuid4()
        spec = {
            "client": {
                "id": "future-owner",
                "via": "ui",
                "human": True,
                "ceiling": sorted(OWNER_SCOPES),
            },
            "accountId": str(account),
            "displayName": "future-owner",
            "ceiling": sorted(OWNER_SCOPES),
            "environment": "prod",
            "backend": "game",
            "resource": "*",
        }
        stale = await provision(admin, spec)
        # authenticate() holds FOR SHARE row locks to end of transaction, so
        # each connection must close before bootstrap's revocation UPDATEs the
        # same account row, or the UPDATE waits on this transaction forever.
        async with await psycopg.AsyncConnection.connect(
            admin,
            options="-c search_path=control,pg_catalog",
            row_factory=psycopg.rows.dict_row,
        ) as conn:
            assert (await authenticate(conn, stale)).owner is False
        await bootstrap(admin, account, "owner", store["credential"])
        async with await psycopg.AsyncConnection.connect(
            admin,
            options="-c search_path=control,pg_catalog",
            row_factory=psycopg.rows.dict_row,
        ) as conn:
            with pytest.raises(Problem):
                await authenticate(conn, stale)
        fresh = await provision(admin, spec)
        async with await psycopg.AsyncConnection.connect(
            admin,
            options="-c search_path=control,pg_catalog",
            row_factory=psycopg.rows.dict_row,
        ) as conn:
            assert (await authenticate(conn, fresh)).owner is True
    finally:
        async with await psycopg.AsyncConnection.connect(
            postgres, autocommit=True
        ) as conn:
            await conn.execute(f'DROP DATABASE "{name}"')


async def arena_agent(store):
    token = await provision(
        store["admin"],
        {
            "client": {
                "id": "arena",
                "via": "game",
                "ceiling": sorted(SERVICE_SCOPES),
            },
            "ceiling": sorted(SERVICE_SCOPES),
            "environment": "prod",
            "backend": "game",
            "resource": "arena",
            "consumer": {
                "id": "arena",
                "generation": str(uuid4()),
                "capabilities": ["settings.gameplay", "settings.gate"],
            },
        },
    )
    store["tokens"]["arena-agent"] = token
    return token


async def test_c7_scoped_consumer_receives_global_settings_and_snapshot(store):
    await arena_agent(store)
    accepted = await request(
        store, "PATCH", "/v2/settings/gameplay/*", patch("global", 0)
    )
    assert accepted.status_code == 202
    frames = await envelopes(store, cid="arena")
    assert len(frames) == 1 and frames[0]["executable"] is True
    snapshot = await request(
        store, "GET", "/v2/agents/arena/snapshot", role="arena-agent"
    )
    assert snapshot.status_code == 200
    scoped = [
        value
        for value in snapshot.json()["settings"]
        if value["namespace"] == "gameplay" and value["target"] == "*"
    ]
    assert len(scoped) == 1 and scoped[0]["value"]["lobby"]["pvpEnabled"] is True


async def test_c7_scoped_consumer_gets_imported_global_gate(store, tmp_path):
    await arena_agent(store)
    path = tmp_path / "arena-gate.sqlite"
    legacy = _U1(str(path))
    legacy.db.execute("UPDATE gate_state SET mode='maintenance'")
    legacy.db.commit()
    expected = legacy.gate()
    legacy.db.close()
    await import_u1(store["admin"], path)
    snapshot = await request(
        store, "GET", "/v2/agents/arena/snapshot", role="arena-agent"
    )
    assert snapshot.status_code == 200
    gates = [
        value for value in snapshot.json()["settings"] if value["namespace"] == "gate"
    ]
    assert gates == [
        {
            "namespace": "gate",
            "target": "*",
            "revision": 0,
            "value": {key: expected[key] for key in ("mode", "message")},
            "value_hash": digest({key: expected[key] for key in ("mode", "message")}),
        }
    ]


async def test_c7_replaced_generation_settles_orphaned_frames(store):
    await queued(store, "orphan")
    (await envelopes(store))[0]
    new_generation = uuid4()
    await sql(
        store, "UPDATE consumers SET generation=%s WHERE id='game'", (new_generation,)
    )
    store["generation"] = new_generation
    stale = (await envelopes(store))[0]
    assert stale["reason"] == "rejected" and stale["executable"] is False
    assert (
        await request(
            store, "POST", "/v2/agents/game/acks", ack_body(stale), "game-agent"
        )
    ).status_code == 409
    body = ack_body(stale, "rejected")
    assert (
        await request(store, "POST", "/v2/agents/game/acks", body, "game-agent")
    ).status_code == 200
    assert (await sql(store, "SELECT received_cursor FROM consumers WHERE id='game'"))[
        0
    ]["received_cursor"] == 1
    await queued(store, "followup")
    live = [f for f in await envelopes(store) if f["sequence"] == 2]
    assert len(live) == 1 and live[0]["executable"] is True
    assert (
        await request(
            store, "POST", "/v2/agents/game/acks", ack_body(live[0]), "game-agent"
        )
    ).status_code == 200


async def test_c7_revoked_issuer_with_newer_revision_settles_rejected(store):
    first = await request(
        store, "PATCH", "/v2/settings/gameplay/arena", patch("revoked-one")
    )
    assert first.status_code == 202
    second = await request(
        store,
        "PATCH",
        "/v2/settings/gameplay/arena",
        patch("revoked-two", 1, {"lobby": {"pvpEnabled": False}}),
    )
    assert second.status_code == 202
    await sql(
        store,
        "UPDATE credentials SET revoked_at=now() WHERE account_id=%s",
        (store["accounts"]["admin"],),
    )
    frames = await envelopes(store)
    assert frames[0]["reason"] == "rejected"
    assert (
        await sql(
            store,
            "SELECT status FROM operations WHERE id=%s",
            (UUID(first.json()["operationId"]),),
        )
    )[0]["status"] == "rejected"


async def test_c7_provision_locks_the_account_before_reading_epoch(store, monkeypatch):
    import cpv2.admin

    account = uuid4()
    await sql(
        store,
        "INSERT INTO accounts(id,display_name) VALUES(%s,'raced')",
        (account,),
    )
    original = cpv2.admin.one
    selected, release, started = asyncio.Event(), asyncio.Event(), False

    async def pause_after_read(conn, query, args=()):
        nonlocal started
        row = await original(conn, query, args)
        if query.startswith("SELECT * FROM accounts WHERE id=") and not started:
            started = True
            selected.set()
            await asyncio.wait_for(release.wait(), 5)
        return row

    monkeypatch.setattr(cpv2.admin, "one", pause_after_read)
    task = asyncio.create_task(
        provision(
            store["admin"],
            {
                "accountId": str(account),
                "displayName": "raced",
                "client": {
                    "id": "raced",
                    "via": "cli",
                    "human": True,
                    "ceiling": sorted(OWNER_SCOPES),
                },
                "ceiling": sorted(OWNER_SCOPES),
                "environment": "prod",
                "backend": "game",
                "resource": "*",
            },
        )
    )
    try:
        await asyncio.wait_for(selected.wait(), 5)
        # A concurrent grant change must block on the same row, not race past it.
        with pytest.raises(psycopg.errors.LockNotAvailable):
            await sql(
                store,
                "SELECT * FROM accounts WHERE id=%s FOR UPDATE NOWAIT",
                (account,),
            )
    finally:
        release.set()
        await asyncio.wait_for(task, 5)


async def test_c8_provisioning_grants_revokes_existing_sessions(store):
    account = uuid4()
    base = {
        "accountId": str(account),
        "displayName": "granted",
        "environment": "prod",
        "backend": "game",
        "resource": "*",
    }
    first = await provision(
        store["admin"],
        base
        | {
            "client": {
                "id": "c8s1",
                "via": "cli",
                "human": True,
                "ceiling": sorted(OWNER_SCOPES),
            },
            "ceiling": sorted(OWNER_SCOPES),
        },
    )
    assert (
        await store["client"].get(
            "/v2/settings/gameplay/arena",
            headers={"Authorization": "Bearer " + first},
        )
    ).status_code == 403
    second = await provision(
        store["admin"],
        base
        | {
            "client": {
                "id": "c8s2",
                "via": "cli",
                "human": True,
                "ceiling": sorted(OWNER_SCOPES),
            },
            "ceiling": sorted(OWNER_SCOPES),
            "grants": [
                {
                    "role": "builder",
                    "environment": "prod",
                    "backend": "game",
                    "resource": "*",
                    "grantor": str(store["accounts"]["owner"]),
                }
            ],
        },
    )
    assert (
        await store["client"].get(
            "/v2/settings/gameplay/arena",
            headers={"Authorization": "Bearer " + first},
        )
    ).status_code == 401
    assert (
        await store["client"].get(
            "/v2/settings/gameplay/arena",
            headers={"Authorization": "Bearer " + second},
        )
    ).status_code == 200


async def test_c8_gate_fallback_never_leaks_across_environments(store, tmp_path):
    token = await provision(
        store["admin"],
        {
            "client": {
                "id": "qa",
                "via": "game",
                "ceiling": sorted(SERVICE_SCOPES),
            },
            "ceiling": sorted(SERVICE_SCOPES),
            "environment": "qa",
            "backend": "game",
            "resource": "*",
            "consumer": {
                "id": "qa",
                "generation": str(uuid4()),
                "capabilities": ["settings.gate"],
            },
        },
    )
    store["tokens"]["qa-agent"] = token
    path = tmp_path / "qa-gate.sqlite"
    legacy = _U1(str(path))
    legacy.db.execute("UPDATE gate_state SET mode='maintenance'")
    legacy.db.commit()
    legacy.db.close()
    await import_u1(store["admin"], path)
    snapshot = await request(store, "GET", "/v2/agents/qa/snapshot", role="qa-agent")
    assert snapshot.status_code == 200
    assert [s for s in snapshot.json()["settings"] if s["namespace"] == "gate"] == []


async def test_c9_late_revocation_never_demotes_a_sibling_effect(store):
    accepted = await request(
        store, "PATCH", "/v2/settings/gameplay/arena", patch("c9-effect")
    )
    assert accepted.status_code == 202
    operation_id = UUID(accepted.json()["operationId"])
    frame = (await envelopes(store))[0]
    for state in ("received", "validated", "applied"):
        assert (
            await request(
                store,
                "POST",
                "/v2/agents/game/acks",
                ack_body(frame, state),
                "game-agent",
            )
        ).status_code == 200
    assert (
        await sql(store, "SELECT status FROM operations WHERE id=%s", (operation_id,))
    )[0]["status"] == "partial"
    await sql(
        store,
        "UPDATE credentials SET revoked_at=now() WHERE account_id=%s",
        (store["accounts"]["admin"],),
    )
    lagging = (await envelopes(store, cid="workshop"))[0]
    assert lagging["reason"] == "rejected" and lagging["executable"] is False
    assert (
        await sql(store, "SELECT status FROM operations WHERE id=%s", (operation_id,))
    )[0]["status"] == "partial"


async def test_c10_snapshot_reads_one_consistent_revision(store, monkeypatch):
    import cpv2.delivery

    await request(store, "PATCH", "/v2/settings/gameplay/arena", patch("c10-base"))
    original_rows, calls = cpv2.delivery.rows, 0
    paused, release = asyncio.Event(), asyncio.Event()

    async def pause_after_first_settings(conn, query, args=()):
        nonlocal calls
        found = await original_rows(conn, query, args)
        calls += 1
        if calls == 1 and "settings_heads" in query:
            paused.set()
            await asyncio.wait_for(release.wait(), 5)
        return found

    monkeypatch.setattr(cpv2.delivery, "rows", pause_after_first_settings)
    task = asyncio.create_task(
        request(store, "GET", "/v2/agents/game/snapshot", role="game-agent")
    )
    try:
        await asyncio.wait_for(paused.wait(), 5)
        assert (
            await request(
                store,
                "PATCH",
                "/v2/settings/gameplay/arena",
                patch("c10-race", 1, {"match": {"maxPlayers": 8}}),
            )
        ).status_code == 202
        assert (
            await request(
                store,
                "PATCH",
                "/v2/settings/gate/*",
                patch("c10-gate", 0, {"mode": "open"}),
            )
        ).status_code == 202
    finally:
        release.set()
    snapshot = await asyncio.wait_for(task, 10)
    assert snapshot.status_code == 200
    seen = {
        (value["namespace"], value["target"]): value["revision"]
        for value in snapshot.json()["settings"]
    }
    assert seen == {("gameplay", "arena"): 1} or seen == {
        ("gameplay", "arena"): 2,
        ("gate", "*"): 1,
    }, f"torn snapshot spanning two commits: {seen}"


async def test_c10_concurrent_consumers_drain_shared_fanout_without_deadlock(store):
    consumers = {
        row["id"]: row
        for row in await sql(
            store, "SELECT * FROM consumers WHERE id IN ('game','workshop')"
        )
    }
    cred = (await sql(store, "SELECT id FROM credentials WHERE client_id='game'"))[0][
        "id"
    ]
    ops = []
    for _ in range(4):
        op = uuid4()
        await sql(
            store,
            "INSERT INTO operations(id,credential_id,client_id,via,kind,target,resource,environment,backend,request_hash,idempotency_key,required_scope,deadline,status) VALUES(%s,%s,'game','game','test.drain','arena','arena','prod','game',%s,%s,'settings.read',now()+interval '60 seconds','accepted')",
            (op, cred, uuid4().hex, uuid4().hex),
        )
        ops.append(op)
    # Same shared operations, opposite outbox orders: without one global lock
    # order the two drains take these rows in opposite orders and deadlock.
    for cid, seq_ops in (("game", ops), ("workshop", list(reversed(ops)))):
        consumer = consumers[cid]
        for seq, op in enumerate(seq_ops, 1):
            await sql(
                store,
                "INSERT INTO outbox(consumer_id,sequence,epoch,operation_id,generation,payload,payload_hash) VALUES(%s,%s,%s,%s,%s,%s,%s)",
                (
                    cid,
                    seq,
                    consumer["epoch"],
                    op,
                    consumer["generation"],
                    Jsonb({"n": seq}),
                    "ab" * 32,
                ),
            )
    go = asyncio.Event()

    async def drain(cid):
        await go.wait()
        async with store["app"].state.db.transaction() as conn:
            identity = await authenticate(conn, store["tokens"][cid + "-agent"])
            consumer = await one(
                conn, "SELECT epoch FROM consumers WHERE id=%s", (cid,)
            )
            return await delivery.batch(conn, identity, cid, consumer["epoch"], 0)

    first = asyncio.create_task(drain("game"))
    second = asyncio.create_task(drain("workshop"))
    await asyncio.sleep(0.2)
    go.set()
    game, workshop = await asyncio.wait_for(asyncio.gather(first, second), 30)
    assert [f["sequence"] for f in game] == [1, 2, 3, 4]
    assert [f["sequence"] for f in workshop] == [1, 2, 3, 4]


async def test_c11_epoch_replacement_settles_retired_frames(store):
    op = await queued(store, "epoch-old")
    await queued(store, "epoch-older")
    frame = (await envelopes(store))[0]
    new_epoch, new_generation = uuid4(), uuid4()
    await sql(
        store,
        "UPDATE consumers SET epoch=%s, generation=%s WHERE id='game'",
        (new_epoch, new_generation),
    )
    store["generation"] = new_generation
    # Old-epoch reconnects must resync, not silently reuse the new cursor.
    assert (
        await store["client"].get(
            "/v2/agents/game/events",
            params={"epoch": frame["epoch"], "cursor": 0},
            headers={"Authorization": "Bearer " + store["tokens"]["game-agent"]},
        )
    ).status_code == 409
    stale = [f for f in await envelopes(store) if f["sequence"] == 1][0]
    assert stale["reason"] == "rejected" and stale["executable"] is False
    current = {
        **ack_body(stale, "rejected"),
        "epoch": str(new_epoch),
        "generation": str(new_generation),
    }
    assert (
        await request(store, "POST", "/v2/agents/game/acks", current, "game-agent")
    ).status_code == 200
    assert (await sql(store, "SELECT received_cursor FROM consumers WHERE id='game'"))[
        0
    ]["received_cursor"] == 1
    # Historical endpoint identity settles a different retired frame; one
    # envelope still settles exactly once, so a second terminal state for the
    # same frame stays a conflict.
    second = [f for f in await envelopes(store) if f["sequence"] == 2][0]
    historic = ack_body(second, "unknown")
    assert (
        await request(store, "POST", "/v2/agents/game/acks", historic, "game-agent")
    ).status_code == 200
    assert (
        await request(store, "POST", "/v2/agents/game/acks", historic, "game-agent")
    ).status_code == 200
    assert (
        await request(
            store,
            "POST",
            "/v2/agents/game/acks",
            dict(historic, result="effect_uncertain"),
            "game-agent",
        )
    ).status_code == 409
    followup = await queued(store, "epoch-new")
    assert followup["operationId"] != op["operationId"]
    live = [f for f in await envelopes(store) if f["sequence"] == 3]
    assert len(live) == 1 and live[0]["executable"] is True
    assert (
        await request(
            store, "POST", "/v2/agents/game/acks", ack_body(live[0]), "game-agent"
        )
    ).status_code == 200


@pytest.mark.parametrize("kill", ["revoke", "expire"])
async def test_c11_unknown_preserved_across_settlement(store, kill):
    first = await request(
        store, "PATCH", "/v2/settings/gameplay/arena", patch("c11-unknown")
    )
    assert first.status_code == 202
    operation_id = UUID(first.json()["operationId"])
    game_frame = (await envelopes(store))[0]
    assert (
        await request(
            store,
            "POST",
            "/v2/agents/game/acks",
            ack_body(game_frame, "unknown"),
            "game-agent",
        )
    ).status_code == 200
    assert (
        await sql(store, "SELECT status FROM operations WHERE id=%s", (operation_id,))
    )[0]["status"] == "partial"
    if kill == "revoke":
        await sql(
            store,
            "UPDATE credentials SET revoked_at=now() WHERE account_id=%s",
            (store["accounts"]["admin"],),
        )
    else:
        await sql(
            store,
            "UPDATE operations SET deadline=now()-interval '1 second' WHERE id=%s",
            (operation_id,),
        )
    for _ in range(3):
        frames = await envelopes(store, cid="workshop")
        assert frames[0]["reason"] in ("expired", "rejected")
        assert frames[0]["executable"] is False
        assert (
            await sql(
                store, "SELECT status FROM operations WHERE id=%s", (operation_id,)
            )
        )[0]["status"] == "partial"
    workshop_frame = (await envelopes(store, cid="workshop"))[0]
    assert (
        await request(
            store,
            "POST",
            "/v2/agents/workshop/acks",
            ack_body(workshop_frame, "rejected"),
            "workshop-agent",
        )
    ).status_code == 200
    assert (
        await sql(store, "SELECT status FROM operations WHERE id=%s", (operation_id,))
    )[0]["status"] == "partial"


async def test_c11_rejected_after_applied_conflicts(store):
    await queued(store, "applied-then-reject")
    frame = (await envelopes(store))[0]
    for state in ("received", "validated", "applied"):
        assert (
            await request(
                store,
                "POST",
                "/v2/agents/game/acks",
                ack_body(frame, state),
                "game-agent",
            )
        ).status_code == 200
    assert (
        await request(
            store,
            "POST",
            "/v2/agents/game/acks",
            ack_body(frame, "rejected"),
            "game-agent",
        )
    ).status_code == 409
    assert (
        await request(
            store,
            "POST",
            "/v2/agents/game/acks",
            ack_body(frame, "unknown"),
            "game-agent",
        )
    ).status_code == 200
    both = await request(
        store, "PATCH", "/v2/settings/gameplay/arena", patch("c11-both-applied")
    )
    assert both.status_code == 202
    both_id = UUID(both.json()["operationId"])
    for cid in ("game", "workshop"):
        role = cid + "-agent"
        envelope = [
            f
            for f in await envelopes(store, cid=cid)
            if f["operationId"] == str(both_id)
        ][0]
        for state in ("received", "validated", "applied"):
            assert (
                await request(
                    store,
                    "POST",
                    f"/v2/agents/{cid}/acks",
                    ack_body(envelope, state),
                    role,
                )
            ).status_code == 200
        assert (
            await request(
                store,
                "POST",
                f"/v2/agents/{cid}/acks",
                ack_body(envelope, "rejected"),
                role,
            )
        ).status_code == 409
    assert (await sql(store, "SELECT status FROM operations WHERE id=%s", (both_id,)))[
        0
    ]["status"] == "applied"


async def test_c11_delayed_chain_uploads_as_history(store):
    await queued(store, "late-a")
    await queued(store, "late-b")
    await queued(store, "late-c")
    await queued(store, "late-d")
    received_a = (await envelopes(store))[0]
    assert (
        await request(
            store, "POST", "/v2/agents/game/acks", ack_body(received_a), "game-agent"
        )
    ).status_code == 200
    received_b = (await envelopes(store))[1]
    assert (
        await request(
            store, "POST", "/v2/agents/game/acks", ack_body(received_b), "game-agent"
        )
    ).status_code == 200
    await sql(
        store,
        "UPDATE credentials SET revoked_at=now() WHERE account_id=%s",
        (store["accounts"]["moderator"],),
    )
    # Loss between received and validated, and after validated: the locally
    # durable chain uploads after the policy change instead of being discarded.
    for frame in (received_a, received_b):
        for state in ("validated", "applied", "effective"):
            assert (
                await request(
                    store,
                    "POST",
                    "/v2/agents/game/acks",
                    ack_body(frame, state),
                    "game-agent",
                )
            ).status_code == 200
    # Loss before received: the whole chain uploads after the policy change.
    late_c = [f for f in await envelopes(store) if f["sequence"] == 3][0]
    for state in ("received", "validated", "applied", "effective"):
        assert (
            await request(
                store,
                "POST",
                "/v2/agents/game/acks",
                ack_body(late_c, state),
                "game-agent",
            )
        ).status_code == 200
    # Batch still fences execution of the dead operation.
    dead = [f for f in await envelopes(store) if f["sequence"] == 4][0]
    assert dead["reason"] == "rejected" and dead["executable"] is False


@pytest.mark.parametrize("kill", ["revoke", "expire_cred", "expire_op"])
async def test_c11_desired_state_outlives_issuer(store, kill):
    gameplay = await request(
        store, "PATCH", "/v2/settings/gameplay/*", patch("c11-desired", 0)
    )
    assert gameplay.status_code == 202
    gate = await request(
        store, "PATCH", "/v2/settings/gate/*", patch("c11-gate", 0, {"mode": "open"})
    )
    assert gate.status_code == 202
    gameplay_id = UUID(gameplay.json()["operationId"])
    frame = [f for f in await envelopes(store) if f["operationId"] == str(gameplay_id)][
        0
    ]
    for state in ("received", "validated", "applied"):
        assert (
            await request(
                store,
                "POST",
                "/v2/agents/game/acks",
                ack_body(frame, state),
                "game-agent",
            )
        ).status_code == 200
    before = await request(store, "GET", "/v2/agents/game/snapshot", role="game-agent")
    assert before.status_code == 200
    if kill == "revoke":
        await sql(
            store,
            "UPDATE credentials SET revoked_at=now() WHERE account_id=%s",
            (store["accounts"]["admin"],),
        )
    elif kill == "expire_cred":
        await sql(
            store,
            "UPDATE credentials SET expires_at=now()-interval '1 second' WHERE account_id=%s",
            (store["accounts"]["admin"],),
        )
    else:
        await sql(
            store,
            "UPDATE operations SET deadline=now()-interval '1 second' WHERE id=%s",
            (gameplay_id,),
        )
    live = await envelopes(store)
    gameplay_live = [f for f in live if f["operationId"] == str(gameplay_id)]
    assert len(gameplay_live) == 1
    assert not gameplay_live[0]["executable"]
    assert gameplay_live[0]["reason"] in ("rejected", "expired", "superseded")
    after = await request(store, "GET", "/v2/agents/game/snapshot", role="game-agent")
    assert after.status_code == 200
    assert after.json()["hash"] == before.json()["hash"]
    assert after.json()["settings"] == before.json()["settings"]
    assert (await request(store, "GET", "/v1/gate", role="game-agent")).json()[
        "mode"
    ] == "open"
    assert (
        await sql(store, "SELECT status FROM operations WHERE id=%s", (gameplay_id,))
    )[0]["status"] in ("applied", "partial")


async def test_c11_snapshot_hash_ignores_row_order(store, monkeypatch):
    import cpv2.delivery

    await request(store, "PATCH", "/v2/settings/gameplay/zeta", patch("order-a"))
    await request(store, "PATCH", "/v2/settings/gameplay/arena", patch("order-b"))
    first = await request(store, "GET", "/v2/agents/game/snapshot", role="game-agent")
    assert first.status_code == 200
    original = cpv2.delivery.rows

    async def flip(conn, query, args=()):
        found = await original(conn, query, args)
        return list(reversed(found)) if "settings_heads" in query else found

    monkeypatch.setattr(cpv2.delivery, "rows", flip)
    second = await request(store, "GET", "/v2/agents/game/snapshot", role="game-agent")
    assert second.status_code == 200
    assert second.json()["hash"] == first.json()["hash"]
    assert [(s["namespace"], s["target"]) for s in second.json()["settings"]] == [
        ("gameplay", "arena"),
        ("gameplay", "zeta"),
    ]


async def test_c11_consumerless_settings_not_expired_on_read(store):
    token = await provision(
        store["admin"],
        {
            "client": {
                "id": "qa",
                "via": "cli",
                "human": True,
                "ceiling": sorted(OWNER_SCOPES),
            },
            "accountId": str(uuid4()),
            "displayName": "qa",
            "ceiling": sorted(OWNER_SCOPES),
            "environment": "qa",
            "backend": "game",
            "resource": "*",
            "grants": [
                {
                    "role": "admin",
                    "environment": "qa",
                    "backend": "game",
                    "resource": "*",
                    "grantor": str(store["accounts"]["owner"]),
                }
            ],
        },
    )
    store["tokens"]["qa-admin"] = token
    accepted = await request(
        store,
        "PATCH",
        "/v2/settings/gameplay/arena",
        dict(patch("qa-only"), environment="qa"),
        role="qa-admin",
    )
    assert accepted.status_code == 202
    operation_id = UUID(accepted.json()["operationId"])
    await sql(
        store,
        "UPDATE operations SET deadline=now()-interval '1 second' WHERE id=%s",
        (operation_id,),
    )
    view = await request(
        store, "GET", "/v2/operations/" + str(operation_id), role="qa-admin"
    )
    assert view.json()["status"] == "accepted"
    assert not await sql(
        store,
        "SELECT * FROM operation_events WHERE operation_id=%s AND status='expired'",
        (operation_id,),
    )
    consumer = await provision(
        store["admin"],
        {
            "client": {
                "id": "qa-game",
                "via": "game",
                "ceiling": sorted(SERVICE_SCOPES),
            },
            "ceiling": sorted(SERVICE_SCOPES),
            "environment": "qa",
            "backend": "game",
            "resource": "*",
            "consumer": {
                "id": "qa-game",
                "generation": str(uuid4()),
                "capabilities": ["settings.gameplay"],
            },
        },
    )
    store["tokens"]["qa-game-agent"] = consumer
    snapshot = await request(
        store, "GET", "/v2/agents/qa-game/snapshot", role="qa-game-agent"
    )
    assert snapshot.status_code == 200
    assert [s for s in snapshot.json()["settings"] if s["target"] == "arena"] != []


async def test_c11_historical_duplicate_beats_generation_check(store):
    await queued(store, "dup-check")
    frame = (await envelopes(store))[0]
    effect = None
    for state in ("received", "validated", "applied", "effective"):
        effect = ack_body(frame, state)
        assert (
            await request(store, "POST", "/v2/agents/game/acks", effect, "game-agent")
        ).status_code == 200
    await sql(store, "UPDATE consumers SET generation=%s WHERE id='game'", (uuid4(),))
    assert (
        await request(store, "POST", "/v2/agents/game/acks", effect, "game-agent")
    ).status_code == 200
    changed = dict(effect, result="apply_failed")
    assert (
        await request(store, "POST", "/v2/agents/game/acks", changed, "game-agent")
    ).status_code == 409


async def test_c11_orphan_rejects_arbitrary_generation(store):
    ops = [await queued(store, f"orphan-{key}") for key in ("a", "b", "c", "d")]
    assert all(o["operationId"] for o in ops)
    new_generation = uuid4()
    await sql(
        store, "UPDATE consumers SET generation=%s WHERE id='game'", (new_generation,)
    )
    frames = await envelopes(store)
    assert len(frames) == 4
    current = dict(ack_body(frames[0], "rejected"), generation=str(new_generation))
    assert (
        await request(store, "POST", "/v2/agents/game/acks", current, "game-agent")
    ).status_code == 200
    historical = ack_body(frames[1], "unknown")
    assert (
        await request(store, "POST", "/v2/agents/game/acks", historical, "game-agent")
    ).status_code == 200
    strange = dict(ack_body(frames[2], "rejected"), generation=str(uuid4()))
    assert (
        await request(store, "POST", "/v2/agents/game/acks", strange, "game-agent")
    ).status_code == 409
    strange_unknown = dict(ack_body(frames[2], "unknown"), generation=str(uuid4()))
    assert (
        await request(
            store, "POST", "/v2/agents/game/acks", strange_unknown, "game-agent"
        )
    ).status_code == 409
    fresh_effect = dict(ack_body(frames[3], "received"), generation=str(new_generation))
    assert (
        await request(store, "POST", "/v2/agents/game/acks", fresh_effect, "game-agent")
    ).status_code == 409


async def test_c11_deadline_rechecked_after_issuer_locks(store, monkeypatch):
    import cpv2.delivery

    op = await queued(store, "short-deadline")
    await sql(
        store,
        "UPDATE operations SET deadline=now()+interval '1 second' WHERE id=%s",
        (UUID(op["operationId"]),),
    )
    original, started = cpv2.delivery.one, False

    async def pause_after_account_lock(conn, query, args=()):
        nonlocal started
        row = await original(conn, query, args)
        if query.startswith("SELECT * FROM accounts WHERE id=") and not started:
            started = True
            await asyncio.sleep(2.5)
        return row

    monkeypatch.setattr(cpv2.delivery, "one", pause_after_account_lock)
    frames = await envelopes(store)
    assert frames[0]["reason"] == "expired" and frames[0]["executable"] is False


async def test_c11_grant_expiry_uses_check_time(store, monkeypatch):
    op = await queued(store, "expiring-grant")
    operation_id = UUID(op["operationId"])
    await sql(
        store,
        "UPDATE role_grants SET expires_at=now()+interval '1 second' WHERE account_id=%s AND revoked_at IS NULL",
        (store["accounts"]["moderator"],),
    )
    holder = await psycopg.AsyncConnection.connect(
        store["admin"], options="-c search_path=control,pg_catalog"
    )
    try:
        await holder.execute(
            "SELECT * FROM operations WHERE id=%s FOR UPDATE", (operation_id,)
        )
        task = asyncio.create_task(envelopes(store))
        await asyncio.sleep(2)
        await holder.execute("ROLLBACK")
        frames = await asyncio.wait_for(task, 10)
    finally:
        await holder.close()
    assert frames[0]["reason"] == "rejected" and frames[0]["executable"] is False
    # Same rule on the authentication path: a lock wait spanning expiry must
    # not resurrect the grant.
    await sql(
        store,
        "UPDATE role_grants SET expires_at=now()+interval '1 second' WHERE account_id=%s AND revoked_at IS NULL",
        (store["accounts"]["builder"],),
    )
    blocker = await psycopg.AsyncConnection.connect(
        store["admin"], options="-c search_path=control,pg_catalog"
    )
    auth_conn = await psycopg.AsyncConnection.connect(
        store["admin"],
        options="-c search_path=control,pg_catalog",
        row_factory=psycopg.rows.dict_row,
    )
    try:
        await blocker.execute(
            "SELECT * FROM accounts WHERE id=%s FOR UPDATE",
            (store["accounts"]["builder"],),
        )
        auth_task = asyncio.create_task(
            authenticate(auth_conn, store["tokens"]["builder"])
        )
        await asyncio.sleep(2)
        await blocker.execute("ROLLBACK")
        identity = await asyncio.wait_for(auth_task, 10)
    finally:
        await blocker.close()
        await auth_conn.close()
    assert identity.grants == []


async def test_c12_unrepresentable_inputs_are_invalid_without_side_effects(store):
    async def counts():
        ops = await sql(store, "SELECT count(*) AS n FROM operations")
        revs = await sql(store, "SELECT count(*) AS n FROM settings_revisions")
        outbox = await sql(store, "SELECT count(*) AS n FROM outbox")
        return ops[0]["n"], revs[0]["n"], outbox[0]["n"]

    before = await counts()
    # A lone surrogate cannot pass through an httpx/json client encoder, so it
    # travels as raw JSON bytes with an escaped surrogate, exactly as a real
    # executor would send it.
    surrogate = (
        '{"idempotencyKey":"surrogate","environment":"prod","backend":"game",'
        '"expectedRevision":0,"patch":{"mode":"open","message":"ok\\ud800tail"}}'
    ).encode()
    response = await store["client"].request(
        "PATCH",
        "/v2/settings/gate/*",
        content=surrogate,
        headers={**headers(store), "content-type": "application/json"},
    )
    assert 400 <= response.status_code < 500, (response.status_code, response.text)
    assert response.status_code != 429
    action = {
        "idempotencyKey": "nul-reason",
        "environment": "prod",
        "backend": "game",
        "consumerId": "game",
        "generation": str(store["generation"]),
        "target": "arena",
        "playerId": str(uuid4()),
        "reason": "bad\x00reason",
        "expiresInSeconds": 60,
    }
    bad = [
        (
            "PATCH",
            "/v2/settings/gate/*",
            patch("nul", 0, {"mode": "open", "message": "a\x00b"}),
        ),
        ("PATCH", "/v2/settings/gameplay/arena", dict(patch("bigrange", 2**63))),
        ("POST", "/v2/actions/moderation.kick", action),
    ]
    for method, path, body in bad:
        response = await request(store, method, path, body)
        assert 400 <= response.status_code < 500, (
            method,
            path,
            response.status_code,
            response.text,
        )
        assert response.status_code != 429
    assert await counts() == before
    invalid = await sql(
        store,
        "SELECT * FROM audit_events WHERE outcome='invalid' AND action IN ('PATCH','POST')",
    )
    assert len(invalid) >= len(bad) + 1
    assert "nul-reason" not in str(await sql(store, "SELECT * FROM operations"))
    # Ordinary non-ASCII text stays representable and is accepted.
    good = await request(
        store,
        "PATCH",
        "/v2/settings/gate/*",
        patch("unicode-ok", 0, {"mode": "open", "message": "миграция ✓"}),
    )
    assert good.status_code == 202, good.text


async def test_c12_import_refuses_a_first_write_committed_during_probe(
    store, tmp_path, monkeypatch
):
    path = tmp_path / "u1.sqlite"
    legacy = _U1(str(path))
    legacy.bootstrap("legacy-test")
    legacy.set_gate("maintenance", "migration", "forwarded-owner", "owner", 0, "one")
    legacy.db.close()
    real_connect = psycopg.AsyncConnection.connect
    release = asyncio.Event()

    async def spy_connect(*args, **kwargs):
        conn = await real_connect(*args, **kwargs)
        original_execute = conn.execute

        async def execute_spy(query, params=()):
            if "LOCK TABLE settings_heads" in str(query):
                await asyncio.wait_for(release.wait(), 30)
            return await original_execute(query, params)

        conn.execute = execute_spy
        return conn

    monkeypatch.setattr(psycopg.AsyncConnection, "connect", spy_connect)
    task = asyncio.create_task(import_u1(store["admin"], path))
    await asyncio.sleep(1)
    first = await request(
        store, "PATCH", "/v2/settings/gameplay/arena", patch("first-write")
    )
    assert first.status_code == 202, first.text
    release.set()
    with pytest.raises(ValueError, match="unused staging"):
        await asyncio.wait_for(task, 30)
    assert not await sql(store, "SELECT * FROM legacy_imports")
    assert (
        await sql(
            store, "SELECT revision FROM settings_heads WHERE namespace='gameplay'"
        )
    )[0]["revision"] == 1


async def test_c12_randomized_delivery_walk_preserves_invariants(store):
    rng = random.Random(20261101)
    consumers = ("game", "workshop")
    states = ("received", "validated", "applied", "effective", "rejected", "unknown")
    valid_statuses = {
        "accepted",
        "received",
        "validated",
        "applied",
        "effective",
        "rejected",
        "expired",
        "unknown",
        "partial",
    }
    seen_outbox = set()
    revoked = False
    replaced = 0
    expired = 0
    prev_snapshot_hash = None
    acked = {state: 0 for state in states}
    denied = 0
    progress = {}
    advance = ("received", "validated", "applied", "effective")

    async def check_invariants():
        for cid in consumers:
            receipts = await sql(
                store,
                "SELECT o.sequence, a.state FROM consumer_acks a "
                "JOIN outbox o ON o.consumer_id=a.consumer_id AND o.sequence=a.sequence "
                "WHERE a.consumer_id=%s",
                (cid,),
            )
            covered = {
                r["sequence"]
                for r in receipts
                if r["state"] in ("received", "rejected", "unknown")
            }
            expect, seq = 0, 1
            while seq in covered:
                expect, seq = seq, seq + 1
            cursor = (
                await sql(
                    store, "SELECT received_cursor FROM consumers WHERE id=%s", (cid,)
                )
            )[0]["received_cursor"]
            assert cursor == expect, (cid, cursor, expect)
            clashes = await sql(
                store,
                "SELECT 1 FROM consumer_acks a JOIN consumer_acks b USING (consumer_id, sequence) "
                "WHERE a.consumer_id=%s AND a.state IN ('applied','effective') "
                "AND b.state='rejected' LIMIT 1",
                (cid,),
            )
            assert not clashes, cid
        rows = await sql(
            store,
            "SELECT consumer_id, sequence, operation_id, payload_hash FROM outbox",
        )
        keys = [(r["consumer_id"], r["sequence"]) for r in rows]
        assert len(set(keys)) == len(keys)
        assert seen_outbox <= {(r["consumer_id"], r["sequence"]) for r in rows}
        seen_outbox.update((r["consumer_id"], r["sequence"]) for r in rows)
        for op in await sql(store, "SELECT id, status FROM operations"):
            assert op["status"] in valid_statuses, op
            agg = await sql(
                store,
                "SELECT DISTINCT a.state FROM consumer_acks a JOIN outbox o "
                "ON o.consumer_id=a.consumer_id AND o.sequence=a.sequence "
                "WHERE o.operation_id=%s",
                (op["id"],),
            )
            have = {r["state"] for r in agg}
            if have & {"applied", "effective"}:
                assert op["status"] not in ("rejected", "expired"), (op, have)
            if have & {"unknown"} and not have & {"applied", "effective"}:
                assert op["status"] != "expired", (op, have)

    async def check_snapshots():
        # Consecutive-read hash stability; called every few steps to stay
        # within the per-route test rate budget (same window other tests use).
        nonlocal prev_snapshot_hash
        current = await request(
            store, "GET", "/v2/agents/game/snapshot", role="game-agent"
        )
        assert current.status_code == 200, (current.status_code, current.text)
        if prev_snapshot_hash is not None:
            assert current.json()["hash"] == prev_snapshot_hash
        prev_snapshot_hash = current.json()["hash"]

    await check_invariants()
    for step in range(60):
        roll = rng.random()
        if roll < 0.30:
            cid = rng.choice(consumers)
            role = "moderator" if not revoked else "admin"
            body = {
                "idempotencyKey": f"walk-{step}",
                "environment": "prod",
                "backend": "game",
                "consumerId": cid,
                "generation": str(store["generation"]),
                "target": "arena",
                "playerId": str(uuid4()),
                "expiresInSeconds": 60,
            }
            response = await request(
                store, "POST", "/v2/actions/moderation.kick", body, role
            )
            assert response.status_code in (202, 403), response.text
        elif roll < 0.65:
            cid = rng.choice(consumers)
            frames = await envelopes(store, cid=cid)
            if frames:
                frames = sorted(frames, key=lambda f: f["sequence"])
                frame = frames[0] if rng.random() < 0.7 else rng.choice(frames)
                key = (cid, frame["sequence"])
                if frame["generation"] != str(store["generation"]):
                    # Retired frame: settle through a documented endpoint
                    # identity with a terminal receipt, never as new work.
                    state = rng.choice(("rejected", "unknown"))
                else:
                    idx = progress.get(key, -1)
                    if idx < 3 and rng.random() < 0.8:
                        state = advance[idx + 1]
                    else:
                        state = rng.choice(states)
                response = await request(
                    store,
                    "POST",
                    f"/v2/agents/{cid}/acks",
                    ack_body(frame, state),
                    cid + "-agent",
                )
                assert response.status_code in (200, 409), response.text
                if response.status_code == 200:
                    acked[state] += 1
                    if state in advance:
                        progress[key] = max(idx, advance.index(state))
                    else:
                        progress[key] = 99
                else:
                    denied += 1
        elif roll < 0.75 and replaced < 3:
            replaced += 1
            store["generation"] = uuid4()
            await sql(
                store,
                "UPDATE consumers SET generation=%s WHERE id IN ('game','workshop')",
                (store["generation"],),
            )
            cid = rng.choice(consumers)
            settled = await envelopes(store, cid=cid)
            if settled:
                old = rng.choice(sorted(settled, key=lambda f: f["sequence"]))
                probe = dict(ack_body(old, "rejected"), generation=str(uuid4()))
                denied_response = await request(
                    store,
                    "POST",
                    f"/v2/agents/{cid}/acks",
                    probe,
                    cid + "-agent",
                )
                assert denied_response.status_code == 409, denied_response.text
                denied += 1
                settle = await request(
                    store,
                    "POST",
                    f"/v2/agents/{cid}/acks",
                    ack_body(old, "unknown"),
                    cid + "-agent",
                )
                assert settle.status_code == 200, settle.text
                acked["unknown"] += 1
                progress[(cid, old["sequence"])] = 99
        elif roll < 0.85:
            open_ops = await sql(
                store, "SELECT id FROM operations WHERE status='accepted' LIMIT 5"
            )
            if open_ops:
                await sql(
                    store,
                    "UPDATE operations SET deadline=now()-interval '1 second' WHERE id=%s",
                    (rng.choice(open_ops)["id"],),
                )
                expired += 1
        elif roll < 0.95 and not revoked:
            revoked = True
            await sql(
                store,
                "UPDATE credentials SET revoked_at=now() WHERE account_id=%s",
                (store["accounts"]["moderator"],),
            )
        else:
            frames = await envelopes(store, cid=rng.choice(consumers))
            assert all(
                f["executable"] is False or f["payload"] is not None for f in frames
            )
        await check_invariants()
        if step % 5 == 0:
            await check_snapshots()
    if acked["rejected"] + acked["unknown"] == 0:
        # Deterministic tail: the frame at the cursor settles terminally on
        # first contact, so the walk always exercises terminal receipts.
        cid = rng.choice(consumers)
        await queued(store, "walk-tail", "admin", cid)
        cursor = (
            await sql(
                store, "SELECT received_cursor FROM consumers WHERE id=%s", (cid,)
            )
        )[0]["received_cursor"]
        tail = [
            f for f in await envelopes(store, cid=cid) if f["sequence"] == cursor + 1
        ][0]
        response = await request(
            store,
            "POST",
            f"/v2/agents/{cid}/acks",
            ack_body(tail, "rejected"),
            cid + "-agent",
        )
        assert response.status_code == 200, response.text
        acked["rejected"] += 1
        await check_invariants()
    # The seed must exercise every operator: issuing, each ack outcome class,
    # replacement, expiry and revocation. Otherwise the walk proves nothing.
    assert replaced == 3 and expired >= 1 and revoked
    assert acked["received"] >= 1 and acked["applied"] >= 1
    assert acked["rejected"] + acked["unknown"] >= 1
    assert denied >= 1


async def test_c13_epoch_only_rotation_fences_frames(store):
    accepted = await request(
        store, "PATCH", "/v2/settings/gameplay/arena", patch("epoch-fence")
    )
    assert accepted.status_code == 202, accepted.text
    operation_id = accepted.json()["operationId"]
    assert (await envelopes(store))[0]["executable"] is True
    await sql(store, "UPDATE consumers SET epoch=%s WHERE id='game'", (uuid4(),))
    stale = (await envelopes(store))[0]
    assert stale["operationId"] == operation_id
    assert stale["reason"] == "rejected" and stale["executable"] is False
    assert stale["payload"] is None
    status = (
        await sql(
            store,
            "SELECT status FROM operations WHERE id=%s",
            (UUID(operation_id),),
        )
    )[0]["status"]
    assert status == "accepted", "a stale epoch must not reject the shared operation"
    workshop = (await envelopes(store, cid="workshop"))[0]
    assert workshop["executable"] is True and workshop["reason"] is None


async def test_c13_queued_owner_requires_interactive_via(store):
    token = await provision(
        store["admin"],
        {
            "accountId": str(store["accounts"]["owner"]),
            "displayName": "owner",
            "client": {
                "id": "owner-discord",
                "via": "discord",
                "human": True,
                "ceiling": sorted(OWNER_SCOPES),
            },
            "ceiling": sorted(OWNER_SCOPES),
            "environment": "prod",
            "backend": "game",
            "resource": "*",
            "grants": [
                {
                    "role": "admin",
                    "environment": "prod",
                    "backend": "game",
                    "resource": "*",
                    "grantor": str(store["accounts"]["admin"]),
                }
            ],
        },
    )
    store["tokens"]["owner-discord"] = token
    async with store["app"].state.db.transaction() as conn:
        assert (await authenticate(conn, token)).owner is False
    accepted = await request(
        store,
        "PATCH",
        "/v2/settings/gameplay/arena",
        patch("discord-owner"),
        "owner-discord",
    )
    assert accepted.status_code == 202, accepted.text
    await sql(
        store,
        "UPDATE role_grants SET expires_at=now()-interval '1 second' WHERE account_id=%s",
        (store["accounts"]["owner"],),
    )
    frame = (await envelopes(store))[0]
    assert frame["operationId"] == accepted.json()["operationId"]
    assert frame["reason"] == "rejected" and frame["executable"] is False


async def test_c13_owner_challenge_without_credentials_is_4xx(store):
    await sql(store, "DELETE FROM owner_credentials")
    response = await request(
        store,
        "POST",
        "/v2/owner/challenges",
        {
            "method": "PATCH",
            "path": "/v2/settings/gameplay/arena",
            "body": patch("no-credential"),
        },
        "owner",
    )
    assert 400 <= response.status_code < 500, (response.status_code, response.text)
    assert response.status_code != 429
    assert response.json()["error"] == "owner_approval_required"


async def test_c13_surrogate_dict_key_is_invalid_without_side_effects(store):
    async def counts():
        ops = await sql(store, "SELECT count(*) AS n FROM operations")
        revs = await sql(store, "SELECT count(*) AS n FROM settings_revisions")
        return ops[0]["n"], revs[0]["n"]

    before = await counts()
    surrogate = (
        '{"idempotencyKey":"key-surrogate","environment":"prod","backend":"game",'
        '"expectedRevision":0,"patch":{"mode":"open","ok\\ud800tail":"x"}}'
    ).encode()
    response = await store["client"].request(
        "PATCH",
        "/v2/settings/gate/*",
        content=surrogate,
        headers={**headers(store), "content-type": "application/json"},
    )
    assert 400 <= response.status_code < 500, (response.status_code, response.text)
    assert response.status_code != 429
    assert await counts() == before
    invalid = await sql(
        store, "SELECT * FROM audit_events WHERE outcome='invalid' AND action='PATCH'"
    )
    assert len(invalid) >= 1


async def test_c14_malformed_owner_assertion_is_4xx(store):
    path = "/v2/settings/ai-limits/global"
    body = patch(
        "c14-malformed",
        value={"sessions": {"12345678-1234-1234-1234-1234567890ab": 1000}},
    )
    proof = json.loads(
        (await assertion(store, "PATCH", path, body))["X-CP-Owner-Assertion"]
    )
    cases = [
        {**proof, "challengeId": 12345},
        {**proof, "challengeId": None},
        {**proof, "credential": "not-a-dict"},
        {**proof, "credential": {**proof["credential"], "id": ["not", "a", "string"]}},
        ["not", "a", "dict"],
    ]
    credential = proof["credential"]
    for field in ("rawId", "type", "response"):
        cases.append({**proof, "credential": {**credential, field: 123}})
    for field in ("clientDataJSON", "authenticatorData", "signature", "userHandle"):
        cases.append(
            {
                **proof,
                "credential": {
                    **credential,
                    "response": {**credential["response"], field: 123},
                },
            }
        )
    for field in ("challengeId", "credential"):
        cases.append({key: value for key, value in proof.items() if key != field})
    for bad in cases:
        response = await request(
            store,
            "PATCH",
            path,
            body,
            "owner",
            {"X-CP-Owner-Assertion": json.dumps(bad)},
        )
        assert 400 <= response.status_code < 500, (
            bad,
            response.status_code,
            response.text,
        )
        assert response.json()["error"] == "invalid_owner_assertion"


async def test_c14_operation_outbox_lookup_uses_operation_index(store):
    cred = await sql(
        store, "SELECT id, client_id FROM credentials WHERE kind='service' LIMIT 1"
    )
    await sql(
        store,
        "INSERT INTO operations(id, credential_id, client_id, via, kind, target, resource,"
        " environment, backend, request_hash, idempotency_key, required_scope, deadline, status)"
        " SELECT gen_random_uuid(), %(cid)s, %(cli)s, 'game', 'settings.gameplay.write',"
        " 'arena', '*', 'prod', 'game', 'seed', 'c14seed-'||g, 'settings.gameplay.write',"
        " now()+interval '1 day', 'accepted' FROM generate_series(1, 2000) g",
        {"cid": cred[0]["id"], "cli": cred[0]["client_id"]},
    )
    await sql(
        store,
        "INSERT INTO outbox(consumer_id, sequence, epoch, operation_id, generation, payload, payload_hash)"
        " SELECT v.c, 1000000+o.rn, gen_random_uuid(), o.id, gen_random_uuid(), '{}'::jsonb, 'seed'"
        " FROM (SELECT id, row_number() OVER () AS rn FROM operations"
        " WHERE idempotency_key LIKE 'c14seed-%%') o CROSS JOIN (VALUES ('game'), ('workshop')) v(c)",
    )
    await sql(store, "ANALYZE outbox")
    target = (
        await sql(
            store,
            "SELECT id FROM operations WHERE idempotency_key='c14seed-1'",
        )
    )[0]["id"]
    plan = await sql(
        store,
        "EXPLAIN SELECT o.consumer_id,COALESCE((SELECT state FROM consumer_acks a"
        " WHERE a.consumer_id=o.consumer_id AND a.sequence=o.sequence ORDER BY CASE state"
        " WHEN 'unknown' THEN 6 WHEN 'rejected' THEN 5 WHEN 'effective' THEN 4"
        " WHEN 'applied' THEN 3 WHEN 'validated' THEN 2 ELSE 1 END DESC LIMIT 1),"
        "'accepted') AS state FROM outbox o WHERE operation_id=%s",
        (target,),
    )
    text = "\n".join(row["QUERY PLAN"] for row in plan)
    print(text)
    assert "outbox_operation" in text, text


async def test_c16_sse_reconnect_replays_unacknowledged_frame(store):
    from starlette.requests import Request

    await queued(store, "c16-reconnect")
    frame = (await envelopes(store))[0]
    app = store["app"]
    token = store["tokens"]["game-agent"]
    async with app.state.db.transaction() as conn:
        identity = await authenticate(conn, token)
    endpoint = next(
        r.endpoint for r in app.routes if r.path == "/v2/agents/{cid}/events"
    )
    req = Request(
        {
            "type": "http",
            "headers": [
                (b"last-event-id", f"{frame['epoch']}:{frame['sequence']}".encode())
            ],
        }
    )
    req.state.identity, req.state.token = identity, token
    response = await endpoint("game", req, UUID(frame["epoch"]), 0)
    try:
        chunk = await anext(response.body_iterator)
        assert f"id: {frame['epoch']}:{frame['sequence']}" in chunk
    finally:
        await response.body_iterator.aclose()


def test_c16_health_budget_is_independent():
    from cpv2.app import Limits

    limiter = Limits(budget=1)
    limiter.check("authenticated")
    limiter.check("health", global_count=False)
    with pytest.raises(Problem, match="rate_limit"):
        limiter.check("authenticated-again")


async def test_c16_nonfinite_patch_is_invalid(store):
    response = await store["client"].patch(
        "/v2/settings/gameplay/*",
        headers={
            "authorization": "Bearer " + store["tokens"]["admin"],
            "content-type": "application/json",
        },
        content='{"idempotencyKey":"c16-nan","environment":"prod","backend":"game","expectedRevision":0,"patch":{"match":{"maxPlayers":NaN}}}',
    )
    assert response.status_code == 422, response.text


async def test_c17_nonhuman_session_cannot_delegate(store):
    await sql(store, "UPDATE clients SET human=false WHERE id='admin'")
    response = await request(
        store,
        "POST",
        "/v2/delegations",
        {
            "idempotencyKey": "c17-nonhuman",
            "resource": "arena",
            "scopes": ["maps.edit"],
            "expiresInSeconds": 60,
        },
    )
    assert response.status_code == 403, response.text
    assert response.json()["error"] == "delegation_not_allowed"
    assert not await sql(store, "SELECT 1 FROM credentials WHERE kind='delegation'")


async def test_c17_auth_locks_parent_before_delegation(store, monkeypatch):
    import cpv2.auth as auth

    response = await request(
        store,
        "POST",
        "/v2/delegations",
        {
            "idempotencyKey": "c17-locks",
            "resource": "arena",
            "scopes": ["maps.edit"],
            "expiresInSeconds": 60,
        },
    )
    assert response.status_code == 201, response.text
    token = response.json()["token"]
    child = (
        await sql(
            store,
            "SELECT id,parent_id FROM credentials WHERE verifier=%s",
            (verifier(token),),
        )
    )[0]
    locks = []
    original = auth.one

    async def observe(conn, query, params=()):
        if "FROM credentials WHERE id=%s FOR SHARE" in query:
            locks.append(params[0])
        return await original(conn, query, params)

    monkeypatch.setattr(auth, "one", observe)
    async with store["app"].state.db.transaction() as conn:
        await authenticate(conn, token)
    assert locks == [child["parent_id"], child["id"]]


async def test_c18_nan_challenge_body_is_invalid(store):
    response = await store["client"].post(
        "/v2/owner/challenges",
        headers={
            "authorization": "Bearer " + store["tokens"]["owner"],
            "content-type": "application/json",
        },
        content='{"method":"PATCH","path":"/v2/settings/gameplay/arena","body":{"idempotencyKey":"c18-nan","environment":"prod","backend":"game","expectedRevision":0,"patch":{"match":{"maxPlayers":NaN}}}}',
    )
    assert response.status_code == 422, response.text


async def test_c18_reprovision_updates_client_ceiling(store):
    base = {
        "client": {"id": "c18-re", "via": "game", "ceiling": ["gate:read"]},
        "ceiling": ["gate:read"],
        "environment": "prod",
        "backend": "game",
        "resource": "*",
    }
    first = await provision(store["admin"], base)
    me = await store["client"].get(
        "/v2/me", headers={"authorization": "Bearer " + first}
    )
    assert me.status_code == 200, me.text
    assert me.json()["ceiling"] == ["gate:read"]
    second = await provision(
        store["admin"],
        {
            "client": {
                "id": "c18-re",
                "via": "game",
                "ceiling": sorted(SERVICE_SCOPES),
            },
            "ceiling": sorted(SERVICE_SCOPES),
            "environment": "prod",
            "backend": "game",
            "resource": "*",
        },
    )
    me = await store["client"].get(
        "/v2/me", headers={"authorization": "Bearer " + second}
    )
    assert me.status_code == 200, me.text
    assert me.json()["ceiling"] == sorted(SERVICE_SCOPES), me.text
    row = await sql(store, "SELECT ceiling FROM clients WHERE id='c18-re'")
    assert row[0]["ceiling"] == sorted(SERVICE_SCOPES)


async def test_c18_provision_sink_gets_bearer_before_commit(store, tmp_path):
    import cpv2.admin as admin

    path = tmp_path / "bearer"
    seen = {}

    def sink(token):
        path.write_text(token + "\n")
        seen["token"] = token

    token = await admin.provision(
        store["admin"],
        {
            "client": {
                "id": "c18-sink",
                "via": "game",
                "ceiling": sorted(SERVICE_SCOPES),
            },
            "ceiling": sorted(SERVICE_SCOPES),
            "environment": "prod",
            "backend": "game",
            "resource": "*",
        },
        bearer_sink=sink,
    )
    assert token == seen["token"] == path.read_text().strip()
    me = await store["client"].get(
        "/v2/me", headers={"authorization": "Bearer " + token}
    )
    assert me.status_code == 200, me.text


async def test_c18_provision_bearer_write_failure_rolls_back(
    store, tmp_path, monkeypatch
):
    import cpv2.admin as admin

    monkeypatch.setattr(admin.secrets, "token_urlsafe", lambda n: "c18sink")
    path = tmp_path / "bearer"

    def sink(token):
        path.write_text(token + "\n")
        raise OSError("c18 disk full")

    with pytest.raises(OSError, match="disk full"):
        await admin.provision(
            store["admin"],
            {
                "client": {
                    "id": "c18-rollback",
                    "via": "game",
                    "ceiling": sorted(SERVICE_SCOPES),
                },
                "ceiling": sorted(SERVICE_SCOPES),
                "environment": "prod",
                "backend": "game",
                "resource": "*",
            },
            bearer_sink=sink,
        )
    assert path.read_text() == "cp2_c18sink\n"
    assert not await sql(
        store,
        "SELECT 1 FROM credentials WHERE verifier=%s",
        (verifier("cp2_c18sink"),),
    )


async def test_c18_protected_scope_rechecked_at_delivery(store):
    path = "/v2/settings/ai-limits/global"
    body = patch(
        "c18-protected",
        value={"sessions": {"12345678-1234-1234-1234-1234567890ab": 1000}},
    )
    proof = await assertion(store, "PATCH", path, body)
    response = await request(store, "PATCH", path, body, "owner", proof)
    assert response.status_code == 202, response.text
    # Narrow the owner client registration: protected-write goes away while
    # ordinary gameplay-write stays. No grant, epoch or credential change.
    narrow = sorted(set(OWNER_SCOPES) - {"settings.protected.write"})
    await provision(
        store["admin"],
        {
            "client": {"id": "owner", "via": "ui", "human": True, "ceiling": narrow},
            "accountId": str(store["accounts"]["owner"]),
            "displayName": "owner",
            "ceiling": narrow,
            "environment": "prod",
            "backend": "game",
            "resource": "*",
        },
    )
    async with store["app"].state.db.transaction() as conn:
        op = await one(
            conn,
            "SELECT * FROM operations WHERE id=%s",
            (response.json()["operationId"],),
        )
        assert op["required_scope"] == (
            "settings.gameplay.write,settings.protected.write"
        ), op["required_scope"]
        assert await delivery.valid_operation(conn, op) == "rejected"


async def test_c19_both_scopes_rechecked_at_delivery(store):
    path = "/v2/settings/ai-limits/global"
    body = patch(
        "c19-both",
        value={"sessions": {"12345678-1234-1234-1234-1234567890ab": 1000}},
    )
    proof = await assertion(store, "PATCH", path, body)
    response = await request(store, "PATCH", path, body, "owner", proof)
    assert response.status_code == 202, response.text
    # Narrow the owner client registration the other way: ordinary
    # gameplay-write goes away while protected-write stays. No grant,
    # epoch or credential change.
    narrow = sorted(set(OWNER_SCOPES) - {"settings.gameplay.write"})
    await provision(
        store["admin"],
        {
            "client": {"id": "owner", "via": "ui", "human": True, "ceiling": narrow},
            "accountId": str(store["accounts"]["owner"]),
            "displayName": "owner",
            "ceiling": narrow,
            "environment": "prod",
            "backend": "game",
            "resource": "*",
        },
    )
    async with store["app"].state.db.transaction() as conn:
        op = await one(
            conn,
            "SELECT * FROM operations WHERE id=%s",
            (response.json()["operationId"],),
        )
        assert set(op["required_scope"].split(",")) == {
            "settings.gameplay.write",
            "settings.protected.write",
        }, op["required_scope"]
        assert await delivery.valid_operation(conn, op) == "rejected"


WORKSHOP_ACTOR = {"draslId": "e10438e4797b49718cfecec6a8fa171b", "name": "Nether"}


def workshop_body(store, **overrides):
    body = {
        "idempotencyKey": "ws-" + uuid4().hex,
        "environment": "prod",
        "backend": "game",
        "consumerId": "workshop",
        "generation": str(store["generation"]),
        "target": "*",
        "actor": dict(WORKSHOP_ACTOR),
        "expiresInSeconds": 60,
    }
    body.update(overrides)
    return body


async def workshop_outbox(store, operation_id):
    return await sql(
        store,
        "SELECT payload, payload_hash FROM outbox WHERE operation_id=%s",
        (operation_id,),
    )


async def bind(
    store, role, drasl=WORKSHOP_ACTOR["draslId"], name=WORKSHOP_ACTOR["name"]
):
    player = str(UUID(hex=drasl))
    await sql(
        store,
        "INSERT INTO account_identities(account_id, issuer, subject, player_id,"
        " current_name, generation) VALUES(%s, 'drasl', %s, %s, %s, 1)",
        (store["accounts"][role], str(store["accounts"][role]), player, name),
    )


async def test_workshop_message_producer_round_trip(store):
    await bind(store, "moderator")
    body = workshop_body(store, message="hi")
    response = await request(store, "POST", "/v2/workshop/message", body, "moderator")
    assert response.status_code == 202, response.text
    rows = await workshop_outbox(store, response.json()["operationId"])
    assert len(rows) == 1
    payload = rows[0]["payload"]
    assert payload == {
        "kind": "message",
        "target": "*",
        "actor": WORKSHOP_ACTOR,
        "message": "hi",
    }
    # Same canonical JSON the Workshop cp_client verifies its frames with.
    expected = hashlib.sha256(
        json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    ).hexdigest()
    assert rows[0]["payload_hash"] == expected
    frames = await envelopes(store, cid="workshop")
    assert frames[-1]["payloadHash"] == expected
    assert frames[-1]["payload"] == payload


async def test_workshop_kinds_produce_exact_consumer_payloads(store):
    await bind(store, "admin")
    member_entries = [
        {"draslId": "f" * 32, "name": "Stranger", "role": "lead"},
    ]
    cases = [
        (
            "members",
            {"members": member_entries},
            {
                "kind": "members",
                "target": "*",
                "grantor": WORKSHOP_ACTOR,
                "members": member_entries,
            },
        ),
        (
            "message",
            {"message": "hello"},
            {
                "kind": "message",
                "target": "*",
                "actor": WORKSHOP_ACTOR,
                "message": "hello",
            },
        ),
        (
            "wake",
            {},
            {"kind": "wake", "target": "*", "actor": WORKSHOP_ACTOR},
        ),
        (
            "cancel",
            {},
            {"kind": "cancel", "target": "*", "actor": WORKSHOP_ACTOR},
        ),
        (
            "release.select",
            {"release": "v9.0.0", "record": {"release": "v9.0.0"}},
            {
                "kind": "release.select",
                "target": "*",
                "actor": WORKSHOP_ACTOR,
                "release": "v9.0.0",
                "record": {"release": "v9.0.0"},
            },
        ),
    ]
    for kind, fields, payload in cases:
        response = await request(
            store,
            "POST",
            f"/v2/workshop/{kind}",
            workshop_body(store, **fields),
            "admin",
        )
        assert response.status_code == 202, (kind, response.text)
        rows = await workshop_outbox(store, response.json()["operationId"])
        assert len(rows) == 1, kind
        assert rows[0]["payload"] == payload, kind


async def test_workshop_invalid_operations_rejected(store):
    cases = [
        ("message", {"actor": {"draslId": "zz", "name": "Nether"}}, "moderator"),
        (
            "message",
            {"actor": {"draslId": WORKSHOP_ACTOR["draslId"], "name": "x"}},
            "moderator",
        ),
        ("message", {"message": "x" * 201}, "moderator"),
        ("message", {"message": "hi §4there"}, "moderator"),
        ("message", {"message": None}, "moderator"),
        ("members", {"members": "nope"}, "admin"),
        ("members", {"members": []}, "admin"),
        (
            "members",
            {"members": [{"draslId": "f" * 32, "name": "S", "role": "x"}]},
            "admin",
        ),
        (
            "members",
            {"members": [{"draslId": "f" * 32, "name": "Stranger", "extra": 1}]},
            "admin",
        ),
        ("wake", {"actor": {"draslId": WORKSHOP_ACTOR["draslId"]}}, "moderator"),
        ("release.select", {"release": "9.0.0"}, "admin"),
        (
            "release.select",
            {"release": "v9.0.0", "record": {"release": "v9.0.1"}},
            "admin",
        ),
    ]
    for kind, fields, role in cases:
        body = workshop_body(store, **fields)
        response = await request(store, "POST", f"/v2/workshop/{kind}", body, role)
        assert response.status_code == 422, (kind, fields, response.text)


async def test_workshop_unknown_kind_rejected(store):
    response = await request(
        store, "POST", "/v2/workshop/checkpoint", workshop_body(store), "admin"
    )
    assert response.status_code == 404


WORKSHOP_COPY = "e10438e4-797b-4971-88cf-ecec6a8fa171"
WORKSHOP_MAP_CREATE = {
    "mapOp": "map-create",
    "args": {
        "mapId": "arena1",
        "name": "Arena 1",
        "supportedModes": ["tdm", "room"],
        "expectedRevision": 3,
        "sessionId": "0f0d9a51-3f43-4f8d-9a37-0d6a3b1d2c4e",
    },
}
WORKSHOP_MAP_PROPERTIES = {
    "mapOp": "map-properties",
    "args": {
        "mapId": "arena1",
        "name": "Arena One",
        "workingCopyId": WORKSHOP_COPY,
        "expectedRevision": 4,
    },
}


def map_op(base, **changes):
    """A map operation body with some arguments replaced (None drops one)."""
    args = {**base["args"], **changes}
    return {**base, "args": {k: v for k, v in args.items() if v is not None}}


async def test_workshop_remaining_kinds_produce_exact_consumer_payloads(store):
    await bind(store, "moderator")
    await bind(store, "admin", "f" * 32, "Stranger")
    await bind(store, "owner", "b" * 32, "Helper")
    helper = {"draslId": "b" * 32, "name": "Helper"}
    stranger = {"draslId": "f" * 32, "name": "Stranger"}
    cases = [
        ("moderator", "map", WORKSHOP_MAP_CREATE, WORKSHOP_ACTOR),
        ("moderator", "map", WORKSHOP_MAP_PROPERTIES, WORKSHOP_ACTOR),
        ("moderator", "sessions", {"offset": 10, "limit": 25}, WORKSHOP_ACTOR),
        ("moderator", "sessions", {"offset": 0}, WORKSHOP_ACTOR),
        (
            "owner",
            "ai-key",
            {"provider": "openrouter", "key": "sk-" + "x" * 20},
            helper,
        ),
        (
            "owner",
            "ai-key",
            {"provider": "custom-1", "key": None},
            helper,
        ),
        (
            "admin",
            "mode",
            {"profile": "game", "expectedRevision": 7, "recover": True},
            stranger,
        ),
        (
            "admin",
            "mode",
            {
                "profile": "workshop",
                "expectedRevision": 7,
                "session": "new",
                "maps": ["arena1", "hub"],
            },
            stranger,
        ),
        # Linear history (workshop#65): a stale caller may still send
        # `branches`; it is accepted for shape and dropped from the payload.
        (
            "admin",
            "mode",
            {
                "profile": "workshop",
                "expectedRevision": 7,
                "session": "new",
                "maps": ["arena1", "hub"],
                "branches": {"arena1": "draft", "hub": "wip"},
            },
            stranger,
            {"branches": {"arena1": "draft", "hub": "wip"}},
        ),
        (
            "admin",
            "mode",
            {
                "profile": "test",
                "expectedRevision": 7,
                "candidateId": "a" * 32,
                "modeId": "tdm",
            },
            stranger,
        ),
    ]
    for role, kind, fields, actor, *rest in cases:
        body = workshop_body(store, actor=dict(actor), **fields)
        response = await request(store, "POST", f"/v2/workshop/{kind}", body, role)
        assert response.status_code == 202, (kind, fields, response.text)
        rows = await workshop_outbox(store, response.json()["operationId"])
        assert len(rows) == 1, kind
        expected = {"kind": kind, "target": "*", "actor": dict(actor)}
        if kind == "sessions" and "limit" not in fields:
            expected.update({**fields, "limit": 100})
        else:
            expected.update(fields)
        for dropped in rest:
            for key in dropped:
                expected.pop(key, None)
        assert rows[0]["payload"] == expected, kind
        # Same canonical JSON the Workshop cp_client verifies its frames with.
        assert rows[0]["payload_hash"] == digest(expected), kind


async def test_workshop_remaining_kinds_reject_bad_shapes(store):
    await bind(store, "moderator")
    await bind(store, "admin", "f" * 32, "Stranger")
    await bind(store, "owner", "b" * 32, "Helper")
    copy = "e10438e4-797b-4971-88cf-ecec6a8fa171"
    key = "sk-" + "x" * 20
    cases = [
        ("moderator", "map", {**WORKSHOP_MAP_CREATE, "mapOp": "map-rename"}),
        ("moderator", "map", map_op(WORKSHOP_MAP_CREATE, mapId="hub")),
        ("moderator", "map", map_op(WORKSHOP_MAP_CREATE, mapId="Arena!")),
        ("moderator", "map", map_op(WORKSHOP_MAP_CREATE, name=" §bad")),
        ("moderator", "map", map_op(WORKSHOP_MAP_CREATE, supportedModes=[])),
        (
            "moderator",
            "map",
            map_op(WORKSHOP_MAP_CREATE, supportedModes=["tdm", "nope"]),
        ),
        (
            "moderator",
            "map",
            map_op(WORKSHOP_MAP_CREATE, supportedModes=["tdm", "tdm"]),
        ),
        # Unhashable elements must 422, not 500 (set() runs on validated strs).
        ("moderator", "map", map_op(WORKSHOP_MAP_CREATE, supportedModes=[[]])),
        ("moderator", "map", map_op(WORKSHOP_MAP_CREATE, sessionId="nope")),
        ("moderator", "map", map_op(WORKSHOP_MAP_CREATE, sessionId=None)),
        ("moderator", "map", map_op(WORKSHOP_MAP_PROPERTIES, workingCopyId="nope")),
        ("moderator", "map", map_op(WORKSHOP_MAP_PROPERTIES, expectedRevision=-1)),
        ("moderator", "map", map_op(WORKSHOP_MAP_PROPERTIES, extra=1)),
        ("moderator", "map", {**WORKSHOP_MAP_CREATE, "target": "arena1"}),
        ("moderator", "map", {"mapOp": "snapshots"}),
        ("moderator", "map", {"mapOp": "snapshots", "args": {"mapId": "A"}}),
        (
            "moderator",
            "map",
            {"mapOp": "commit", "args": {"mapId": "arena1", "note": "x"}},
        ),
        (
            "moderator",
            "map",
            {
                "mapOp": "commit",
                "args": {
                    "mapId": "arena1",
                    "workingCopyId": WORKSHOP_COPY,
                    "expectedHead": None,
                    "note": "  ",
                },
            },
        ),
        (
            "moderator",
            "map",
            {"mapOp": "snapshot-delete", "args": {"mapId": "arena1", "name": "main"}},
        ),
        (
            "moderator",
            "map",
            {"mapOp": "publish", "args": {"candidateId": "a" * 32, "force": 1}},
        ),
        (
            "moderator",
            "map",
            {
                "mapOp": "publish",
                "args": {
                    "candidateId": "a" * 32,
                    "resolutions": {"../etc/passwd": "ours"},
                },
            },
        ),
        (
            "moderator",
            "map",
            {
                "mapOp": "publish",
                "args": {
                    "candidateId": "a" * 32,
                    "resolutions": {"map.json": "mine"},
                },
            },
        ),
        ("moderator", "map", {"mapOp": "reject", "args": {"candidateId": "A" * 32}}),
        ("moderator", "map", {"mapOp": "limbo-export", "args": {"versionDigest": "1"}}),
        ("moderator", "sessions", {"offset": -1}),
        ("moderator", "sessions", {"offset": True}),
        ("moderator", "sessions", {"offset": 0, "limit": 101}),
        ("moderator", "sessions", {"offset": 0, "target": "arena1"}),
        ("owner", "ai-key", {"provider": "openrouter"}),
        ("owner", "ai-key", {"provider": "openrouter", "key": "short"}),
        ("owner", "ai-key", {"provider": "gateway", "key": key}),
        ("owner", "ai-key", {"provider": "OPENROUTER", "key": key}),
        ("owner", "ai-key", {"provider": "openrouter", "key": key, "target": "hub"}),
        ("admin", "mode", {"profile": "game"}),
        (
            "admin",
            "mode",
            {"profile": "workshop", "expectedRevision": 1, "recover": True},
        ),
        (
            "admin",
            "mode",
            {"profile": "workshop", "expectedRevision": 1, "session": "later"},
        ),
        (
            "admin",
            "mode",
            {
                "profile": "workshop",
                "expectedRevision": 1,
                "session": "new",
                "maps": ["arena1", "arena1"],
            },
        ),
        # Unhashable entries must 422, not 500 (set() runs on validated strs).
        (
            "admin",
            "mode",
            {
                "profile": "workshop",
                "expectedRevision": 1,
                "session": "new",
                "maps": [{}],
            },
        ),
        (
            "admin",
            "mode",
            {
                "profile": "workshop",
                "expectedRevision": 1,
                "session": "new",
                "maps": ["arena1"],
                "branches": {"other": "draft"},
            },
        ),
        (
            "admin",
            "mode",
            {
                "profile": "workshop",
                "expectedRevision": 1,
                "session": "new",
                "maps": ["arena1"],
                "branches": {"arena1": "main"},
            },
        ),
        (
            "admin",
            "mode",
            {
                "profile": "workshop",
                "expectedRevision": 1,
                "session": "resume",
                "sessionId": "nope",
            },
        ),
        (
            "admin",
            "mode",
            {"profile": "game", "expectedRevision": 1, "sessionId": copy},
        ),
        ("admin", "mode", {"profile": "test", "expectedRevision": 1}),
        (
            "admin",
            "mode",
            {
                "profile": "test",
                "expectedRevision": 1,
                "candidateId": "a" * 32,
                "modeId": "nope",
            },
        ),
        (
            "admin",
            "mode",
            {"profile": "game", "expectedRevision": 1, "target": "arena1"},
        ),
    ]
    for role, kind, fields in cases:
        body = workshop_body(store, **fields)
        response = await request(store, "POST", f"/v2/workshop/{kind}", body, role)
        assert response.status_code == 422, (kind, fields, response.text)


async def test_workshop_remaining_kinds_rbac(store):
    await bind(store, "builder")
    await bind(store, "moderator", "c" * 32, "Mod")
    await bind(store, "admin", "f" * 32, "Stranger")
    await bind(store, "owner", "b" * 32, "Helper")
    mod = {"draslId": "c" * 32, "name": "Mod"}
    stranger = {"draslId": "f" * 32, "name": "Stranger"}
    helper = {"draslId": "b" * 32, "name": "Helper"}
    # Builders page drafts only; moderators handle map drafts; mode is admin;
    # keys are founders only.
    assert (
        await request(
            store,
            "POST",
            "/v2/workshop/sessions",
            workshop_body(store, offset=0),
            "builder",
        )
    ).status_code == 202
    for kind, fields in (
        ("map", WORKSHOP_MAP_CREATE),
        ("mode", {"profile": "game", "expectedRevision": 0}),
        ("ai-key", {"provider": "openrouter", "key": "sk-" + "x" * 20}),
    ):
        assert (
            await request(
                store,
                "POST",
                f"/v2/workshop/{kind}",
                workshop_body(store, **fields),
                "builder",
            )
        ).status_code == 403
    assert (
        await request(
            store,
            "POST",
            "/v2/workshop/map",
            workshop_body(store, actor=mod, **WORKSHOP_MAP_CREATE),
            "moderator",
        )
    ).status_code == 202
    for kind, fields in (
        ("mode", {"profile": "game", "expectedRevision": 0}),
        ("ai-key", {"provider": "openrouter", "key": "sk-" + "x" * 20}),
    ):
        assert (
            await request(
                store,
                "POST",
                f"/v2/workshop/{kind}",
                workshop_body(store, **fields),
                "moderator",
            )
        ).status_code == 403
    assert (
        await request(
            store,
            "POST",
            "/v2/workshop/mode",
            workshop_body(store, actor=stranger, profile="game", expectedRevision=0),
            "admin",
        )
    ).status_code == 202
    assert (
        await request(
            store,
            "POST",
            "/v2/workshop/ai-key",
            workshop_body(store, provider="openrouter", key="sk-" + "x" * 20),
            "admin",
        )
    ).status_code == 403
    key_body = workshop_body(
        store, actor=helper, provider="openrouter", key="sk-" + "x" * 20
    )
    response = await request(store, "POST", "/v2/workshop/ai-key", key_body, "owner")
    assert response.status_code == 202, response.text
    # Key material never reaches operation results or the audit trail.
    operation = await request(
        store, "GET", f"/v2/operations/{response.json()['operationId']}", role="owner"
    )
    assert operation.status_code == 200, operation.text
    assert "sk-" not in json.dumps(operation.json()["result"])
    audit = await sql(
        store,
        "SELECT detail FROM audit_events WHERE action='workshop.ai-key' ORDER BY sequence DESC LIMIT 1",
    )
    assert "sk-" not in json.dumps(audit[0]["detail"])


async def test_workshop_remaining_kinds_service_split(store):
    await bind(store, "moderator")
    site = await provision(
        store["admin"],
        {
            "client": {
                "id": "site-maps",
                "via": "game",
                "ceiling": ["workshop.act", "workshop.map", "workshop.sessions"],
            },
            "ceiling": ["workshop.act", "workshop.map", "workshop.sessions"],
            "environment": "prod",
            "backend": "game",
            "resource": "*",
        },
    )
    store["tokens"]["site-maps"] = site
    for kind, fields in (
        ("map", WORKSHOP_MAP_CREATE),
        ("sessions", {"offset": 0}),
    ):
        assert (
            await request(
                store,
                "POST",
                f"/v2/workshop/{kind}",
                workshop_body(store, **fields),
                "site-maps",
            )
        ).status_code == 202
    # Mode and keys need an asserted actor: only an unbound site principal
    # may hold them, and act-only credentials cannot mint them either.
    with pytest.raises(ValueError, match="unbound site credential"):
        await provision(
            store["admin"],
            {
                "client": {
                    "id": "site-mode",
                    "via": "game",
                    "ceiling": ["workshop.act", "workshop.mode"],
                },
                "ceiling": ["workshop.act", "workshop.mode"],
                "environment": "prod",
                "backend": "game",
                "resource": "arena1",
            },
        )
    act_only = await provision(
        store["admin"],
        {
            "client": {"id": "site-act", "via": "game", "ceiling": ["workshop.act"]},
            "ceiling": ["workshop.act"],
            "environment": "prod",
            "backend": "game",
            "resource": "*",
        },
    )
    store["tokens"]["site-act"] = act_only
    for kind, fields in (
        ("mode", {"profile": "game", "expectedRevision": 0}),
        ("ai-key", {"provider": "openrouter", "key": "sk-" + "x" * 20}),
    ):
        assert (
            await request(
                store,
                "POST",
                f"/v2/workshop/{kind}",
                workshop_body(store, **fields),
                "site-act",
            )
        ).status_code == 403


async def test_owner_enroll_names_second_founder_explicitly(store, postgres):
    founder = uuid4()
    second = dict(store["credential"], id=bytes_to_base64url(b"test-credential-2"))
    await enroll_owner(store["admin"], founder, "cofounder", second)
    rows = await sql(store, "SELECT account_id FROM owner_memberships")
    assert {row["account_id"] for row in rows} == {
        store["accounts"]["owner"],
        founder,
    }
    with pytest.raises(ValueError, match="already an owner"):
        await enroll_owner(store["admin"], founder, "cofounder", second)
    with pytest.raises(ValueError, match="both founders"):
        await enroll_owner(store["admin"], uuid4(), "third", second)
    bad = dict(second, origin="http://control.example.test")
    with pytest.raises(ValueError, match="independent HTTPS origin"):
        await enroll_owner(store["admin"], uuid4(), "third", bad)
    name = "cp_" + uuid4().hex
    async with await psycopg.AsyncConnection.connect(postgres, autocommit=True) as conn:
        await conn.execute(f'CREATE DATABASE "{name}"')
    fresh = make_conninfo(postgres, dbname=name)
    await migrate(fresh, name)
    with pytest.raises(ValueError, match="not bootstrapped"):
        await enroll_owner(fresh, uuid4(), "first", second)


async def test_fresh_database_reaches_latest_schema_and_health(store):
    # A newly initialized database must end at len(MIGRATIONS) with no
    # second migrate run: health requires the latest version, and log
    # ingestion needs the newest tables from the start.

    applied = await sql(store, "SELECT MAX(version) AS version FROM schema_migrations")
    assert applied[0]["version"] == len(MIGRATIONS)
    seq = await sql(store, "SELECT to_regclass('control.console_log_seq') AS name")
    assert seq[0]["name"] == "console_log_seq"
    health = await request(store, "GET", "/health")
    assert health.status_code == 200, health.text
    assert health.json()["schema"] == len(MIGRATIONS)


async def test_workshop_rbac_mirrors_moderation_split(store):
    # Builders cannot issue; moderators handle member-level ops only.
    await bind(store, "moderator")
    await bind(store, "admin", "f" * 32, "Stranger")
    assert (
        await request(
            store,
            "POST",
            "/v2/workshop/message",
            workshop_body(store, message="hi"),
            "builder",
        )
    ).status_code == 403
    for kind, fields in (
        ("members", {"members": [dict(WORKSHOP_ACTOR, role="admin")]}),
        ("release.select", {"release": "v9.0.0"}),
    ):
        assert (
            await request(
                store,
                "POST",
                f"/v2/workshop/{kind}",
                workshop_body(store, **fields),
                "moderator",
            )
        ).status_code == 403
    for kind, fields in (
        ("message", {"message": "hi"}),
        ("wake", {}),
        ("cancel", {}),
    ):
        response = await request(
            store,
            "POST",
            f"/v2/workshop/{kind}",
            workshop_body(store, **fields),
            "moderator",
        )
        assert response.status_code == 202, (kind, response.text)
    admin_actor = {"draslId": "f" * 32, "name": "Stranger"}
    for kind, fields in (
        ("members", {"members": [{"draslId": "a" * 32, "name": "Helper"}]}),
        ("release.select", {"release": "v9.0.0"}),
    ):
        response = await request(
            store,
            "POST",
            f"/v2/workshop/{kind}",
            workshop_body(store, actor=admin_actor, **fields),
            "admin",
        )
        assert response.status_code == 202, (kind, response.text)


async def test_workshop_consumer_capability_and_generation_fenced(store):
    await bind(store, "moderator")
    body = workshop_body(store, message="hi", consumerId="game")
    response = await request(store, "POST", "/v2/workshop/message", body, "moderator")
    assert response.status_code == 409, response.text
    body = workshop_body(store, message="hi", generation=str(uuid4()))
    response = await request(store, "POST", "/v2/workshop/message", body, "moderator")
    assert response.status_code == 409, response.text


async def test_workshop_idempotent_retry_returns_same_operation(store):
    await bind(store, "moderator")
    body = workshop_body(store, message="hi")
    first = await request(store, "POST", "/v2/workshop/message", body, "moderator")
    assert first.status_code == 202, first.text
    second = await request(store, "POST", "/v2/workshop/message", body, "moderator")
    assert second.status_code == 202, second.text
    assert second.json()["operationId"] == first.json()["operationId"]
    rows = await workshop_outbox(store, first.json()["operationId"])
    assert len(rows) == 1


async def test_workshop_target_is_carried_and_maps_need_wildcard(store):
    await bind(store, "moderator")
    await bind(store, "admin", "b" * 32, "Helper")
    helper = {"draslId": "b" * 32, "name": "Helper"}
    scoped = workshop_body(store, message="hi", target="arena")
    response = await request(store, "POST", "/v2/workshop/message", scoped, "moderator")
    assert response.status_code == 202, response.text
    rows = await workshop_outbox(store, response.json()["operationId"])
    assert rows[0]["payload"]["target"] == "arena"
    maps = [{"draslId": "f" * 32, "name": "Stranger", "maps": ["arena"]}]
    wide = workshop_body(store, members=maps, actor=helper)
    response = await request(store, "POST", "/v2/workshop/members", wide, "admin")
    assert response.status_code == 202, response.text
    rows = await workshop_outbox(store, response.json()["operationId"])
    assert rows[0]["payload"]["target"] == "*"
    narrow = workshop_body(store, members=maps, target="arena", actor=helper)
    response = await request(store, "POST", "/v2/workshop/members", narrow, "admin")
    assert response.status_code == 422, response.text


async def test_workshop_person_actor_must_be_bound(store):
    body = workshop_body(store, message="hi")
    response = await request(store, "POST", "/v2/workshop/message", body, "moderator")
    assert response.status_code == 403, response.text
    assert response.json()["error"] == "workshop_actor_unbound"
    await bind(store, "moderator")
    forged = workshop_body(
        store, message="hi", actor={"draslId": "f" * 32, "name": "Stranger"}
    )
    response = await request(store, "POST", "/v2/workshop/message", forged, "moderator")
    assert response.status_code == 403, response.text
    derived = workshop_body(store, message="hi", actor=None)
    response = await request(
        store, "POST", "/v2/workshop/message", derived, "moderator"
    )
    assert response.status_code == 202, response.text
    rows = await workshop_outbox(store, response.json()["operationId"])
    assert rows[0]["payload"]["actor"] == WORKSHOP_ACTOR


async def test_workshop_service_act_scope(store):
    site = await provision(
        store["admin"],
        {
            "client": {
                "id": "site",
                "via": "game",
                "ceiling": ["workshop.act", "workshop.message"],
            },
            "ceiling": ["workshop.act", "workshop.message"],
            "environment": "prod",
            "backend": "game",
            "resource": "*",
        },
    )
    store["tokens"]["site"] = site
    body = workshop_body(store, message="hi")
    response = await request(store, "POST", "/v2/workshop/message", body, "site")
    assert response.status_code == 202, response.text
    rows = await sql(
        store,
        "SELECT detail FROM audit_events WHERE action=%s ORDER BY sequence DESC LIMIT 1",
        ("workshop.message",),
    )
    assert rows[0]["detail"]["workshopActor"] == WORKSHOP_ACTOR
    assert rows[0]["detail"]["principal"]["client"] == "site"
    assert rows[0]["detail"]["principal"]["account"] is None
    agent = workshop_body(store, message="hi")
    response = await request(store, "POST", "/v2/workshop/message", agent, "game-agent")
    assert response.status_code == 403, response.text
    anonymous = workshop_body(store, message="hi", actor=None)
    response = await request(store, "POST", "/v2/workshop/message", anonymous, "site")
    assert response.status_code == 422, response.text


async def test_workshop_admin_members_need_owner_step_up(store):
    await bind(store, "admin")
    await bind(store, "owner", "b" * 32, "Helper")
    admins = [dict(WORKSHOP_ACTOR, role="admin")]
    denied = workshop_body(store, members=admins)
    response = await request(store, "POST", "/v2/workshop/members", denied, "admin")
    assert response.status_code == 403, response.text
    assert response.json()["error"] == "owner_approval_required"
    builders = workshop_body(store, members=[{"draslId": "f" * 32, "name": "Stranger"}])
    response = await request(store, "POST", "/v2/workshop/members", builders, "admin")
    assert response.status_code == 202, response.text
    body = workshop_body(
        store, members=admins, actor={"draslId": "b" * 32, "name": "Helper"}
    )
    proof = await assertion(store, "POST", "/v2/workshop/members", body)
    response = await request(
        store, "POST", "/v2/workshop/members", body, "owner", proof
    )
    assert response.status_code == 202, response.text
    rows = await workshop_outbox(store, response.json()["operationId"])
    assert rows[0]["payload"]["members"] == admins
    site = await provision(
        store["admin"],
        {
            "client": {"id": "site-stepup", "via": "game", "ceiling": ["workshop.act"]},
            "ceiling": ["workshop.act"],
            "environment": "prod",
            "backend": "game",
            "resource": "*",
        },
    )
    store["tokens"]["site-stepup"] = site
    service = workshop_body(store, members=admins)
    response = await request(
        store, "POST", "/v2/workshop/members", service, "site-stepup"
    )
    # Members needs an asserted human (the site principal's actor), never
    # workshop.act: rejected before any owner step-up is evaluated.
    assert response.status_code == 403, response.text
    assert response.json()["error"] == "service_actor_required"


async def test_c20_health_reports_database_outage(store, monkeypatch):
    # CP-H5: the probe fails closed (503, no internals) when the DB is gone.
    response = await store["client"].get("/health")
    assert response.status_code == 200, response.text
    assert response.json() == {"status": "ok", "schema": len(MIGRATIONS)}
    await store["app"].state.db.close()
    # Success is cached briefly so public probe floods skip the DB.
    assert (await store["client"].get("/health")).status_code == 200
    now = cpv2_app._health_clock()
    monkeypatch.setattr(cpv2_app, "_health_clock", lambda: now + 6)
    broken = await store["client"].get("/health")
    assert broken.status_code == 503, broken.text
    assert broken.json() == {"status": "unavailable", "schema": len(MIGRATIONS)}


async def test_health_reports_applied_schema_version_before_stats_migration(postgres):
    # /health must report the applied migration, not the binary's latest:
    # on a schema-2 database readiness stays 503 until 003 is applied.
    name = "cp_" + uuid4().hex
    async with await psycopg.AsyncConnection.connect(postgres, autocommit=True) as conn:
        await conn.execute(f'CREATE DATABASE "{name}"')
    try:
        admin = make_conninfo(postgres, dbname=name)
        runtime = make_conninfo(admin, user="cp_api")
        await migrate(admin, name)
        async with await psycopg.AsyncConnection.connect(
            admin, autocommit=True
        ) as conn:
            await conn.execute("DROP TABLE control.stat_rating_rebuilds")
            await conn.execute("DROP TABLE control.stat_result_voids")
            await conn.execute("DROP TABLE control.stat_rating_changes")
            await conn.execute("DROP TABLE control.stat_ratings")
            await conn.execute("DROP TABLE control.stat_classes")
            await conn.execute("DROP TABLE control.stat_participants")
            await conn.execute("DROP TABLE control.stat_profiles")
            await conn.execute("DROP TABLE control.stat_results")
            await conn.execute("DELETE FROM control.schema_migrations WHERE version>=3")
        async with await psycopg.AsyncConnection.connect(admin) as conn:
            await conn.execute("GRANT cp_runtime TO cp_api")
        key = ec.generate_private_key(ec.SECP256R1())
        numbers = key.public_key().public_numbers()
        cose = cbor2.dumps(
            {
                1: 2,
                3: -7,
                -1: 1,
                -2: numbers.x.to_bytes(32, "big"),
                -3: numbers.y.to_bytes(32, "big"),
            }
        )
        credential = {
            "id": bytes_to_base64url(b"test-credential"),
            "publicKey": bytes_to_base64url(cose),
            "origin": "https://control.example.test",
            "rpId": "control.example.test",
        }
        await bootstrap(admin, uuid4(), "owner", credential)
        app = create_app(runtime)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="https://control.example.test",
            ) as client:
                response = await client.get("/health")
                assert response.status_code == 503, response.text
                assert response.json() == {"status": "unavailable", "schema": 2}
    finally:
        async with await psycopg.AsyncConnection.connect(
            postgres, autocommit=True
        ) as conn:
            await conn.execute(f'DROP DATABASE "{name}"')


def _rooms_body(key="rooms", revision=0, value=None):
    return {
        "idempotencyKey": key,
        "environment": "prod",
        "backend": "game",
        "expectedRevision": revision,
        "patch": value or {"maxRooms": 4},
    }


async def test_settings_rooms_cas_conflict_and_idempotent_retry(store):
    path = "/v2/settings/rooms/arena"
    assert (
        await request(store, "POST", path + "/validate", _rooms_body())
    ).status_code == 200
    responses = await asyncio.gather(
        request(store, "PATCH", path, _rooms_body("one")),
        request(store, "PATCH", path, _rooms_body("two")),
    )
    assert sorted(r.status_code for r in responses) == [202, 409]
    key = "one" if responses[0].status_code == 202 else "two"
    assert (await request(store, "PATCH", path, _rooms_body(key))).status_code == 202
    assert (
        await request(store, "PATCH", path, _rooms_body(key, value={"maxRooms": 8}))
    ).status_code == 409
    assert (
        await request(store, "PATCH", path, _rooms_body("invalid", 1, {"maxRooms": 0}))
    ).status_code == 422


async def test_ai_limits_budget_is_owner_only(store):
    path = "/v2/settings/ai-limits/global"
    account = "12345678-1234-1234-1234-1234567890ab"
    body = {
        "idempotencyKey": "ai-budget",
        "environment": "prod",
        "backend": "game",
        "expectedRevision": 0,
        "patch": {"sessions": {account: 1000}},
    }
    # A nested budget change must hit the protected path, not slip past it.
    assert (await request(store, "PATCH", path, body)).status_code == 403
    proof = await assertion(store, "PATCH", path, body)
    assert (
        await request(store, "PATCH", path, body, "owner", proof)
    ).status_code == 202


STAFF_SERVICE_SCOPES = ("staff.read", "staff.lower.manage", "staff.admin.manage")


async def _site(store):
    if "site" not in store["tokens"]:
        store["tokens"]["site"] = await provision(
            store["admin"],
            {
                "client": {
                    "id": "site",
                    "via": "cli",
                    "ceiling": sorted(STAFF_SERVICE_SCOPES),
                },
                "ceiling": sorted(STAFF_SERVICE_SCOPES),
                "environment": "prod",
                "backend": "game",
                "resource": "*",
            },
        )
    return store["tokens"]["site"]


async def test_staff_scopes_only_on_unbound_site_credential(store):
    # A resource-bound consumer holding staff scopes could assert any admin
    # whose grant covers its resource as the acting account.
    assert not set(STAFF_SERVICE_SCOPES) & SERVICE_SCOPES
    with pytest.raises(ValueError, match="unbound site credential"):
        await provision(
            store["admin"],
            {
                "client": {
                    "id": "arena-staff",
                    "via": "game",
                    "ceiling": ["staff.lower.manage"],
                },
                "ceiling": ["staff.lower.manage"],
                "environment": "prod",
                "backend": "game",
                "resource": "arena",
            },
        )


async def _second_staff_admin(store):
    second = uuid4()
    store["accounts"]["second-admin"] = second
    store["tokens"]["second-admin"] = await provision(
        store["admin"],
        {
            "accountId": str(second),
            "displayName": "second",
            "client": {
                "id": "second-admin",
                "via": "cli",
                "human": True,
                "ceiling": sorted(OWNER_SCOPES),
            },
            "ceiling": sorted(OWNER_SCOPES),
            "environment": "prod",
            "backend": "game",
            "resource": "*",
            "grants": [
                {
                    "role": "admin",
                    "environment": "prod",
                    "backend": "game",
                    "resource": "*",
                    "grantor": str(store["accounts"]["owner"]),
                }
            ],
        },
    )
    return second


def _grant(key, account, role, actor=None, revoke=False):
    body = {
        "idempotencyKey": key,
        "expectedRevision": 1,
        "accountId": str(account),
        "role": role,
        "resource": "*",
        "revoke": revoke,
    }
    if actor is not None:
        body["actorAccountId"] = str(actor)
    return body


async def test_staff_service_roster_read_ok(store):
    await _site(store)
    target = store["accounts"]["admin"]
    response = await request(
        store, "GET", f"/v2/staff/grants?accountId={target}", None, "site"
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["accountId"] == str(target)
    epoch = (
        await sql(
            store,
            "SELECT authorization_epoch AS e FROM accounts WHERE id=%s",
            (target,),
        )
    )[0]["e"]
    assert data["expectedRevision"] == epoch
    assert all(
        {"role", "environment", "backend", "resource", "revision"} <= set(g)
        for g in data["grants"]
    ), data["grants"]
    assert any(
        g["role"] == "admin"
        and g["environment"] == "prod"
        and g["backend"] == "game"
        and g["resource"] == "*"
        for g in data["grants"]
    ), data["grants"]
    missing = await request(
        store, "GET", f"/v2/staff/grants?accountId={uuid4()}", None, "site"
    )
    assert missing.status_code == 404
    assert missing.json()["error"] == "account_not_found"


async def test_staff_service_roster_read_stays_in_its_scope(store):
    # The access check covers prod/game only, so grants elsewhere stay hidden.
    await _site(store)
    target = uuid4()
    await provision(
        store["admin"],
        {
            "accountId": str(target),
            "displayName": "qa-mod",
            "client": {
                "id": "qa-mod",
                "via": "cli",
                "human": True,
                "ceiling": sorted(OWNER_SCOPES),
            },
            "ceiling": sorted(OWNER_SCOPES),
            "environment": "prod",
            "backend": "game",
            "resource": "*",
            "grants": [
                {
                    "role": "moderator",
                    "environment": env,
                    "backend": backend,
                    "resource": "*",
                    "grantor": str(store["accounts"]["owner"]),
                }
                for env, backend in (
                    ("qa", "game"),
                    ("prod", "workshop"),
                    ("prod", "game"),
                )
            ],
        },
    )
    response = await request(
        store, "GET", f"/v2/staff/grants?accountId={target}", None, "site"
    )
    assert response.status_code == 200, response.text
    assert {(g["environment"], g["backend"]) for g in response.json()["grants"]} == {
        ("prod", "game")
    }


async def test_staff_service_roster_read_forbidden_for_non_service(store):
    await _site(store)
    narrow = await provision(
        store["admin"],
        {
            "client": {"id": "narrow", "via": "game", "ceiling": ["gate:read"]},
            "ceiling": ["gate:read"],
            "environment": "prod",
            "backend": "game",
            "resource": "*",
        },
    )
    store["tokens"]["narrow"] = narrow
    # Fixture consumer agents hold every service scope by construction, so the
    # negative service case uses a narrowly provisioned credential instead.
    path = f"/v2/staff/grants?accountId={store['accounts']['admin']}"
    for role in ("admin", "ordinary", "narrow"):
        response = await request(store, "GET", path, None, role)
        assert response.status_code == 403, (role, response.text)


async def test_staff_service_grant_actor_peer_and_missing_actor(store):
    await _site(store)
    second = await _second_staff_admin(store)
    admin = store["accounts"]["admin"]
    peer = await request(
        store,
        "POST",
        "/v2/staff/grants",
        # Lower-role change on an admin target: the peer rule fires for the
        # asserted actor exactly like a direct non-owner admin call.
        _grant("peer", second, "builder", actor=admin, revoke=True),
        "site",
    )
    assert peer.status_code == 403 and peer.json()["error"] == "peer_role_edit", (
        peer.text
    )
    for key, role, revoke in (
        ("no-actor-grant", "admin", False),
        ("no-actor-revoke", "admin", True),
        ("no-actor-lower", "builder", False),
    ):
        denied = await request(
            store,
            "POST",
            "/v2/staff/grants",
            _grant(
                key,
                second if role == "admin" else store["accounts"]["ordinary"],
                role,
                revoke=revoke,
            ),
            "site",
        )
        assert denied.status_code == 403
        assert denied.json()["error"] == "service_actor_required", denied.text


async def test_staff_service_actor_read_holds_share_lock(store, monkeypatch):
    # Without FOR SHARE a revocation of the asserted admin could commit between
    # this read and the grant insert, applying a change under a revoked admin.
    await _site(store)
    admin = store["accounts"]["admin"]
    seen = []
    original = core.one

    async def observe(conn, query, params=()):
        if "FROM accounts WHERE id=%s" in query and params and params[0] == admin:
            seen.append(query)
        return await original(conn, query, params)

    monkeypatch.setattr(core, "one", observe)
    response = await request(
        store,
        "POST",
        "/v2/staff/grants",
        _grant("svc-lock", store["accounts"]["ordinary"], "moderator", actor=admin),
        "site",
    )
    assert response.status_code == 202, response.text
    assert seen and all("FOR SHARE" in q for q in seen), seen


async def test_staff_service_grant_actor_applies_and_audits(store):
    await _site(store)
    admin = store["accounts"]["admin"]
    ordinary, other = store["accounts"]["ordinary"], store["accounts"]["other"]
    response = await request(
        store,
        "POST",
        "/v2/staff/grants",
        _grant("svc-grant", ordinary, "moderator", actor=admin),
        "site",
    )
    assert response.status_code == 202, response.text
    receipt = response.json()
    assert receipt["result"]["authorizationEpoch"] == 2
    operation = (
        await sql(
            store,
            "SELECT account_id FROM operations WHERE id=%s",
            (receipt["operationId"],),
        )
    )[0]
    assert operation["account_id"] == admin
    live = await sql(
        store,
        "SELECT grantor, role FROM role_grants WHERE account_id=%s AND revoked_at IS NULL",
        (ordinary,),
    )
    assert any(g["grantor"] == admin and g["role"] == "moderator" for g in live)
    audits = await sql(
        store,
        "SELECT actor FROM audit_events WHERE operation_id=%s",
        (receipt["operationId"],),
    )
    assert audits and all(a["actor"] == admin for a in audits), audits
    # An actor without staff authority cannot grant through the service.
    powerless = await request(
        store,
        "POST",
        "/v2/staff/grants",
        _grant("svc-powerless", other, "builder", actor=ordinary),
        "site",
    )
    assert powerless.status_code == 403, powerless.text
    # The service cannot assert the target as its own actor.
    selfish = await request(
        store,
        "POST",
        "/v2/staff/grants",
        _grant("svc-self", admin, "builder", actor=admin),
        "site",
    )
    assert selfish.status_code == 403
    assert selfish.json()["error"] == "self_role_edit", selfish.text
    # Direct callers never supply the actor: it is authenticated, not asserted.
    forged = await request(
        store,
        "POST",
        "/v2/staff/grants",
        _grant("human-actor", other, "builder", actor=admin),
        "admin",
    )
    assert forged.status_code == 403
    assert forged.json()["error"] == "actor_forbidden", forged.text


async def test_settings_patch_null_deletes_rollback_restores_and_replays(store):
    path = "/v2/settings/kits/arena"
    seed = patch(
        "seed",
        0,
        {
            "kits": {"alpha": {"name": "a"}, "beta": {"name": "b"}},
            "fixedModeKits": {"campaign": "alpha"},
        },
    )
    assert (await request(store, "PATCH", path, seed)).status_code == 202
    delete = patch("del-beta", 1, {"kits": {"beta": None}})
    response = await request(store, "PATCH", path, delete)
    assert response.status_code == 202, response.text
    value = (await request(store, "GET", path)).json()
    assert value["revision"] == 2
    assert set(value["value"]["kits"]) == {"alpha"}
    # Idempotent replay returns the same receipt without a new revision.
    replay = await request(store, "PATCH", path, delete)
    assert replay.status_code == 202
    assert replay.json() == response.json()
    assert (await request(store, "GET", path)).json()["revision"] == 2
    # Null stays a value under fixedModeKits ("kit id or null").
    clear = patch("clear-fixed", 2, {"fixedModeKits": {"campaign": None}})
    assert (await request(store, "PATCH", path, clear)).status_code == 202
    value = (await request(store, "GET", path)).json()
    assert value["value"]["fixedModeKits"] == {"campaign": None}
    # Rollback to revision 1 restores the deleted kit.
    rollback = {"idempotencyKey": "rollback", "expectedRevision": 3, "revision": 1}
    response = await request(store, "POST", path + "/rollback", rollback)
    assert response.status_code == 202, response.text
    value = (await request(store, "GET", path)).json()
    assert set(value["value"]["kits"]) == {"alpha", "beta"}


async def test_gameplay_explicit_ai_write_is_rejected(store):
    path = "/v2/settings/gameplay/arena"
    body = patch("ai-write", 0, {"ai": {"hardLimit": 200}})
    assert (await request(store, "PATCH", path, body)).status_code == 422
    assert (await request(store, "GET", path)).json()["revision"] == 0


async def test_settings_patch_nested_delete_reset_and_invalid_change(store):
    path = "/v2/settings/campaign/arena"
    seed = patch(
        "camp-seed",
        0,
        {
            "campaignBalance": {
                "c1": {"max_tickets": 100, "score_per_kill": 5},
                "gone": {"max_tickets": 10},
            }
        },
    )
    assert (await request(store, "PATCH", path, seed)).status_code == 202
    # Nested delete removes one key inside a campaign entry.
    nested = patch(
        "camp-nested", 1, {"campaignBalance": {"c1": {"score_per_kill": None}}}
    )
    assert (await request(store, "PATCH", path, nested)).status_code == 202
    value = (await request(store, "GET", path)).json()["value"]
    assert value["campaignBalance"] == {
        "c1": {"max_tickets": 100},
        "gone": {"max_tickets": 10},
    }
    # Whole-dict reset empties the namespace.
    reset = patch("camp-reset", 2, {"campaignBalance": None})
    assert (await request(store, "PATCH", path, reset)).status_code == 202
    assert (await request(store, "GET", path)).json()["value"] == {
        "campaignBalance": {}
    }
    # The removed ai section is rejected like any unknown field.
    gpath = "/v2/settings/gameplay/arena"
    seed = patch("g-seed", 0, {"match": {"maxPlayers": 24}})
    assert (await request(store, "PATCH", gpath, seed)).status_code == 202
    gone = patch("g-gone", 1, {"ai": {"hardLimit": 200}})
    assert (await request(store, "PATCH", gpath, gone)).status_code == 422


async def test_cpp1_workshop_leg_reaches_proxy_snapshot_and_frames(store):
    # Writer contract: whoever holds workshop.gate reports the leg (admin here;
    # the autonomous workshop reporter needs the authorship follow-up noted in
    # .dev/cpp1/map.md). Serving is identical whoever writes: the proxy
    # consumer (settings.gate, resource *) gets the leg in its snapshot and
    # frames with the same lease semantics as the game leg.
    leg = patch(
        "workshop-leg-1",
        0,
        {
            "state": "builders",
            "message": "night build",
            "allowed": [
                {
                    "draslId": "abababababababababababababababab",
                    "name": "Builder1",
                }
            ],
        },
    )
    accepted = await request(store, "PATCH", "/v2/settings/gate/workshop", leg)
    assert accepted.status_code == 202
    value = leg["patch"]
    snapshot = await request(
        store, "GET", "/v2/agents/game/snapshot", role="game-agent"
    )
    assert snapshot.status_code == 200
    assert [
        entry
        for entry in snapshot.json()["settings"]
        if entry["namespace"] == "gate" and entry["target"] == "workshop"
    ] == [
        {
            "namespace": "gate",
            "target": "workshop",
            "revision": 1,
            "value": value,
            "value_hash": digest(value),
        }
    ]
    frames = await envelopes(store, cid="game")
    assert {
        "kind": "settings",
        "namespace": "gate",
        "target": "workshop",
        "value": value,
        "timing": "live",
    } in [frame["payload"] for frame in frames if frame["executable"]]


async def test_cpp1_workshop_leg_fail_closed_and_validated(store):
    snapshot = await request(
        store, "GET", "/v2/agents/game/snapshot", role="game-agent"
    )
    assert snapshot.status_code == 200
    assert [
        entry
        for entry in snapshot.json()["settings"]
        if entry["namespace"] == "gate" and entry["target"] == "workshop"
    ] == []
    view = await request(store, "GET", "/v2/settings/gate/workshop")
    assert view.json()["initialized"] is False
    assert view.json()["value"]["state"] == "closed"
    game_leg = patch("g-bad", 0, {"state": "builders"})
    assert (
        await request(store, "PATCH", "/v2/settings/gate/*", game_leg)
    ).status_code == 422
    bad_mode = patch("w-bad", 0, {"mode": "open"})
    assert (
        await request(store, "PATCH", "/v2/settings/gate/workshop", bad_mode)
    ).status_code == 422
    bad_state = patch("w-bad-state", 0, {"state": "open"})
    assert (
        await request(store, "PATCH", "/v2/settings/gate/workshop", bad_state)
    ).status_code == 422
    starting = patch(
        "w-starting",
        0,
        {
            "state": "STARTING",
            "allowed": [
                {
                    "draslId": "abab-abababababab-abababababababab",
                    "name": "Builder1",
                }
            ],
        },
    )
    assert (
        await request(store, "PATCH", "/v2/settings/gate/workshop", starting)
    ).status_code == 202
    view = await request(store, "GET", "/v2/settings/gate/workshop")
    assert view.json()["value"] == {
        "state": "starting",
        "message": "",
        "allowed": [
            {"draslId": "abababababababababababababababab", "name": "Builder1"}
        ],
    }


async def test_cpp3_service_reports_workshop_leg_with_service_actor(store):
    # CPP3: the workshop controller reports its gate leg with a
    # workshop.gate service credential. Before the fix the PATCH failed 503
    # (settings_revisions.actor NOT NULL, service has no account) and, even
    # accepted, the frame stayed non-executable at delivery.
    store["tokens"]["reporter"] = await provision(
        store["admin"],
        {
            "client": {
                "id": "workshop-reporter",
                "via": "game",
                "ceiling": ["workshop.gate"],
            },
            "ceiling": ["workshop.gate"],
            "environment": "prod",
            "backend": "game",
            "resource": "*",
        },
    )
    # The reporter reads the leg back with the write scope alone (no global
    # settings.read) to report idempotently; other namespaces stay denied.
    view = await request(store, "GET", "/v2/settings/gate/workshop", role="reporter")
    assert view.status_code == 200, view.text
    assert view.json()["initialized"] is False
    assert view.json()["value"]["state"] == "closed"
    denied = await request(store, "GET", "/v2/settings/gameplay/arena", role="reporter")
    assert denied.status_code == 403, denied.text
    leg = patch(
        "reporter-leg-1",
        0,
        {
            "state": "builders",
            "message": "night build",
            "allowed": [
                {
                    "draslId": "abababababababababababababababab",
                    "name": "Builder1",
                }
            ],
        },
    )
    accepted = await request(
        store, "PATCH", "/v2/settings/gate/workshop", leg, "reporter"
    )
    assert accepted.status_code == 202, accepted.text
    operation = accepted.json()["operationId"]
    rows = await sql(
        store,
        "SELECT account_id, credential_id FROM operations WHERE id=%s",
        (operation,),
    )
    assert rows[0]["account_id"] is None
    revisions = await sql(
        store,
        "SELECT actor FROM settings_revisions WHERE operation_id=%s",
        (operation,),
    )
    names = await sql(
        store, "SELECT display_name FROM accounts WHERE id=%s", (revisions[0]["actor"],)
    )
    assert names == [{"display_name": "service:workshop-reporter"}]
    # The proxy consumer receives the leg in snapshot and executable frames.
    snapshot = await request(
        store, "GET", "/v2/agents/game/snapshot", role="game-agent"
    )
    assert snapshot.status_code == 200
    assert [
        entry
        for entry in snapshot.json()["settings"]
        if entry["namespace"] == "gate" and entry["target"] == "workshop"
    ] == [
        {
            "namespace": "gate",
            "target": "workshop",
            "revision": 1,
            "value": leg["patch"],
            "value_hash": digest(leg["patch"]),
        }
    ]
    frames = await envelopes(store, cid="game")
    assert {
        "kind": "settings",
        "namespace": "gate",
        "target": "workshop",
        "value": leg["patch"],
        "timing": "live",
    } in [frame["payload"] for frame in frames if frame["executable"]]
    # A changed report revises the same leg under the same service actor; a
    # stale revision still conflicts.
    update = patch("reporter-leg-2", 1, {"message": "morning build"})
    updated = await request(
        store, "PATCH", "/v2/settings/gate/workshop", update, "reporter"
    )
    assert updated.status_code == 202, updated.text
    again = await sql(
        store,
        "SELECT actor FROM settings_revisions WHERE operation_id=%s",
        (updated.json()["operationId"],),
    )
    assert again == revisions
    stale = patch("reporter-leg-3", 1, {"message": "stale"})
    assert (
        await request(store, "PATCH", "/v2/settings/gate/workshop", stale, "reporter")
    ).status_code == 409
    # The reporter scope reaches nothing else.
    other = patch("reporter-other", 0, {"lobby": {"pvpEnabled": True}})
    assert (
        await request(store, "PATCH", "/v2/settings/gameplay/arena", other, "reporter")
    ).status_code == 403
    assert (
        await request(store, "PATCH", "/v2/settings/gate/*", other, "reporter")
    ).status_code == 403


async def test_cpp1r2_service_act_alone_cannot_post_members(store):
    # A service holding only workshop.act must not change the workshop member
    # ACL: members needs the admin-only workshop.members scope, which no
    # service credential may hold.
    store["tokens"]["act-only"] = await provision(
        store["admin"],
        {
            "client": {"id": "act-only", "via": "game", "ceiling": ["workshop.act"]},
            "ceiling": ["workshop.act"],
            "environment": "prod",
            "backend": "game",
            "resource": "*",
        },
    )
    body = workshop_body(store, members=[{"draslId": "f" * 32, "name": "Stranger"}])
    response = await request(store, "POST", "/v2/workshop/members", body, "act-only")
    assert response.status_code == 403, response.text


async def test_service_workshop_op_rechecked_at_delivery(store):
    # A workshop.act operation (site/proxy attesting a human) carries no
    # account: delivery re-checks the provisioned scopes (SERVICE_ISSUED), so
    # it executes while the credential holds them and fences once revoked.
    store["tokens"]["messenger"] = await provision(
        store["admin"],
        {
            "client": {
                "id": "messenger",
                "via": "game",
                "ceiling": ["workshop.act", "workshop.message"],
            },
            "ceiling": ["workshop.act", "workshop.message"],
            "environment": "prod",
            "backend": "game",
            "resource": "*",
        },
    )
    body = workshop_body(store, message="hi")
    response = await request(store, "POST", "/v2/workshop/message", body, "messenger")
    assert response.status_code == 202, response.text
    operation_id = response.json()["operationId"]
    rows = await sql(
        store,
        "SELECT account_id FROM operations WHERE id=%s",
        (operation_id,),
    )
    assert rows[0]["account_id"] is None
    frames = await envelopes(store, cid="workshop")
    frame = next(item for item in frames if item["operationId"] == operation_id)
    assert frame["executable"] is True
    assert frame["payload"]["actor"] == WORKSHOP_ACTOR
    second = await request(
        store,
        "POST",
        "/v2/workshop/message",
        workshop_body(store, message="again"),
        "messenger",
    )
    assert second.status_code == 202, second.text
    await sql(
        store,
        "UPDATE credentials SET revoked_at=now() WHERE client_id='messenger'",
    )
    frames = await envelopes(store, cid="workshop")
    fenced = next(
        item for item in frames if item["operationId"] == second.json()["operationId"]
    )
    assert not fenced["executable"]
    assert fenced["payload"] is None


async def _workshop_service(store, client_id, ceiling, resource="*"):
    store["tokens"][client_id] = await provision(
        store["admin"],
        {
            "client": {"id": client_id, "via": "game", "ceiling": ceiling},
            "ceiling": ceiling,
            "environment": "prod",
            "backend": "game",
            "resource": resource,
        },
    )


async def test_workshop_map_ops_produce_exact_payloads(store):
    await bind(store, "moderator")
    head, other = "a" * 64, "b" * 64
    cases = {
        "map-create": WORKSHOP_MAP_CREATE["args"],
        "map-properties": WORKSHOP_MAP_PROPERTIES["args"],
        "limbo-export": {"versionDigest": head},
        "commit": {
            "mapId": "arena1",
            "workingCopyId": WORKSHOP_COPY,
            "expectedHead": None,
            "note": " tidy ",
        },
        "compare": {"mapId": "arena1", "before": head, "after": other},
        "snapshots": {"mapId": "arena1"},
        "snapshot-create": {"mapId": "arena1", "name": "v1", "versionDigest": head},
        "snapshot-delete": {"mapId": "arena1", "name": "v1"},
        "snapshot-copy": {
            "mapId": "arena1",
            "name": "draft.2",
            "workingCopyId": WORKSHOP_COPY,
        },
        "checkout-fresh": {"mapId": "arena1", "workingCopyId": WORKSHOP_COPY},
        "candidate": {
            "mapId": "arena1",
            "workingCopyId": WORKSHOP_COPY,
            "expectedHead": head,
            "commit": True,
            "note": "ready",
        },
        "rollback": {"mapId": "arena1", "versionDigest": head, "expectedHead": other},
        "publish": {
            "candidateId": "c" * 32,
            "force": True,
            "expectedHead": None,
            "resolutions": {
                "map.json": "ours",
                "world/region/r.0.-1.mca": "theirs",
                "map.json#/spawn/0": "theirs",
            },
        },
        "reject": {"candidateId": "c" * 32},
        "export": {"candidateId": "c" * 32},
    }
    assert set(cases) == set(core.WORKSHOP_MAP_OPS)
    for op, args in cases.items():
        body = workshop_body(store, mapOp=op, args=args)
        response = await request(store, "POST", "/v2/workshop/map", body, "moderator")
        assert response.status_code == 202, (op, response.text)
        rows = await workshop_outbox(store, response.json()["operationId"])
        expected = {**args, "note": args["note"].strip()} if "note" in args else args
        assert rows[0]["payload"] == {
            "kind": "map",
            "target": "*",
            "actor": WORKSHOP_ACTOR,
            "mapOp": op,
            "args": expected,
        }, op


async def test_workshop_site_principal_asserts_admin_kinds(store):
    await _workshop_service(
        store,
        "site-ws",
        ["workshop.act", "workshop.members", "workshop.mode", "workshop.ai-key"],
    )
    accounts = store["accounts"]
    admin = {"draslId": accounts["admin"].hex, "name": "Admin"}
    owner = {"draslId": accounts["owner"].hex, "name": "Owner"}
    mode = {"profile": "game", "expectedRevision": 0}

    async def post(kind, role="site-ws", **fields):
        return await request(
            store, "POST", f"/v2/workshop/{kind}", workshop_body(store, **fields), role
        )

    # Admin/owner kinds never ride workshop.act: the human is asserted.
    response = await post("mode", actor=admin, **mode)
    assert response.status_code == 403
    assert response.json()["error"] == "service_actor_required"
    response = await post(
        "mode", actor=admin, actorAccountId=str(accounts["admin"]), **mode
    )
    assert response.status_code == 202, response.text
    operation_id = response.json()["operationId"]
    rows = await sql(
        store, "SELECT account_id FROM operations WHERE id=%s", (operation_id,)
    )
    assert rows[0]["account_id"] == accounts["admin"]
    payload = (await workshop_outbox(store, operation_id))[0]["payload"]
    assert payload == {"kind": "mode", "target": "*", "actor": admin, **mode}
    frames = await envelopes(store, cid="workshop")
    frame = next(item for item in frames if item["operationId"] == operation_id)
    assert frame["executable"] is True
    # The workshop actor is the asserted account itself.
    response = await post(
        "mode", actor=owner, actorAccountId=str(accounts["admin"]), **mode
    )
    assert response.status_code == 422
    # The asserted actor's own grants decide: moderators cannot switch
    # modes, keys stay founders only.
    moderator = {"draslId": accounts["moderator"].hex, "name": "Mod"}
    response = await post(
        "mode", actor=moderator, actorAccountId=str(accounts["moderator"]), **mode
    )
    assert response.status_code == 403
    key = {"provider": "openrouter", "key": "sk-" + "x" * 20}
    response = await post(
        "ai-key", actor=admin, actorAccountId=str(accounts["admin"]), **key
    )
    assert response.status_code == 403
    response = await post(
        "ai-key", actor=owner, actorAccountId=str(accounts["owner"]), **key
    )
    assert response.status_code == 202, response.text
    # Members: without an owner step-up, every Workshop admin must be a CP
    # admin or owner.
    members = [
        {"draslId": accounts["admin"].hex, "name": "Admin", "role": "admin"},
        {"draslId": "f" * 32, "name": "Stranger"},
    ]
    response = await post(
        "members", actor=admin, actorAccountId=str(accounts["admin"]), members=members
    )
    assert response.status_code == 202, response.text
    response = await post(
        "members",
        actor=admin,
        actorAccountId=str(accounts["admin"]),
        members=[{"draslId": "f" * 32, "name": "Stranger", "role": "admin"}],
    )
    assert response.status_code == 403
    assert response.json()["error"] == "workshop_admin_not_cp_admin"
    # Direct callers and workshop.act kinds never carry an asserted account.
    response = await post(
        "mode", "admin", actor=admin, actorAccountId=str(accounts["admin"]), **mode
    )
    assert response.json()["error"] == "actor_forbidden"
    response = await post(
        "message", actor=admin, actorAccountId=str(accounts["admin"]), message="hi"
    )
    assert response.json()["error"] == "actor_forbidden"


async def test_workshop_release_ci_selects_without_actor(store):
    await _workshop_service(store, "release-ci", ["workshop.release.select"])
    record = {"release": "v9.1.0"}
    body = workshop_body(store, actor=None, release="v9.1.0", record=record)
    response = await request(
        store, "POST", "/v2/workshop/release.select", body, "release-ci"
    )
    assert response.status_code == 202, response.text
    operation_id = response.json()["operationId"]
    payload = (await workshop_outbox(store, operation_id))[0]["payload"]
    assert payload == {
        "kind": "release.select",
        "target": "*",
        "release": "v9.1.0",
        "record": record,
    }
    frames = await envelopes(store, cid="workshop")
    frame = next(item for item in frames if item["operationId"] == operation_id)
    assert frame["executable"] is True
    # The release principal never attests a human or reaches other kinds.
    for kind, fields in (
        ("release.select", {"release": "v9.1.0"}),
        ("message", {"message": "hi"}),
    ):
        response = await request(
            store,
            "POST",
            f"/v2/workshop/{kind}",
            workshop_body(store, **fields),
            "release-ci",
        )
        assert response.status_code == 403, kind
    # An attesting service cannot select releases actorless.
    await _workshop_service(store, "attester", ["workshop.act", "workshop.message"])
    response = await request(
        store,
        "POST",
        "/v2/workshop/release.select",
        workshop_body(store, actor=None, release="v9.1.0"),
        "attester",
    )
    assert response.status_code == 403


async def test_workshop_state_report_read_and_stream(store, monkeypatch):
    from types import SimpleNamespace

    await _workshop_service(
        store,
        "ws-reporter",
        ["workshop.gate", "workshop.report"],
        resource="workshop",
    )
    await _workshop_service(store, "ws-reader", ["workshop.read"])

    async def put(name, value, role="ws-reporter"):
        return await request(
            store, "PUT", f"/v2/workshop/state/{name}", {"value": value}, role
        )

    status = {"phase": "workshop", "revision": 3}
    response = await put("status", status)
    assert response.status_code == 200, response.text
    assert response.json()["changed"] is True and response.json()["revision"] == 1
    response = await put("status", status)
    assert response.json()["changed"] is False and response.json()["revision"] == 1
    response = await put("status", {**status, "revision": 4})
    assert response.json()["revision"] == 2
    assert (await put("nope", {})).status_code == 404
    assert (await put("status", status, "ws-reader")).status_code == 403
    assert (
        await request(store, "GET", "/v2/workshop/state", role="ws-reporter")
    ).status_code == 403
    document = (
        await request(store, "GET", "/v2/workshop/state", role="ws-reader")
    ).json()
    assert document["documents"]["status"]["value"] == {**status, "revision": 4}
    # Results keep only the newest WORKSHOP_RESULTS_KEPT.
    monkeypatch.setattr(core, "WORKSHOP_RESULTS_KEPT", 2)
    ids = [str(uuid4()) for _ in range(3)]
    for index, op in enumerate(ids):
        assert (await put(f"result:{op}", {"ok": True, "n": index})).status_code == 200
    names = ",".join(f"result:{op}" for op in ids)
    kept = (
        await request(
            store, "GET", f"/v2/workshop/state?names={names}", role="ws-reader"
        )
    ).json()["documents"]
    assert set(kept) == {f"result:{op}" for op in ids[1:]}
    # The stream replays past the cursor, then pushes each change.
    async with store["app"].state.db.transaction() as conn:
        identity = await authenticate(conn, store["tokens"]["ws-reader"])
    endpoint = next(
        route.endpoint
        for route in store["app"].routes
        if route.path == "/v2/workshop/state/events"
    )
    req = SimpleNamespace(
        state=SimpleNamespace(identity=identity, token=store["tokens"]["ws-reader"])
    )
    response = await endpoint(req, after=0)
    iterator = response.body_iterator
    try:
        replayed = [await asyncio.wait_for(anext(iterator), 2) for _ in range(3)]
        assert [
            json.loads(item.split("data: ", 1)[1])["name"] for item in replayed
        ] == [
            "status",
            f"result:{ids[1]}",
            f"result:{ids[2]}",
        ]
        await put("maps", {"schema": 1, "maps": []})
        pushed = await asyncio.wait_for(anext(iterator), 5)
        assert json.loads(pushed.split("data: ", 1)[1])["value"] == {
            "schema": 1,
            "maps": [],
        }
    finally:
        await iterator.aclose()


async def test_workshop_state_cursor_follows_commit_order(store):
    started = asyncio.Event()

    async def second():
        async with store["app"].state.db.transaction() as conn:
            started.set()
            return await core._workshop_state_upsert(conn, "maps", {"n": 2})

    async with store["app"].state.db.transaction() as conn:
        first = await core._workshop_state_upsert(conn, "status", {"n": 1})
        task = asyncio.create_task(second())
        await started.wait()
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(asyncio.shield(task), 0.1)
    later = await asyncio.wait_for(task, 5)
    assert first["seq"] < later["seq"]
    async with store["app"].state.db.transaction() as conn:
        assert [
            x["name"] for x in await core.workshop_state_since(conn, first["seq"])
        ] == ["maps"]


async def _site_sessions_token(store, cid="site-sessions"):
    if cid not in store["tokens"]:
        store["tokens"][cid] = await provision(
            store["admin"],
            {
                "client": {"id": cid, "via": "game", "ceiling": ["site.sessions"]},
                "ceiling": ["site.sessions"],
                "environment": "prod",
                "backend": "game",
                "resource": "*",
            },
        )
    return store["tokens"][cid]


async def test_site_sessions_provision_requires_unbound_credential(store):
    from cpv2.auth import SERVICE_SCOPES, SITE_SESSIONS_SCOPES

    assert not SITE_SESSIONS_SCOPES & SERVICE_SCOPES
    with pytest.raises(ValueError, match="unbound site credential"):
        await provision(
            store["admin"],
            {
                "client": {
                    "id": "bound-sessions",
                    "via": "game",
                    "ceiling": ["site.sessions"],
                },
                "ceiling": ["site.sessions"],
                "environment": "prod",
                "backend": "game",
                "resource": "arena",
            },
        )
    with pytest.raises(ValueError, match="service credential ceiling"):
        await provision(
            store["admin"],
            {
                "client": {
                    "id": "human-sessions",
                    "via": "game",
                    "ceiling": ["site.sessions"],
                    "human": True,
                },
                "ceiling": ["site.sessions"],
                "environment": "prod",
                "backend": "game",
                "resource": "*",
            },
        )


async def test_site_sessions_crud_and_revoke_all(store):
    await _site_sessions_token(store)
    created = await request(
        store,
        "POST",
        "/v2/site/sessions",
        {"sealedToken": "sealed-one", "playerUuid": "player-1"},
        "site-sessions",
    )
    assert created.status_code == 201, created.text
    sid = created.json()["sessionId"]
    assert len(sid) == 32 and all(c in "0123456789abcdef" for c in sid)
    fetched = await request(
        store, "GET", f"/v2/site/sessions/{sid}", None, "site-sessions"
    )
    assert fetched.status_code == 200, fetched.text
    assert fetched.json() == {"sealedToken": "sealed-one", "playerUuid": "player-1"}
    second = await request(
        store,
        "POST",
        "/v2/site/sessions",
        {"sealedToken": "sealed-two", "playerUuid": "player-1"},
        "site-sessions",
    )
    assert second.status_code == 201, second.text
    revoked_all = await request(
        store,
        "DELETE",
        "/v2/site/users/player-1/sessions",
        None,
        "site-sessions",
    )
    assert revoked_all.status_code == 200, revoked_all.text
    assert revoked_all.json()["revoked"] == 2
    assert (
        await request(store, "GET", f"/v2/site/sessions/{sid}", None, "site-sessions")
    ).status_code == 404
    single = await request(
        store,
        "POST",
        "/v2/site/sessions",
        {"sealedToken": "sealed-three", "playerUuid": "player-1"},
        "site-sessions",
    )
    one_id = single.json()["sessionId"]
    first_delete = await request(
        store, "DELETE", f"/v2/site/sessions/{one_id}", None, "site-sessions"
    )
    assert first_delete.json() == {"revoked": True}
    second_delete = await request(
        store, "DELETE", f"/v2/site/sessions/{one_id}", None, "site-sessions"
    )
    assert second_delete.json() == {"revoked": False}


async def test_site_sessions_rbac(store):
    await _site_sessions_token(store)
    body = {"sealedToken": "tok", "playerUuid": "player-rbac"}
    for role in ("ordinary", "builder", "moderator", "admin", "game-agent"):
        response = await request(store, "POST", "/v2/site/sessions", body, role)
        assert response.status_code == 403, (role, response.text)
    assert (
        await request(store, "POST", "/v2/site/sessions", body, "owner")
    ).status_code == 201
    created = await request(store, "POST", "/v2/site/sessions", body, "site-sessions")
    sid = created.json()["sessionId"]
    for role in ("ordinary", "admin"):
        assert (
            await request(store, "GET", f"/v2/site/sessions/{sid}", None, role)
        ).status_code == 403
    assert (
        await request(store, "GET", f"/v2/site/sessions/{sid}", None, "owner")
    ).status_code == 200
    assert (await store["client"].get(f"/v2/site/sessions/{sid}")).status_code == 401


async def test_site_sessions_caps_and_expiry(store):
    await _site_sessions_token(store, "site-caps")
    ids = []
    for index in range(21):
        response = await request(
            store,
            "POST",
            "/v2/site/sessions",
            {"sealedToken": f"tok-{index}", "playerUuid": "player-caps"},
            "site-caps",
        )
        assert response.status_code == 201, response.text
        ids.append(response.json()["sessionId"])
    rows = await sql(
        store,
        "SELECT count(*) AS n FROM site_sessions WHERE player_uuid=%s",
        ("player-caps",),
    )
    assert rows[0]["n"] == 20
    assert (
        await request(store, "GET", f"/v2/site/sessions/{ids[0]}", None, "site-caps")
    ).status_code == 404
    stale = await request(
        store,
        "POST",
        "/v2/site/sessions",
        {"sealedToken": "stale", "playerUuid": "player-stale"},
        "site-caps",
    )
    stale_id = stale.json()["sessionId"]
    await sql(
        store,
        "UPDATE site_sessions SET last_seen=now()-interval '61 days' WHERE id=%s",
        (stale_id,),
    )
    assert (
        await request(store, "GET", f"/v2/site/sessions/{stale_id}", None, "site-caps")
    ).status_code == 404
    assert not await sql(store, "SELECT 1 FROM site_sessions WHERE id=%s", (stale_id,))


async def test_site_sessions_validation(store):
    await _site_sessions_token(store, "site-valid")
    bad = await request(
        store,
        "POST",
        "/v2/site/sessions",
        {"sealedToken": "", "playerUuid": "p"},
        "site-valid",
    )
    assert bad.status_code == 422, bad.text
    assert (
        await request(store, "GET", "/v2/site/sessions/not-hex", None, "site-valid")
    ).status_code == 404
    assert (
        await request(store, "DELETE", "/v2/site/sessions/not-hex", None, "site-valid")
    ).status_code == 404


async def test_site_sessions_touch_deleted_reports_not_found(store, monkeypatch):
    # Finding ..391: a read that selected a session must not return its sealed
    # token after a concurrent revoke deletes it before the touch.
    await _site_sessions_token(store, "site-touch")
    created = await request(
        store,
        "POST",
        "/v2/site/sessions",
        {"sealedToken": "touch-me", "playerUuid": "player-touch"},
        "site-touch",
    )
    assert created.status_code == 201, created.text
    sid = created.json()["sessionId"]
    real_one = core.one
    entered, release = asyncio.Event(), asyncio.Event()

    async def gated_one(conn, query, args=()):
        row = await real_one(conn, query, args)
        if "FROM site_sessions WHERE id=" in query:
            entered.set()
            await release.wait()
        return row

    monkeypatch.setattr(core, "one", gated_one)
    reader = asyncio.create_task(
        request(store, "GET", f"/v2/site/sessions/{sid}", None, "site-touch")
    )
    await asyncio.wait_for(entered.wait(), 5)
    revoked = await request(
        store, "DELETE", f"/v2/site/sessions/{sid}", None, "site-touch"
    )
    assert revoked.json() == {"revoked": True}
    release.set()
    response = await asyncio.wait_for(reader, 10)
    assert response.status_code == 404, response.text
    assert not await sql(store, "SELECT 1 FROM site_sessions WHERE id=%s", (sid,))


def _site_race_identity(cid):
    from cpv2.auth import Identity

    return Identity(
        {
            "id": cid,
            "ceiling": ["site.sessions"],
            "environment": "prod",
            "backend": "game",
            "resource": "*",
            "kind": "service",
        },
        {"id": cid, "ceiling": ["site.sessions"], "human": False, "via": "game"},
        None,
        [],
        False,
    )


async def _site_race_conn(store):
    return await psycopg.AsyncConnection.connect(
        store["runtime"],
        row_factory=psycopg.rows.dict_row,
        options="-c search_path=control,pg_catalog",
    )


async def test_site_sessions_concurrent_create_enforces_cap(store):
    # Finding ..414: two concurrent creates on a 19-session player must leave
    # 20 rows, not 21. Two raw connections hold both inserts uncommitted, so
    # the prune check overlaps deterministically.
    from cpv2.models import SiteSessionCreate

    await _site_sessions_token(store, "site-conc")
    for index in range(19):
        response = await request(
            store,
            "POST",
            "/v2/site/sessions",
            {"sealedToken": f"c-{index}", "playerUuid": "player-conc"},
            "site-conc",
        )
        assert response.status_code == 201, response.text
    identity = _site_race_identity("site-conc")
    conn_a, conn_b = await _site_race_conn(store), await _site_race_conn(store)
    try:
        async with conn_a.transaction():
            await core.site_session_create(
                conn_a,
                identity,
                None,
                SiteSessionCreate(sealedToken="c-A", playerUuid="player-conc"),
            )

            async def second():
                async with conn_b.transaction():
                    return await core.site_session_create(
                        conn_b,
                        identity,
                        None,
                        SiteSessionCreate(sealedToken="c-B", playerUuid="player-conc"),
                    )

            task = asyncio.create_task(second())
            await asyncio.sleep(0.5)
            blocked = not task.done()
        result = await asyncio.wait_for(task, 10)
        assert result["sessionId"]
        # The second create must have waited for the first to commit so its
        # prune sees the committed row.
        assert blocked
    finally:
        await conn_a.close()
        await conn_b.close()
    count = await sql(
        store,
        "SELECT count(*) AS n FROM site_sessions WHERE player_uuid=%s",
        ("player-conc",),
    )
    assert count[0]["n"] == 20


async def test_site_sessions_create_revoke_all_serialized(store):
    # Finding ..402: an uncommitted create must not slip past a concurrent
    # revoke-all. The revoke blocks on the per-player lock, then deletes the
    # committed row.
    from cpv2.models import SiteSessionCreate

    await _site_sessions_token(store, "site-race")
    identity = _site_race_identity("site-race")
    conn_a, conn_b = await _site_race_conn(store), await _site_race_conn(store)
    try:
        async with conn_a.transaction():
            await core.site_session_create(
                conn_a,
                identity,
                None,
                SiteSessionCreate(sealedToken="r-A", playerUuid="player-race"),
            )

            async def revoke():
                async with conn_b.transaction():
                    return await core.site_sessions_revoke_user(
                        conn_b, identity, None, "player-race"
                    )

            task = asyncio.create_task(revoke())
            await asyncio.sleep(0.5)
            assert not task.done()
            assert (await sql(store, "SELECT 1 FROM site_sessions")) == []
        result = await asyncio.wait_for(task, 10)
        assert result["revoked"] == 1
    finally:
        await conn_a.close()
        await conn_b.close()
    assert not await sql(
        store, "SELECT 1 FROM site_sessions WHERE player_uuid=%s", ("player-race",)
    )


async def test_site_sessions_completion_audit_atomic(store, monkeypatch):
    # Finding ..423: the completion audit commits in the same transaction as
    # the mutation (the app.write path). If it fails, the client gets 503 and
    # the mutation is rolled back, not half-committed.
    import cpv2.app as app_module

    await _site_sessions_token(store, "site-audit")
    created = await request(
        store,
        "POST",
        "/v2/site/sessions",
        {"sealedToken": "audit-keep", "playerUuid": "player-audit"},
        "site-audit",
    )
    assert created.status_code == 201, created.text
    sid = created.json()["sessionId"]
    real_audit = app_module.audit

    async def fail_completed(*args, **kwargs):
        outcome = args[5] if len(args) > 5 else kwargs.get("outcome")
        if outcome == "completed":
            raise psycopg.OperationalError("synthetic completion-audit outage")
        return await real_audit(*args, **kwargs)

    monkeypatch.setattr(app_module, "audit", fail_completed)
    failed = await request(
        store,
        "POST",
        "/v2/site/sessions",
        {"sealedToken": "audit-lost", "playerUuid": "player-audit-2"},
        "site-audit",
    )
    assert failed.status_code == 503, failed.text
    assert not await sql(
        store,
        "SELECT 1 FROM site_sessions WHERE player_uuid=%s",
        ("player-audit-2",),
    )
    # The delete routes share the same write wrapper: a failed completion
    # audit rolls the revoke back, so the row is still there after the 503.
    gone = await request(
        store, "DELETE", f"/v2/site/sessions/{sid}", None, "site-audit"
    )
    assert gone.status_code == 503, gone.text
    assert await sql(store, "SELECT 1 FROM site_sessions WHERE id=%s", (sid,))


async def _stats_token(store, server_id, cid="stats-producer"):
    if cid not in store["tokens"]:
        store["tokens"][cid] = await provision(
            store["admin"],
            {
                "client": {
                    "id": cid,
                    "via": "game",
                    "ceiling": ["stats.ingest"],
                },
                "ceiling": ["stats.ingest"],
                "environment": "prod",
                "backend": "game",
                "resource": server_id,
            },
        )
    return store["tokens"][cid]


def _stats_counter_set(**over):
    counters = {
        "kills": 3,
        "deaths": 1,
        "captures": 2,
        "neutralizations": 0,
        "pointSeconds": 90,
        "playSeconds": 120,
        "suicides": 0,
        "teamKills": 0,
        "maxKillstreak": 3,
    }
    counters.update(over)
    return counters


def _stats_campaign_body():
    return {
        "schemaVersion": 1,
        "eventId": "11111111-1111-1111-1111-111111111111",
        "serverId": "22222222-2222-2222-2222-222222222222",
        "kind": "campaign",
        "sessionPurpose": "gameplay",
        "modeId": "campaign",
        "ranked": True,
        "rulesetVersion": "review-v1",
        "matchId": None,
        "campaignSessionId": "11111111-1111-1111-1111-111111111111",
        "mapId": None,
        "startedAt": "2026-11-11T10:00:00Z",
        "endedAt": "2026-11-11T11:59:00.123456789Z",
        "endReason": "completed",
        "winner": "RED",
        "participants": [
            {
                "uuid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "name": "Игрок Один",
                "team": "RED",
                "score": 12.5,
                **_stats_counter_set(),
                "classes": [
                    {
                        "classId": "assault",
                        "variantId": "0",
                        "timeSeconds": 60,
                        "kills": 2,
                        "deaths": 1,
                        "pointSeconds": 40,
                    },
                    {
                        "classId": "medic",
                        "variantId": "10",
                        "timeSeconds": 60,
                        "kills": 1,
                        "deaths": 0,
                        "pointSeconds": 50,
                    },
                ],
            },
            {
                "uuid": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                "name": "Second Player",
                "team": "BLUE",
                "score": 7,
                **_stats_counter_set(
                    kills=1,
                    deaths=3,
                    captures=0,
                    neutralizations=1,
                    pointSeconds=30,
                    suicides=1,
                    maxKillstreak=1,
                ),
                "classes": [
                    {
                        "classId": "recon",
                        "variantId": "2",
                        "timeSeconds": 120,
                        "kills": 1,
                        "deaths": 3,
                        "pointSeconds": 30,
                    },
                ],
            },
        ],
        "rounds": ["33333333-3333-3333-3333-333333333333"],
        "telemetry": {
            "shots": 100,
            "fallbackShare": 0.00001,
            "tickMsP50": 0.0001,
            "tickMsP99": 12.5,
            "ageTicksP50": 2,
            "tickMsP99Overflow": False,
            "ageTicksP50Overflow": False,
            "rewindTicksP50": 1,
            "rewindTicksP50Overflow": True,
            "counters": {"hits": 80, "misses": 20},
            "tickMsBuckets": [{"le": 5, "count": 90}, {"le": 1e16, "count": 10}],
            "ageTickBuckets": [{"le": "inf", "count": 100}],
            "rewindTickBuckets": [{"le": 3, "count": 100}],
            "disputes": [{"tick": 42, "kind": "rewind", "ok": True}],
        },
    }


async def test_stats_provision_requires_bound_producer_credential(store):
    from cpv2.auth import SERVICE_SCOPES, STATS_SCOPES

    assert STATS_SCOPES == {"stats.ingest"}
    assert not STATS_SCOPES & SERVICE_SCOPES
    with pytest.raises(ValueError, match="bound producer credential"):
        await provision(
            store["admin"],
            {
                "client": {
                    "id": "stats-unbound",
                    "via": "game",
                    "ceiling": ["stats.ingest"],
                },
                "ceiling": ["stats.ingest"],
                "environment": "prod",
                "backend": "game",
                "resource": "*",
            },
        )
    with pytest.raises(ValueError, match="service credential ceiling"):
        await provision(
            store["admin"],
            {
                "client": {
                    "id": "stats-human",
                    "via": "game",
                    "ceiling": ["stats.ingest"],
                    "human": True,
                },
                "ceiling": ["stats.ingest"],
                "environment": "prod",
                "backend": "game",
                "resource": "22222222-2222-2222-2222-222222222222",
            },
        )
    with pytest.raises(ValueError, match="unknown scope"):
        await provision(
            store["admin"],
            {
                "client": {
                    "id": "stats-account",
                    "via": "cli",
                    "human": True,
                    "ceiling": sorted(SERVICE_SCOPES | STATS_SCOPES),
                },
                "accountId": str(uuid4()),
                "displayName": "stats-account",
                "ceiling": ["stats.ingest"],
                "environment": "prod",
                "backend": "game",
                "resource": "*",
            },
        )


async def test_stats_ingest_rbac(store):
    server = "22222222-2222-2222-2222-222222222222"
    await _stats_token(store, server)
    body = _stats_campaign_body()
    for role in ("ordinary", "builder", "moderator", "admin", "game-agent"):
        response = await request(store, "POST", "/v2/stats/results", body, role)
        assert response.status_code == 403, (role, response.text)
    assert (
        await request(store, "POST", "/v2/stats/results", body, "owner")
    ).status_code == 403
    assert (
        await store["client"].post("/v2/stats/results", json=body)
    ).status_code == 401
    other = "33333333-3333-3333-3333-333333333333"
    await _stats_token(store, other, "stats-other")
    forged = dict(body, serverId=server)
    response = await request(store, "POST", "/v2/stats/results", forged, "stats-other")
    assert response.status_code == 403, response.text
    denied = await request(store, "GET", "/v2/audit", None, "stats-producer")
    assert denied.status_code == 403, denied.text


async def test_stats_ingest_campaign_roundtrip_replay_and_conflict(store):
    server = "22222222-2222-2222-2222-222222222222"
    await _stats_token(store, server)
    body = _stats_campaign_body()
    created = await request(store, "POST", "/v2/stats/results", body, "stats-producer")
    assert created.status_code == 201, created.text
    assert created.json() == {
        "inserted": True,
        "eventId": "11111111-1111-1111-1111-111111111111",
    }
    rows = await sql(
        store,
        "SELECT digest,payload FROM stat_results WHERE server_id=%s",
        (server,),
    )
    assert len(rows) == 1
    assert rows[0]["digest"] == (
        "03fa04f02e46766d2f158e563b4a1e32fca61cdcf4bef721912375a9c22782dc"
    )
    assert rows[0]["payload"]["telemetry"]["fallbackShare"] == 0.00001
    assert await sql(store, "SELECT count(*) AS n FROM stat_participants") == [{"n": 2}]
    assert await sql(store, "SELECT count(*) AS n FROM stat_classes") == [{"n": 3}]
    names = await sql(store, "SELECT uuid,name FROM stat_profiles ORDER BY uuid")
    assert [(row["uuid"], row["name"]) for row in names] == [
        ("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "Игрок Один"),
        ("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "Second Player"),
    ]
    replayed = await request(store, "POST", "/v2/stats/results", body, "stats-producer")
    assert replayed.status_code == 200, replayed.text
    assert replayed.json() == {
        "inserted": False,
        "eventId": "11111111-1111-1111-1111-111111111111",
    }
    assert await sql(store, "SELECT count(*) AS n FROM stat_results") == [{"n": 1}]
    conflict = dict(body, winner="BLUE")
    denied = await request(
        store, "POST", "/v2/stats/results", conflict, "stats-producer"
    )
    assert denied.status_code == 409, denied.text
    assert denied.json() == {"error": "result_conflict"}
    kept = await sql(
        store,
        "SELECT digest FROM stat_results WHERE server_id=%s",
        (server,),
    )
    assert kept[0]["digest"] == rows[0]["digest"]


async def test_stats_ingest_validation(store):
    server = "22222222-2222-2222-2222-222222222222"
    await _stats_token(store, server, "stats-valid")
    cases = [
        {"schemaVersion": 2},
        {"eventId": "not-a-uuid"},
        {"sessionPurpose": "test"},
        {"modeId": "room", "ranked": True},
        {"kind": "campaign", "modeId": "room"},
        {"endReason": "abandoned", "winner": "RED"},
        {"startedAt": "2026-11-11T12:00:00Z"},
        {"endedAt": "2099-01-01T00:00:00Z"},
        {"endedAt": "not-a-time"},
        {"rounds": ["not-a-uuid"]},
        {"matchId": "00000000-0000-0000-0000-000000000000"},
        {"winnerUuid": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"},
    ]
    for index, patch in enumerate(cases):
        body = _stats_campaign_body()
        body.update(patch)
        response = await request(
            store, "POST", "/v2/stats/results", body, "stats-valid"
        )
        assert response.status_code == 422, (index, patch, response.text)
        assert response.json()["error"] == "invalid_result"
    players = _stats_campaign_body()
    players["participants"] = players["participants"] * 257
    response = await request(store, "POST", "/v2/stats/results", players, "stats-valid")
    assert response.status_code == 422, response.text
    dup = _stats_campaign_body()
    dup["participants"] = [dup["participants"][0], dup["participants"][0]]
    response = await request(store, "POST", "/v2/stats/results", dup, "stats-valid")
    assert response.status_code == 422, response.text
    bad_name = _stats_campaign_body()
    bad_name["participants"][0]["name"] = "has\x00control"
    response = await request(
        store, "POST", "/v2/stats/results", bad_name, "stats-valid"
    )
    assert response.status_code == 422, response.text


async def test_stats_ingest_drops_bad_telemetry_not_the_match(store):
    from cpv2 import core as core_module

    server = "22222222-2222-2222-2222-222222222222"
    await _stats_token(store, server, "stats-telemetry")
    before = core_module.telemetry_dropped
    body = _stats_campaign_body()
    body["eventId"] = "55555555-5555-5555-5555-555555555555"
    body["campaignSessionId"] = body["eventId"]
    body["telemetry"] = {"shots": -1}
    created = await request(store, "POST", "/v2/stats/results", body, "stats-telemetry")
    assert created.status_code == 201, created.text
    assert core_module.telemetry_dropped == before + 1
    rows = await sql(
        store,
        "SELECT payload FROM stat_results WHERE event_id=%s",
        (body["eventId"],),
    )
    assert "telemetry" not in rows[0]["payload"]


async def test_stats_ingest_drops_oversized_json_integer_telemetry(store):
    # A 400-digit fallbackShare is Infinity on the site and overflows
    # float() here: the block is dropped (never a 500) and the match ingests.
    from cpv2 import core as core_module

    server = "22222222-2222-2222-2222-222222222222"
    await _stats_token(store, server, "stats-bigint")
    before = core_module.telemetry_dropped
    body = _stats_campaign_body()
    body["eventId"] = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    body["campaignSessionId"] = body["eventId"]
    body["telemetry"]["fallbackShare"] = int("9" * 400)
    created = await request(store, "POST", "/v2/stats/results", body, "stats-bigint")
    assert created.status_code == 201, created.text
    assert core_module.telemetry_dropped == before + 1
    rows = await sql(
        store,
        "SELECT payload FROM stat_results WHERE event_id=%s",
        (body["eventId"],),
    )
    assert "telemetry" not in rows[0]["payload"]


async def test_stats_ingest_rejects_oversized_json_integer_score(store):
    # Outside telemetry there is no block to drop: a 400-digit score is a
    # 422 validation Problem, never an unhandled OverflowError/500.
    server = "22222222-2222-2222-2222-222222222222"
    await _stats_token(store, server, "stats-score")
    body = _stats_campaign_body()
    body["participants"][0]["score"] = 10**400
    response = await request(store, "POST", "/v2/stats/results", body, "stats-score")
    assert response.status_code == 422, response.text
    assert response.json()["error"] == "invalid_result"


async def test_stats_ingest_ffa_winner_and_large_body(store):
    server = "22222222-2222-2222-2222-222222222222"
    await _stats_token(store, server, "stats-size")
    body = _stats_ffa_body(server)
    created = await request(store, "POST", "/v2/stats/results", body, "stats-size")
    assert created.status_code == 201, created.text
    rows = await sql(
        store,
        "SELECT digest FROM stat_results WHERE event_id=%s",
        (body["eventId"],),
    )
    assert rows[0]["digest"] == (
        "ade4a1e9d923746a25ef06f362a35ef90aa9b6f5c9b8879e13b81a877073e221"
    )
    big = _stats_campaign_body()
    big["eventId"] = "66666666-6666-6666-6666-666666666666"
    big["campaignSessionId"] = big["eventId"]
    base = big["participants"][0]
    big["participants"] = [
        {
            **base,
            "uuid": str(uuid4()),
            "name": f"player-{index}",
            "team": "RED" if index % 2 else "BLUE",
        }
        for index in range(512)
    ]
    assert len(json.dumps(big).encode()) > 32768
    accepted = await request(store, "POST", "/v2/stats/results", big, "stats-size")
    assert accepted.status_code == 201, accepted.text
    assert await sql(
        store,
        "SELECT count(*) AS n FROM stat_participants WHERE event_id=%s",
        (big["eventId"],),
    ) == [{"n": 512}]
    huge = _stats_campaign_body()
    huge["eventId"] = "77777777-7777-7777-7777-777777777777"
    huge["campaignSessionId"] = huge["eventId"]
    entry = {
        "classId": "assault",
        "variantId": "0",
        "timeSeconds": 1,
        "kills": 0,
        "deaths": 0,
        "pointSeconds": 0,
    }
    huge["participants"] = [
        {
            **base,
            "uuid": str(uuid4()),
            "name": f"player-{index}",
            "classes": [{**entry, "variantId": str(slot)} for slot in range(256)],
        }
        for index in range(512)
    ]
    assert len(json.dumps(huge).encode()) > 1048576
    refused = await request(store, "POST", "/v2/stats/results", huge, "stats-size")
    assert refused.status_code == 413, refused.status_code
    assert refused.json() == {"error": "body_too_large"}


async def test_stats_ingest_display_name_cache_keeps_real_names(store):
    server = "22222222-2222-2222-2222-222222222222"
    await _stats_token(store, server, "stats-names")
    first = _stats_campaign_body()
    first["eventId"] = "88888888-8888-8888-8888-888888888888"
    first["campaignSessionId"] = first["eventId"]
    created = await request(store, "POST", "/v2/stats/results", first, "stats-names")
    assert created.status_code == 201, created.text
    second = _stats_campaign_body()
    second["eventId"] = "99999999-9999-9999-9999-999999999999"
    second["campaignSessionId"] = second["eventId"]
    second["participants"][0]["name"] = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    replayed = await request(store, "POST", "/v2/stats/results", second, "stats-names")
    assert replayed.status_code == 201, replayed.text
    names = await sql(
        store,
        "SELECT name FROM stat_profiles WHERE uuid=%s",
        ("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",),
    )
    assert names == [{"name": "Игрок Один"}]


def test_js_number_matches_site_stringify():
    from cpv2.core import _js_number

    assert _js_number(0.0) == "0"
    assert _js_number(-0.0) == "0"
    assert _js_number(1e-6) == "0.000001"
    assert _js_number(0.00001) == "0.00001"
    assert _js_number(0.0001) == "0.0001"
    assert _js_number(1e-7) == "1e-7"
    assert _js_number(123.456) == "123.456"
    assert _js_number(1e16) == "10000000000000000"
    assert _js_number(1e20) == "100000000000000000000"
    assert _js_number(1e21) == "1e+21"
    assert _js_number(1e300) == "1e+300"
    assert _js_number(-12.5) == "-12.5"
    assert _js_number(100) == "100"


def _stats_ffa_body(server="22222222-2222-2222-2222-222222222222"):
    return {
        "schemaVersion": 1,
        "eventId": "44444444-4444-4444-4444-444444444444",
        "serverId": server,
        "kind": "match",
        "sessionPurpose": "gameplay",
        "modeId": "deathmatch",
        "ranked": False,
        "rulesetVersion": "review-v1",
        "matchId": "44444444-4444-4444-4444-444444444444",
        "campaignSessionId": None,
        "mapId": "arena-1",
        "startedAt": "2026-11-11T10:00:00Z",
        "endedAt": "2026-11-11T10:30:00Z",
        "endReason": "completed",
        "winner": "NONE",
        "winnerUuid": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "participants": [
            {
                "uuid": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                "name": "Second Player",
                "team": "NONE",
                "score": -0.0,
                **_stats_counter_set(
                    kills=5,
                    deaths=2,
                    captures=0,
                    neutralizations=0,
                    pointSeconds=0,
                    playSeconds=60,
                    maxKillstreak=4,
                ),
                "classes": [],
            }
        ],
        "rounds": [],
    }


def test_stats_digest_matches_site_producer_contract():
    # Digests pinned against the site's own validateResult+canonical run on
    # origin/main (node evidence in .dev/sitedbu1-c1 for P1/P2 and
    # .dev/sitedbu1-c2 for the P3 large-integer bucket, not committed): a
    # dual-write reconcile can compare digests across the two stores.
    import datetime

    from cpv2.core import _stat_canonical, validate_stat_result

    now = int(
        datetime.datetime(
            2026, 11, 11, 12, 0, 0, tzinfo=datetime.timezone.utc
        ).timestamp()
        * 1000
    )
    campaign, campaign_digest, _ = validate_stat_result(_stats_campaign_body(), now)
    assert campaign["telemetry"]["fallbackShare"] == 0.00001
    assert campaign_digest == (
        "03fa04f02e46766d2f158e563b4a1e32fca61cdcf4bef721912375a9c22782dc"
    )
    ffa, ffa_digest, _ = validate_stat_result(_stats_ffa_body(), now)
    assert ffa["winnerUuid"] == "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    assert ffa_digest == (
        "ade4a1e9d923746a25ef06f362a35ef90aa9b6f5c9b8879e13b81a877073e221"
    )
    p3 = _stats_campaign_body()
    p3["eventId"] = "cccccccc-cccc-cccc-cccc-cccccccccccc"
    p3["campaignSessionId"] = p3["eventId"]
    p3["rounds"] = ["dddddddd-dddd-dddd-dddd-dddddddddddd"]
    p3["telemetry"]["tickMsBuckets"] = [
        {"le": 9007199254740993, "count": 90},
        {"le": "inf", "count": 10},
    ]
    p3clean, p3_digest, _ = validate_stat_result(p3, now)
    # 2**53+1 is not exactly representable: both sides canonicalize the
    # double the site's JSON.parse produces, not the source digits.
    assert '"le":9007199254740992' in _stat_canonical(p3clean)
    assert p3_digest == (
        "03c233d10842cc43553a73bc03f66552debb192ef05c5c3929c7497cad189d0b"
    )


async def _stats_reader_token(store, cid="stats-reader"):
    # Unbound service credential with stats.read (site SSR/launcher/bot path).
    if cid not in store["tokens"]:
        store["tokens"][cid] = await provision(
            store["admin"],
            {
                "client": {"id": cid, "via": "game", "ceiling": ["stats.read"]},
                "ceiling": ["stats.read"],
                "environment": "prod",
                "backend": "game",
                "resource": "*",
            },
        )
    return store["tokens"][cid]


def _stats_u3_participant(uuid, name, team, score, kills, deaths, classes, **over):
    counters = _stats_counter_set()
    counters.update({"kills": kills, "deaths": deaths, **over})
    return {
        "uuid": uuid,
        "name": name,
        "team": team,
        "score": score,
        **counters,
        "classes": classes,
    }


def _stats_u3_class(class_id, variant_id, time_seconds, kills, deaths, point_seconds=0):
    return {
        "classId": class_id,
        "variantId": variant_id,
        "timeSeconds": time_seconds,
        "kills": kills,
        "deaths": deaths,
        "pointSeconds": point_seconds,
    }


def _stats_u3_match_body(
    event,
    server,
    started,
    ended,
    winner,
    participants,
    telemetry=None,
    mode="room",
):
    body = {
        "schemaVersion": 1,
        "eventId": event,
        "serverId": server,
        "kind": "match",
        "sessionPurpose": "gameplay",
        "modeId": mode,
        "ranked": False,
        "rulesetVersion": "review-v1",
        "matchId": event,
        "campaignSessionId": None,
        "mapId": "fields",
        "startedAt": started,
        "endedAt": ended,
        "endReason": "completed",
        "winner": winner,
        "participants": participants,
        "rounds": [],
    }
    if telemetry is not None:
        body["telemetry"] = telemetry
    return body


def _stats_u3_telemetry():
    return {
        "shots": 100,
        "fallbackShare": 0.25,
        "tickMsP50": 5,
        "tickMsP99": 20,
        "ageTicksP50": 2,
        "tickMsP99Overflow": False,
        "ageTicksP50Overflow": False,
        "rewindTicksP50": 1,
        "rewindTicksP50Overflow": False,
        "counters": {"hits": 70, "shots_fired": 100},
        "tickMsBuckets": [{"le": 10, "count": 100}],
        "ageTickBuckets": [{"le": "inf", "count": 100}],
        "rewindTickBuckets": [{"le": 3, "count": 100}],
        "disputes": [{"tick": 7, "kind": "rewind"}],
    }


def _stats_u3_campaign_body(event, server, ended, winner, participants):
    return {
        "schemaVersion": 1,
        "eventId": event,
        "serverId": server,
        "kind": "campaign",
        "sessionPurpose": "gameplay",
        "modeId": "campaign",
        "ranked": True,
        "rulesetVersion": "review-v1",
        "matchId": None,
        "campaignSessionId": event,
        "mapId": None,
        "startedAt": "2026-11-11T11:00:00Z",
        "endedAt": ended,
        "endReason": "completed",
        "winner": winner,
        "participants": participants,
        "rounds": ["33333333-3333-3333-3333-333333333333"],
    }


def _stats_c4_campaign_body(event, ended, winner, started="2026-11-11T11:00:00Z"):
    body = _stats_u3_campaign_body(
        event,
        _U3_SERVER,
        ended,
        winner,
        [
            _stats_u3_participant(
                _U3_PA,
                "Игрок Альфа",
                "RED",
                4,
                1,
                3,
                [_stats_u3_class("assault", "0", 30, 1, 3, 5)],
            ),
            _stats_u3_participant(
                _U3_PB,
                "Player Beta",
                "BLUE",
                9,
                6,
                1,
                [_stats_u3_class("recon", "2", 120, 6, 1, 30)],
            ),
        ],
    )
    body["startedAt"] = started
    return body


_U3_SERVER = "55555555-5555-4555-8555-555555555555"
_U3_PA = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1"
_U3_PB = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbb2"
_U3_M1 = "66666666-6666-4666-8666-666666666666"
_U3_M2 = "77777777-7777-4777-8777-777777777777"
_U3_C1 = "88888888-8888-4888-8888-888888888888"


async def _stats_u3_seed(store):
    await _stats_token(store, _U3_SERVER, "stats-u3-producer")
    matches = [
        _stats_u3_match_body(
            _U3_M1,
            _U3_SERVER,
            "2026-11-11T09:00:00Z",
            "2026-11-11T10:00:00Z",
            "RED",
            [
                _stats_u3_participant(
                    _U3_PA,
                    "Игрок Альфа",
                    "RED",
                    10,
                    5,
                    0,
                    [_stats_u3_class("assault", "0", 60, 5, 0, 10)],
                    captures=1,
                ),
                _stats_u3_participant(
                    _U3_PB,
                    "Player Beta",
                    "BLUE",
                    7,
                    2,
                    5,
                    [_stats_u3_class("recon", "2", 60, 2, 5, 3)],
                ),
            ],
            _stats_u3_telemetry(),
        ),
        _stats_u3_match_body(
            _U3_M2,
            _U3_SERVER,
            "2026-11-11T10:00:00Z",
            "2026-11-11T11:00:00Z",
            "BLUE",
            [
                _stats_u3_participant(
                    _U3_PA,
                    "Игрок Альфа",
                    "RED",
                    4,
                    1,
                    3,
                    [
                        _stats_u3_class("assault", "0", 30, 1, 3, 5),
                        _stats_u3_class("medic", "1", 90, 0, 0, 20),
                    ],
                ),
                _stats_u3_participant(
                    _U3_PB,
                    "Player Beta",
                    "BLUE",
                    9,
                    6,
                    1,
                    [_stats_u3_class("recon", "2", 120, 6, 1, 30)],
                    captures=1,
                ),
            ],
        ),
    ]
    for body in matches:
        response = await request(
            store, "POST", "/v2/stats/results", body, "stats-u3-producer"
        )
        assert response.status_code == 201, response.text
    campaign = _stats_u3_campaign_body(
        _U3_C1,
        _U3_SERVER,
        "2026-11-11T12:00:00Z",
        "RED",
        [
            _stats_u3_participant(
                _U3_PA,
                "Игрок Альфа",
                "RED",
                12,
                4,
                1,
                [_stats_u3_class("assault", "0", 500, 4, 1, 100)],
            ),
            _stats_u3_participant(
                _U3_PB,
                "Player Beta",
                "BLUE",
                8,
                2,
                4,
                [_stats_u3_class("recon", "2", 500, 2, 4, 50)],
            ),
        ],
    )
    response = await request(
        store, "POST", "/v2/stats/results", campaign, "stats-u3-producer"
    )
    assert response.status_code == 201, response.text
    await _stats_reader_token(store)


async def _stats_wait_idle(store, season="s2", timeout=15):
    # The void request only enqueues; the background loop replays within a
    # poll interval. Wait until the season flag clears.
    deadline = time.monotonic() + timeout
    while True:
        board = await request(
            store, "GET", f"/v2/stats/leaderboard?season={season}", None, "stats-reader"
        )
        assert board.status_code == 200, board.text
        if not board.json()["ratingsRebuilding"]:
            return board.json()
        assert time.monotonic() < deadline, "rating rebuild did not finish"
        await asyncio.sleep(0.2)


def test_stats_glicko2_matches_site_algorithm():
    # Pinned outputs of the site's own glicko2.ts (origin/next e48b327) run
    # under node (.dev/u-sitedb-u3/parity-battery.mjs + parity-output.json):
    # the CP port must agree bit-for-bit on the same fixture.
    from cpv2.core import (
        _stat_glicko_composite,
        _stat_glicko_inflate,
        _stat_glicko_initial,
        _stat_glicko_soft_reset,
        _stat_glicko_update,
        _stat_js_round,
        _stat_mmr,
    )

    red0, blue0 = _stat_glicko_initial(), _stat_glicko_initial()
    red1 = _stat_glicko_update(
        red0, [{"opponent": _stat_glicko_composite([blue0]), "score": 1}]
    )
    blue1 = _stat_glicko_update(
        blue0, [{"opponent": _stat_glicko_composite([red0]), "score": 0}]
    )
    assert red1 == {
        "rating": 1662.3108939062977,
        "rd": 290.31896371798047,
        "volatility": 0.05999967537233814,
    }
    assert blue1 == {
        "rating": 1337.6891060937023,
        "rd": 290.31896371798047,
        "volatility": 0.05999967537233814,
    }
    assert _stat_mmr(
        {"rating": red1["rating"], "rd": red1["rd"], "ratedCampaigns": 1}
    ) == {
        "rating": 1662,
        "rd": 290,
        "ratedCampaigns": 1,
        "provisional": True,
    }
    inflated = _stat_glicko_inflate(
        {"rating": red1["rating"], "rd": red1["rd"], "volatility": red1["volatility"]},
        0,
    )
    red2 = _stat_glicko_update(
        inflated,
        [
            {
                "opponent": _stat_glicko_composite(
                    [{"rating": blue1["rating"], "rd": blue1["rd"]}]
                ),
                "score": 0.5,
            }
        ],
    )
    assert red2 == {
        "rating": 1576.6886643068638,
        "rd": 260.48876356402207,
        "volatility": 0.05999914867562188,
    }
    assert _stat_glicko_soft_reset(
        {"rating": 1700, "rd": 60, "volatility": 0.06}, 1
    ) == {
        "rating": 1600,
        "rd": 200,
        "volatility": 0.06,
    }
    assert _stat_glicko_soft_reset(
        {"rating": 1700, "rd": 60, "volatility": 0.06}, 2
    ) == {
        "rating": 1550,
        "rd": 200,
        "volatility": 0.06,
    }
    assert _stat_glicko_composite(
        [{"rating": 1600, "rd": 100}, {"rating": 1400, "rd": 200}]
    ) == {
        "rating": 1500,
        "rd": 158.11388300841898,
    }
    assert _stat_glicko_inflate({"rating": 1600, "rd": 60, "volatility": 0.06}, 3) == {
        "rating": 1600,
        "rd": 62.65717069576213,
        "volatility": 0.06,
    }
    assert _stat_glicko_update({"rating": 1600, "rd": 100, "volatility": 0.06}, []) == {
        "rating": 1600,
        "rd": 100.54173435212178,
        "volatility": 0.06,
    }
    # Site Math.round is half-up; Python round() is banker's: 1500.5 -> 1501.
    assert _stat_js_round(1500.5) == 1501
    assert _stat_mmr({"rating": 1500.5, "rd": 150.0, "ratedCampaigns": 5}) == {
        "rating": 1501,
        "rd": 150,
        "ratedCampaigns": 5,
        "provisional": False,
    }
    assert _stat_mmr({"rating": None, "rd": None, "ratedCampaigns": None}) is None


def test_stats_seasons_match_site_contract():
    # Pinned seasons() output of the site (same node battery): s1 alpha,
    # s2 to end of 2026, then UTC quarters.
    from cpv2.core import stat_season_at, stat_seasons

    nov = stat_seasons(1793836800000)
    assert nov == [
        {
            "id": "s1",
            "name": "Альфа Сезон",
            "startsAt": "2026-09-14T00:00:00.000Z",
            "endsAt": "2026-09-25T23:59:59.999Z",
        },
        {
            "id": "s2",
            "name": "Сезон 1",
            "startsAt": "2026-09-26T00:00:00.000Z",
            "endsAt": "2026-12-31T23:59:59.999Z",
        },
    ]
    assert [s["id"] for s in stat_seasons(1805068800000)] == ["s1", "s2", "s3"]
    assert stat_season_at(1577836800000)["id"] == "s1"
    assert stat_season_at(1792900000000)["id"] == "s2"


async def test_stats_seasons_route(store):
    await _stats_reader_token(store)
    response = await request(store, "GET", "/v2/stats/seasons", None, "stats-reader")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["schemaVersion"] == 1
    assert body["current"] == body["seasons"][-1]["id"]
    assert [s["id"] for s in body["seasons"][:2]] == ["s1", "s2"]
    assert body["seasons"][0]["startsAt"] == "2026-09-14T00:00:00.000Z"
    assert body["seasons"][1] == {
        "id": "s2",
        "name": "Сезон 1",
        "startsAt": "2026-09-26T00:00:00.000Z",
        "endsAt": "2026-12-31T23:59:59.999Z",
    }


async def test_stats_reads_require_stats_read_scope(store):
    await _stats_token(store, _U3_SERVER, "stats-u3-producer")
    await _stats_reader_token(store)
    for path in (
        "/v2/stats/seasons",
        "/v2/stats/leaderboard",
        f"/v2/stats/players/{_U3_PA}",
        "/v2/stats/hitreg",
    ):
        assert (await store["client"].get(path)).status_code == 401
        denied = await request(store, "GET", path, None, "stats-u3-producer")
        assert denied.status_code == 403, denied.text
        assert denied.json() == {"error": "forbidden"}
    void = {"serverId": _U3_SERVER, "eventId": _U3_M1, "voided": True}
    assert (
        await store["client"].post("/v2/stats/results/void", json=void)
    ).status_code == 401
    denied = await request(
        store, "POST", "/v2/stats/results/void", void, "stats-u3-producer"
    )
    assert denied.status_code == 403, denied.text
    denied = await request(
        store, "POST", "/v2/stats/results/void", void, "stats-reader"
    )
    assert denied.status_code == 403, denied.text


async def test_stats_filters_reject_like_site(store):
    await _stats_reader_token(store)
    from cpv2.core import stat_seasons

    future = f"s{len(stat_seasons()) + 1}"
    cases = [
        "mode=arena",
        "period=year",
        "sort=unknown",
        "season=s2&period=all",
        "season=s2&period=week",
        "season=s99",
        f"season={future}",
        "limit=0",
        "limit=101",
        "limit=abc",
        "limit=25.0",
        "page=0",
        "page=1001",
        "page=x",
    ]
    for query in cases:
        response = await request(
            store, "GET", f"/v2/stats/leaderboard?{query}", None, "stats-reader"
        )
        assert response.status_code == 400, (query, response.text)
        assert response.json() == {"error": "invalid_stats_filter"}, query


async def test_stats_leaderboard_player_hitreg_roundtrip(store):
    await _stats_u3_seed(store)
    board = await request(
        store, "GET", "/v2/stats/leaderboard?season=s2", None, "stats-reader"
    )
    assert board.status_code == 200, board.text
    body = board.json()
    assert body["schemaVersion"] == 1
    assert body["mode"] is None
    assert body["season"] == "s2"
    assert body["mmrSeason"] == "s2"
    assert body["page"] == 1 and body["limit"] == 25
    assert body["total"] == 2
    assert body["ratingStatus"] == "glicko2-v1"
    assert [p["uuid"] for p in body["players"]] == [_U3_PB, _U3_PA]
    first, second = body["players"]
    assert (first["rank"], second["rank"]) == (1, 2)
    assert (first["score"], second["score"]) == (16.0, 14.0)
    assert (first["kills"], first["deaths"], first["kd"]) == (8, 6, 1.333)
    assert (second["kills"], second["deaths"], second["kd"]) == (6, 3, 2.0)
    assert (first["wins"], second["wins"]) == (1, 1)
    assert (first["matches"], second["matches"]) == (2, 2)
    assert first["mmr"] == {
        "rating": 1338,
        "rd": 290,
        "ratedCampaigns": 1,
        "provisional": True,
    }
    assert second["mmr"] == {
        "rating": 1662,
        "rd": 290,
        "ratedCampaigns": 1,
        "provisional": True,
    }
    # Campaign summaries never count round kills/score twice.
    assert first["captures"] == 3 and second["captures"] == 3
    # Sort/rank contract: ties break by uuid ascending.
    tied = (
        await request(
            store,
            "GET",
            "/v2/stats/leaderboard?season=s2&sort=captures",
            None,
            "stats-reader",
        )
    ).json()["players"]
    assert [(p["uuid"], p["rank"]) for p in tied] == [(_U3_PA, 1), (_U3_PB, 2)]
    kills = (
        await request(
            store,
            "GET",
            "/v2/stats/leaderboard?season=s2&sort=kd",
            None,
            "stats-reader",
        )
    ).json()["players"]
    assert [p["uuid"] for p in kills] == [_U3_PA, _U3_PB]
    rated = (
        await request(
            store,
            "GET",
            "/v2/stats/leaderboard?season=s2&sort=rating",
            None,
            "stats-reader",
        )
    ).json()["players"]
    assert [p["uuid"] for p in rated] == [_U3_PA, _U3_PB]
    empty = (
        await request(
            store, "GET", "/v2/stats/leaderboard?season=s1", None, "stats-reader"
        )
    ).json()
    assert empty["total"] == 0 and empty["players"] == [] and empty["mmrSeason"] == "s1"

    player = await request(
        store, "GET", f"/v2/stats/players/{_U3_PA}?season=s2", None, "stats-reader"
    )
    assert player.status_code == 200, player.text
    data = player.json()
    assert data["schemaVersion"] == 1
    assert data["profile"] == {
        "uuid": _U3_PA,
        "name": "Игрок Альфа",
        "lastSeen": 1794398400000,
    }
    assert data["totals"]["rank"] == 2
    assert data["totals"]["score"] == 14.0
    assert data["campaigns"] == {"completed": 1, "wins": 1}
    # Classes aggregate matches only: the 500 s campaign breakdown stays out.
    assert data["classes"] == [
        {
            "classId": "assault",
            "variantId": "0",
            "timeSeconds": 90,
            "kills": 6,
            "deaths": 3,
            "pointSeconds": 15,
        },
        {
            "classId": "medic",
            "variantId": "1",
            "timeSeconds": 90,
            "kills": 0,
            "deaths": 0,
            "pointSeconds": 20,
        },
    ]
    assert [(h["eventId"], h["kind"]) for h in data["history"]] == [
        (_U3_C1, "campaign"),
        (_U3_M2, "match"),
        (_U3_M1, "match"),
    ]
    assert data["history"][0]["winner"] == "RED"
    assert data["history"][2]["winnerUuid"] is None
    assert data["mmr"] == {
        "rating": 1662,
        "rd": 290,
        "ratedCampaigns": 1,
        "provisional": True,
    }
    assert data["ratingHistory"] == [
        {
            "campaignSessionId": _U3_C1,
            "ratedAt": 1794398400000,
            "team": "RED",
            "score": 1,
            "before": 1500,
            "after": 1662,
            "rd": 290,
        }
    ]
    assert data["ratingStatus"] == "glicko2-v1"
    unknown = await request(
        store,
        "GET",
        "/v2/stats/players/99999999-9999-4999-8999-999999999999?season=s2",
        None,
        "stats-reader",
    )
    assert unknown.status_code == 404, unknown.text
    malformed = await request(
        store, "GET", "/v2/stats/players/not-a-uuid?season=s2", None, "stats-reader"
    )
    assert malformed.status_code == 400, malformed.text

    hitreg = (
        await request(store, "GET", "/v2/stats/hitreg?season=s2", None, "stats-reader")
    ).json()
    assert hitreg["schemaVersion"] == 1
    assert hitreg["mode"] is None
    assert hitreg["matches"] == 2
    assert hitreg["withTelemetry"] == 1
    assert hitreg["truncated"] is False
    assert hitreg["shots"] == 100
    assert hitreg["fallbackShare"] == 0.25
    assert hitreg["disputes"] == 1
    assert hitreg["counters"] == {"hits": 70, "shots_fired": 100}
    assert hitreg["tickMsP50Median"] == 5.0
    assert hitreg["tickMsP99P99"] == 20.0
    assert hitreg["ageTicksP50Median"] == 2.0
    assert hitreg["rewindTicksP50Median"] == 1.0


async def test_stats_void_replays_ratings_like_site(store):
    await _stats_u3_seed(store)

    async def mmr_of(uuid):
        player = (
            await request(
                store,
                "GET",
                f"/v2/stats/players/{uuid}?season=s2",
                None,
                "stats-reader",
            )
        ).json()
        return player["mmr"], player["ratingHistory"]

    before_a, history_a = await mmr_of(_U3_PA)
    assert before_a == {
        "rating": 1662,
        "rd": 290,
        "ratedCampaigns": 1,
        "provisional": True,
    }
    assert len(history_a) == 1
    # Matches are not rated: voiding one only removes its battles.
    match_void = {"serverId": _U3_SERVER, "eventId": _U3_M1, "voided": True}
    response = await request(
        store, "POST", "/v2/stats/results/void", match_void, "admin"
    )
    assert response.status_code == 200, response.text
    assert response.json()["rebuilt"] is None
    board = (
        await request(
            store, "GET", "/v2/stats/leaderboard?season=s2", None, "stats-reader"
        )
    ).json()
    assert {p["uuid"]: (p["matches"], p["score"]) for p in board["players"]} == {
        _U3_PA: (1, 4.0),
        _U3_PB: (1, 9.0),
    }
    # Voiding the rated campaign enqueues a background replay: the request
    # returns at once, the worker clears the ratings shortly after.
    campaign_void = {"serverId": _U3_SERVER, "eventId": _U3_C1, "voided": True}
    response = await request(
        store, "POST", "/v2/stats/results/void", campaign_void, "admin"
    )
    assert response.status_code == 200, response.text
    assert response.json()["rebuilt"] == "s2"
    await _stats_wait_idle(store)
    after_a, history_after = await mmr_of(_U3_PA)
    assert after_a is None and history_after == []
    assert await sql(store, "SELECT count(*) AS n FROM stat_rating_rebuilds") == [
        {"n": 0}
    ]
    # Double void conflicts; restoring replays the same ratings back.
    conflict = await request(
        store, "POST", "/v2/stats/results/void", campaign_void, "admin"
    )
    assert conflict.status_code == 409, conflict.text
    restore = {"serverId": _U3_SERVER, "eventId": _U3_C1, "voided": False}
    response = await request(store, "POST", "/v2/stats/results/void", restore, "admin")
    assert response.status_code == 200, response.text
    assert response.json()["rebuilt"] == "s2"
    await _stats_wait_idle(store)
    restored_a, history_restored = await mmr_of(_U3_PA)
    assert restored_a == before_a and history_restored == history_a
    missing = await request(
        store,
        "POST",
        "/v2/stats/results/void",
        {"serverId": _U3_SERVER, "eventId": _U3_M2, "voided": False},
        "admin",
    )
    assert missing.status_code == 409, missing.text
    gone = await request(
        store,
        "POST",
        "/v2/stats/results/void",
        {
            "serverId": _U3_SERVER,
            "eventId": "99999999-9999-4999-8999-999999999999",
            "voided": True,
        },
        "admin",
    )
    assert gone.status_code == 404, gone.text


async def test_stats_migration_005_backfills_pre_005_results(store):
    # Results ingested before 005 have no ratings rows; applying 005 replays
    # them so the store equals a fresh ingest, and re-migrating is a no-op.
    from cpv2.db import migrate
    from psycopg.conninfo import conninfo_to_dict

    await _stats_u3_seed(store)
    ratings_query = (
        "SELECT season_id,uuid,rating,rd,volatility,rated_campaigns,last_rated_at"
        " FROM stat_ratings ORDER BY uuid"
    )
    changes_query = (
        "SELECT server_id,event_id,uuid,rules_version,team,score,opp_rating,opp_rd,"
        "before_rating,before_rd,before_volatility,after_rating,after_rd,"
        "after_volatility,rated_at,season_id FROM stat_rating_changes"
        " ORDER BY server_id,event_id,uuid"
    )
    before = await sql(store, ratings_query)
    changes_before = await sql(store, changes_query)
    assert len(before) == 2 and len(changes_before) == 2
    dbname = conninfo_to_dict(store["admin"])["dbname"]
    async with await psycopg.AsyncConnection.connect(
        store["admin"], autocommit=True
    ) as conn:
        await conn.execute("DROP TABLE control.stat_rating_rebuilds")
        await conn.execute("DROP TABLE control.stat_result_voids")
        await conn.execute("DROP TABLE control.stat_rating_changes")
        await conn.execute("DROP TABLE control.stat_ratings")
        await conn.execute("DROP TABLE control.stat_events")
        await conn.execute("DROP TABLE control.stat_samples")
        await conn.execute("DELETE FROM control.schema_migrations WHERE version>=5")
    await migrate(store["admin"], dbname)
    assert await sql(store, ratings_query) == before
    assert await sql(store, changes_query) == changes_before
    await migrate(store["admin"], dbname)
    assert await sql(store, ratings_query) == before


async def test_stats_winner_none_completed_is_stored_unrated(store):
    # A completed campaign without a winner is stored but never rated (the
    # site scored it as a loss for both sides); a draw still splits the point.
    server = "22222222-2222-2222-2222-222222222222"
    await _stats_token(store, server, "stats-none")
    await _stats_reader_token(store)
    participants = [
        _stats_u3_participant(
            _U3_PA,
            "Игрок Альфа",
            "RED",
            10,
            5,
            0,
            [_stats_u3_class("assault", "0", 60, 5, 0, 10)],
        ),
        _stats_u3_participant(
            _U3_PB,
            "Player Beta",
            "BLUE",
            7,
            2,
            5,
            [_stats_u3_class("recon", "2", 60, 2, 5, 3)],
        ),
    ]
    none_event = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    none = _stats_u3_campaign_body(
        none_event, server, "2026-11-11T12:00:00Z", "NONE", participants
    )
    created = await request(store, "POST", "/v2/stats/results", none, "stats-none")
    assert created.status_code == 201, created.text
    stored = await sql(
        store, "SELECT 1 FROM stat_results WHERE event_id=%s", (none_event,)
    )
    assert len(stored) == 1
    changes = await sql(
        store,
        "SELECT uuid FROM stat_rating_changes WHERE event_id=%s",
        (none_event,),
    )
    assert changes == []
    ratings = await sql(store, "SELECT uuid FROM stat_ratings WHERE season_id='s2'")
    assert ratings == []
    # The gap scan must not treat the unrated campaign as a missing rating.
    from cpv2.core import stat_gap_scan

    async with store["app"].state.db.transaction() as conn:
        assert await stat_gap_scan(conn) is None
    draw_event = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    draw = _stats_u3_campaign_body(
        draw_event, server, "2026-11-11T13:00:00Z", "NONE", participants
    )
    draw["endReason"] = "draw"
    created = await request(store, "POST", "/v2/stats/results", draw, "stats-none")
    assert created.status_code == 201, created.text
    changes = await sql(
        store,
        "SELECT uuid,score FROM stat_rating_changes WHERE event_id=%s ORDER BY uuid",
        (draw_event,),
    )
    assert [(row["uuid"], row["score"]) for row in changes] == [
        (_U3_PA, 0.5),
        (_U3_PB, 0.5),
    ]


async def test_stats_leaderboard_every_sort_key(store):
    from cpv2.core import STAT_SORTS

    await _stats_u3_seed(store)
    for sort in STAT_SORTS:
        response = await request(
            store,
            "GET",
            f"/v2/stats/leaderboard?season=s2&sort={sort}",
            None,
            "stats-reader",
        )
        assert response.status_code == 200, (sort, response.text)
        body = response.json()
        assert body["total"] == 2 and len(body["players"]) == 2, sort
        assert body["ratingsRebuilding"] is False, sort


async def test_stats_void_returns_fast_and_rebuild_matches_replay(store):
    await _stats_u3_seed(store)
    player = (
        await request(
            store, "GET", f"/v2/stats/players/{_U3_PA}?season=s2", None, "stats-reader"
        )
    ).json()
    assert player["ratingsRebuilding"] is False
    started = time.monotonic()
    response = await request(
        store,
        "POST",
        "/v2/stats/results/void",
        {"serverId": _U3_SERVER, "eventId": _U3_C1, "voided": True},
        "admin",
    )
    assert response.status_code == 200, response.text
    assert response.json()["rebuilt"] == "s2"
    assert time.monotonic() - started < 5
    await _stats_wait_idle(store)
    # Restore, then immediately ingest a second campaign while the rebuild is
    # pending: the ingest serializes on the rating lock and stays correct.
    restore = await request(
        store,
        "POST",
        "/v2/stats/results/void",
        {"serverId": _U3_SERVER, "eventId": _U3_C1, "voided": False},
        "admin",
    )
    assert restore.status_code == 200, restore.text
    second_event = "99999999-9999-4999-8999-999999999999"
    second = _stats_u3_campaign_body(
        second_event,
        _U3_SERVER,
        "2026-11-11T13:00:00Z",
        "BLUE",
        [
            _stats_u3_participant(
                _U3_PA,
                "Игрок Альфа",
                "RED",
                4,
                1,
                3,
                [_stats_u3_class("assault", "0", 30, 1, 3, 5)],
            ),
            _stats_u3_participant(
                _U3_PB,
                "Player Beta",
                "BLUE",
                9,
                6,
                1,
                [_stats_u3_class("recon", "2", 120, 6, 1, 30)],
            ),
        ],
    )
    created = await request(
        store, "POST", "/v2/stats/results", second, "stats-u3-producer"
    )
    assert created.status_code == 201, created.text
    await _stats_wait_idle(store)
    history = (
        await request(
            store, "GET", f"/v2/stats/players/{_U3_PA}?season=s2", None, "stats-reader"
        )
    ).json()
    assert [row["campaignSessionId"] for row in history["ratingHistory"]] == [
        second_event,
        _U3_C1,
    ]
    assert [row["score"] for row in history["ratingHistory"]] == [0, 1]
    assert history["mmr"]["ratedCampaigns"] == 2
    assert history["ratingsRebuilding"] is False
    # The worker's replay and a manual full replay of the results table agree.
    snap = await sql(
        store,
        "SELECT season_id,uuid,rating,rd,volatility,rated_campaigns FROM stat_ratings ORDER BY uuid",
    )
    from cpv2.core import _stat_rebuild_ratings, stat_seasons

    season = next(s for s in stat_seasons() if s["id"] == "s2")
    async with await psycopg.AsyncConnection.connect(
        store["admin"],
        options="-c search_path=control,pg_catalog",
        row_factory=psycopg.rows.dict_row,
    ) as conn:
        async with conn.transaction():
            await _stat_rebuild_ratings(conn, season)
    assert (
        await sql(
            store,
            "SELECT season_id,uuid,rating,rd,volatility,rated_campaigns FROM stat_ratings ORDER BY uuid",
        )
        == snap
    )


async def test_stats_c3_batched_replay_never_blocks_requests(store, monkeypatch):
    # Round 3A: the replay holds the rating lock per bounded batch only. With
    # a mocked slow batch in flight, a void and an ingest still complete
    # without waiting for the whole replay, and ratings converge afterwards.
    await _stats_u3_seed(store)
    extras = []
    for hour, event in (
        ("13", "99999991-9999-4999-8999-999999999999"),
        ("14", "99999992-9999-4999-8999-999999999999"),
        ("15", "99999993-9999-4999-8999-999999999999"),
    ):
        body = _stats_u3_campaign_body(
            event,
            _U3_SERVER,
            f"2026-11-11T{hour}:00:00Z",
            "RED" if hour != "14" else "BLUE",
            [
                _stats_u3_participant(
                    _U3_PA,
                    "Игрок Альфа",
                    "RED",
                    4,
                    1,
                    3,
                    [_stats_u3_class("assault", "0", 30, 1, 3, 5)],
                ),
                _stats_u3_participant(
                    _U3_PB,
                    "Player Beta",
                    "BLUE",
                    9,
                    6,
                    1,
                    [_stats_u3_class("recon", "2", 120, 6, 1, 30)],
                ),
            ],
        )
        created = await request(
            store, "POST", "/v2/stats/results", body, "stats-u3-producer"
        )
        assert created.status_code == 201, created.text
        extras.append(event)
    real_rate = core._stat_rate

    async def slow_rate(conn, clean, ended_ms):
        await asyncio.sleep(0.5)
        return await real_rate(conn, clean, ended_ms)

    monkeypatch.setattr(core, "_stat_rate", slow_rate)
    voided = await request(
        store,
        "POST",
        "/v2/stats/results/void",
        {"serverId": _U3_SERVER, "eventId": _U3_C1, "voided": True},
        "admin",
    )
    assert voided.status_code == 200, voided.text

    async def drain_once():
        async with await psycopg.AsyncConnection.connect(
            store["admin"],
            options="-c search_path=control,pg_catalog",
            row_factory=psycopg.rows.dict_row,
        ) as conn:
            async with conn.transaction():
                await core.stat_rebuild_drain(conn)

    replay = asyncio.create_task(drain_once())
    await asyncio.sleep(0.3)
    fresh_event = "99999994-9999-4999-8999-999999999999"
    fresh = _stats_u3_campaign_body(
        fresh_event,
        _U3_SERVER,
        "2026-11-11T16:00:00Z",
        "BLUE",
        [
            _stats_u3_participant(
                _U3_PA,
                "Игрок Альфа",
                "RED",
                4,
                1,
                3,
                [_stats_u3_class("assault", "0", 30, 1, 3, 5)],
            ),
            _stats_u3_participant(
                _U3_PB,
                "Player Beta",
                "BLUE",
                9,
                6,
                1,
                [_stats_u3_class("recon", "2", 120, 6, 1, 30)],
            ),
        ],
    )
    started = time.monotonic()
    void_response, ingest_response = await asyncio.gather(
        request(
            store,
            "POST",
            "/v2/stats/results/void",
            {"serverId": _U3_SERVER, "eventId": extras[0], "voided": True},
            "admin",
        ),
        request(store, "POST", "/v2/stats/results", fresh, "stats-u3-producer"),
    )
    elapsed = time.monotonic() - started
    assert void_response.status_code == 200, void_response.text
    assert ingest_response.status_code == 201, ingest_response.text
    # The replay needs ~2 s (4 campaigns x 0.5 s); neither request waited it out.
    assert elapsed < 1.5, elapsed
    assert not replay.done()
    await replay
    monkeypatch.undo()
    await _stats_wait_idle(store)
    assert await sql(store, "SELECT count(*) AS n FROM stat_rating_rebuilds") == [
        {"n": 0}
    ]
    snap = await sql(
        store,
        "SELECT season_id,uuid,rating,rd,volatility,rated_campaigns FROM stat_ratings ORDER BY uuid",
    )
    season = next(s for s in core.stat_seasons() if s["id"] == "s2")
    async with await psycopg.AsyncConnection.connect(
        store["admin"],
        options="-c search_path=control,pg_catalog",
        row_factory=psycopg.rows.dict_row,
    ) as conn:
        async with conn.transaction():
            await core._stat_rebuild_ratings(conn, season)
    assert (
        await sql(
            store,
            "SELECT season_id,uuid,rating,rd,volatility,rated_campaigns FROM stat_ratings ORDER BY uuid",
        )
        == snap
    )


async def test_stats_c3_rebuilding_covers_earlier_seasons(store, monkeypatch):
    # Round 3B: voiding an s1 campaign rebuilds every later season, so s1 AND
    # s2 reads report ratingsRebuilding until the worker lands. The worker is
    # frozen so the pending row cannot vanish mid-assertion.
    await _stats_u3_seed(store)
    s1_event = "99999995-9999-4999-8999-999999999999"
    campaign = _stats_u3_campaign_body(
        s1_event,
        _U3_SERVER,
        "2026-09-20T12:00:00Z",
        "RED",
        [
            _stats_u3_participant(
                _U3_PA,
                "Игрок Альфа",
                "RED",
                12,
                4,
                1,
                [_stats_u3_class("assault", "0", 500, 4, 1, 100)],
            ),
            _stats_u3_participant(
                _U3_PB,
                "Player Beta",
                "BLUE",
                8,
                2,
                4,
                [_stats_u3_class("recon", "2", 500, 2, 4, 50)],
            ),
        ],
    )
    campaign["startedAt"] = "2026-09-20T11:00:00Z"
    created = await request(
        store, "POST", "/v2/stats/results", campaign, "stats-u3-producer"
    )
    assert created.status_code == 201, created.text

    async def frozen(conn):
        return None

    monkeypatch.setattr(core, "stat_rebuild_drain", frozen)
    voided = await request(
        store,
        "POST",
        "/v2/stats/results/void",
        {"serverId": _U3_SERVER, "eventId": s1_event, "voided": True},
        "admin",
    )
    assert voided.status_code == 200, voided.text
    assert voided.json()["rebuilt"] == "s1"
    for path in (
        "/v2/stats/leaderboard?season=s1",
        "/v2/stats/leaderboard?season=s2",
        f"/v2/stats/players/{_U3_PA}?season=s2",
    ):
        body = (await request(store, "GET", path, None, "stats-reader")).json()
        assert body["ratingsRebuilding"] is True, path
    monkeypatch.undo()
    await _stats_wait_idle(store)
    board = (
        await request(
            store, "GET", "/v2/stats/leaderboard?season=s2", None, "stats-reader"
        )
    ).json()
    assert board["ratingsRebuilding"] is False
    player = (
        await request(
            store, "GET", f"/v2/stats/players/{_U3_PA}?season=s2", None, "stats-reader"
        )
    ).json()
    assert player["ratingsRebuilding"] is False
    assert player["mmr"] == {
        "rating": 1662,
        "rd": 290,
        "ratedCampaigns": 1,
        "provisional": True,
    }


async def test_stats_c3_gap_scan_heals_old_path_campaign(store):
    # Round 3C: a campaign committed by the old (no-rating) path after the
    # migration has no stat_rating_changes row; the gap scan enqueues a
    # rebuild for it (idempotent) and the worker fills the ratings in.
    from cpv2.core import stat_gap_scan

    await _stats_u3_seed(store)
    gap_event = "99999996-9999-4999-8999-999999999999"
    body = _stats_u3_campaign_body(
        gap_event,
        _U3_SERVER,
        "2026-11-11T14:00:00Z",
        "BLUE",
        [
            _stats_u3_participant(
                _U3_PA,
                "Игрок Альфа",
                "RED",
                4,
                1,
                3,
                [_stats_u3_class("assault", "0", 30, 1, 3, 5)],
            ),
            _stats_u3_participant(
                _U3_PB,
                "Player Beta",
                "BLUE",
                9,
                6,
                1,
                [_stats_u3_class("recon", "2", 120, 6, 1, 30)],
            ),
        ],
    )
    async with await psycopg.AsyncConnection.connect(
        store["admin"], autocommit=True
    ) as conn:
        await conn.execute(
            "INSERT INTO control.stat_results(server_id,event_id,kind,mode,campaign_id,ended_at,reason,winner,digest,payload)"
            " VALUES(%s,%s,'campaign','campaign',%s,%s,'completed','BLUE',%s,%s)",
            (
                _U3_SERVER,
                gap_event,
                gap_event,
                "2026-11-11T14:00:00+00:00",
                "gapdigest",
                Jsonb(body),
            ),
        )
        for participant in (
            (_U3_PA, "RED", 4, 1, 3),
            (_U3_PB, "BLUE", 9, 6, 1),
        ):
            await conn.execute(
                "INSERT INTO control.stat_participants(server_id,event_id,uuid,team,score,kills,deaths,captures,neutralizations,"
                "point_seconds,play_seconds,suicides,team_kills,max_streak)"
                " VALUES(%s,%s,%s,%s,%s,%s,%s,0,0,0,0,0,0,0)",
                (_U3_SERVER, gap_event, *participant),
            )
    assert await sql(
        store,
        "SELECT count(*) AS n FROM stat_rating_changes WHERE event_id=%s",
        (gap_event,),
    ) == [{"n": 0}]
    async with await psycopg.AsyncConnection.connect(
        store["admin"],
        autocommit=True,
        options="-c search_path=control,pg_catalog",
        row_factory=psycopg.rows.dict_row,
    ) as conn:
        assert await stat_gap_scan(conn) == "s2"
        assert await stat_gap_scan(conn) == "s2"
        queue = await (
            await conn.execute("SELECT * FROM stat_rating_rebuilds")
        ).fetchall()
        assert [row["season_id"] for row in queue] == ["s2"]
    await _stats_wait_idle(store)
    assert await sql(
        store,
        "SELECT count(*) AS n FROM stat_rating_changes WHERE event_id=%s",
        (gap_event,),
    ) == [{"n": 2}]
    player = (
        await request(
            store, "GET", f"/v2/stats/players/{_U3_PA}?season=s2", None, "stats-reader"
        )
    ).json()
    assert player["mmr"]["ratedCampaigns"] == 2
    assert player["ratingsRebuilding"] is False


async def test_stats_c4_reenqueue_restarts_for_late_campaign(store, monkeypatch):
    # Round 4A: a re-enqueue carries its from-point. A late campaign ingested
    # behind the replay cursor restarts the replay (NULL cursor) so the worker
    # replays it; a later campaign keeps the cursor. Fail-before: the old bump
    # kept the cursor and the queue cleared with the late rating missing.
    from datetime import datetime, timezone

    from cpv2.core import stat_gap_scan

    real_drain = core.stat_rebuild_drain

    async def frozen(conn):
        return None

    monkeypatch.setattr(core, "stat_rebuild_drain", frozen)

    async def drain_once():
        async with await psycopg.AsyncConnection.connect(
            store["admin"],
            options="-c search_path=control,pg_catalog",
            row_factory=psycopg.rows.dict_row,
        ) as conn:
            async with conn.transaction():
                await real_drain(conn)

    await _stats_u3_seed(store)
    extra = await request(
        store,
        "POST",
        "/v2/stats/results",
        _stats_c4_campaign_body(
            "99999981-9999-4999-8999-999999999999", "2026-11-11T13:00:00Z", "BLUE"
        ),
        "stats-u3-producer",
    )
    assert extra.status_code == 201, extra.text
    voided = await request(
        store,
        "POST",
        "/v2/stats/results/void",
        {"serverId": _U3_SERVER, "eventId": _U3_C1, "voided": True},
        "admin",
    )
    assert voided.status_code == 200, voided.text
    await drain_once()
    assert await sql(
        store,
        "SELECT last_ended_at IS NOT NULL AS progressed FROM stat_rating_rebuilds",
    ) == [{"progressed": True}]
    # A later campaign keeps the cursor: the replay reaches it on its own.
    later = await request(
        store,
        "POST",
        "/v2/stats/results",
        _stats_c4_campaign_body(
            "99999982-9999-4999-8999-999999999999", "2026-11-11T14:00:00Z", "RED"
        ),
        "stats-u3-producer",
    )
    assert later.status_code == 201, later.text
    assert await sql(
        store,
        "SELECT last_ended_at AT TIME ZONE 'UTC' AS cursor FROM stat_rating_rebuilds",
    ) == [{"cursor": datetime(2026, 11, 11, 13, 0)}]
    # The gap scan defers to the progressing replay instead of restarting it.
    async with await psycopg.AsyncConnection.connect(
        store["admin"],
        autocommit=True,
        options="-c search_path=control,pg_catalog",
        row_factory=psycopg.rows.dict_row,
    ) as conn:
        assert await stat_gap_scan(conn) is None
    # A late campaign behind the cursor restarts the replay from the start.
    late = await request(
        store,
        "POST",
        "/v2/stats/results",
        _stats_c4_campaign_body(
            "99999983-9999-4999-8999-999999999999", "2026-11-11T11:30:00Z", "RED"
        ),
        "stats-u3-producer",
    )
    assert late.status_code == 201, late.text
    assert await sql(
        store,
        "SELECT last_ended_at,last_server_id,last_event_id FROM stat_rating_rebuilds",
    ) == [{"last_ended_at": None, "last_server_id": None, "last_event_id": None}]
    monkeypatch.undo()
    await _stats_wait_idle(store)
    for event in (
        "99999981-9999-4999-8999-999999999999",
        "99999982-9999-4999-8999-999999999999",
        "99999983-9999-4999-8999-999999999999",
    ):
        assert await sql(
            store,
            "SELECT count(*) AS n FROM stat_rating_changes WHERE event_id=%s",
            (event,),
        ) == [{"n": 2}], event
    assert await sql(store, "SELECT count(*) AS n FROM stat_rating_rebuilds") == [
        {"n": 0}
    ]
    # Upsert matrix: new rows start over; a later from-point keeps the cursor;
    # an earlier one and season start (NULL) restart it.
    from cpv2.core import _stat_enqueue_rebuild

    utc = timezone.utc
    async with await psycopg.AsyncConnection.connect(
        store["admin"],
        options="-c search_path=control,pg_catalog",
        row_factory=psycopg.rows.dict_row,
    ) as conn:
        async with conn.transaction():

            async def cursor():
                row = await (
                    await conn.execute(
                        "SELECT last_ended_at,last_server_id,last_event_id"
                        " FROM stat_rating_rebuilds WHERE season_id='s2'"
                    )
                ).fetchone()
                return (
                    row["last_ended_at"],
                    row["last_server_id"],
                    row["last_event_id"],
                )

            await _stat_enqueue_rebuild(
                conn,
                "s2",
                _U3_SERVER,
                "99999981-9999-4999-8999-999999999999",
                datetime(2026, 11, 11, 13, 0, tzinfo=utc),
            )
            assert await cursor() == (None, None, None)
            await conn.execute(
                "UPDATE stat_rating_rebuilds SET last_ended_at=%s,last_server_id=%s,last_event_id=%s"
                " WHERE season_id='s2'",
                (
                    datetime(2026, 11, 11, 13, 0, tzinfo=utc),
                    _U3_SERVER,
                    "99999981-9999-4999-8999-999999999999",
                ),
            )
            await _stat_enqueue_rebuild(
                conn,
                "s2",
                _U3_SERVER,
                "99999982-9999-4999-8999-999999999999",
                datetime(2026, 11, 11, 14, 0, tzinfo=utc),
            )
            assert await cursor() == (
                datetime(2026, 11, 11, 13, 0, tzinfo=utc),
                _U3_SERVER,
                "99999981-9999-4999-8999-999999999999",
            )
            await _stat_enqueue_rebuild(
                conn,
                "s2",
                _U3_SERVER,
                "99999983-9999-4999-8999-999999999999",
                datetime(2026, 11, 11, 11, 30, tzinfo=utc),
            )
            assert await cursor() == (None, None, None)
            await conn.execute(
                "UPDATE stat_rating_rebuilds SET last_ended_at=%s,last_server_id=%s,last_event_id=%s"
                " WHERE season_id='s2'",
                (
                    datetime(2026, 11, 11, 13, 0, tzinfo=utc),
                    _U3_SERVER,
                    "99999981-9999-4999-8999-999999999999",
                ),
            )
            await _stat_enqueue_rebuild(
                conn, "s2", _U3_SERVER, "99999981-9999-4999-8999-999999999999", None
            )
            assert await cursor() == (None, None, None)


async def test_stats_c4_earliest_season_first_and_matches_full_replay(
    store, monkeypatch
):
    # Round 4B: the worker serves the earliest queued season first, so an s1
    # rebuild runs while a mid-replay s2 row waits (its stale cursor resets
    # when s1 restarts from scratch), and the final ratings equal a full
    # replay. Fail-before: the old requested_at order served s2 first.
    monkeypatch.setattr(core, "STAT_REBUILD_BATCH", 1)
    real_drain = core.stat_rebuild_drain

    async def frozen(conn):
        return None

    monkeypatch.setattr(core, "stat_rebuild_drain", frozen)

    async def drain_once():
        async with await psycopg.AsyncConnection.connect(
            store["admin"],
            options="-c search_path=control,pg_catalog",
            row_factory=psycopg.rows.dict_row,
        ) as conn:
            async with conn.transaction():
                await real_drain(conn)

    await _stats_u3_seed(store)
    first = await request(
        store,
        "POST",
        "/v2/stats/results",
        _stats_c4_campaign_body(
            "99999985-9999-4999-8999-999999999999",
            "2026-09-20T12:00:00Z",
            "RED",
            started="2026-09-20T11:00:00Z",
        ),
        "stats-u3-producer",
    )
    assert first.status_code == 201, first.text
    for event, hour in (
        ("99999986-9999-4999-8999-999999999999", "13"),
        ("99999987-9999-4999-8999-999999999999", "14"),
    ):
        created = await request(
            store,
            "POST",
            "/v2/stats/results",
            _stats_c4_campaign_body(event, f"2026-11-11T{hour}:00:00Z", "BLUE"),
            "stats-u3-producer",
        )
        assert created.status_code == 201, created.text
    assert (
        await request(
            store,
            "POST",
            "/v2/stats/results/void",
            {"serverId": _U3_SERVER, "eventId": _U3_C1, "voided": True},
            "admin",
        )
    ).status_code == 200
    await drain_once()
    assert (
        await request(
            store,
            "POST",
            "/v2/stats/results/void",
            {
                "serverId": _U3_SERVER,
                "eventId": "99999985-9999-4999-8999-999999999999",
                "voided": True,
            },
            "admin",
        )
    ).status_code == 200
    before = await sql(
        store,
        "SELECT season_id,requested_at,last_ended_at IS NOT NULL AS progressed"
        " FROM stat_rating_rebuilds ORDER BY season_id",
    )
    assert [(row["season_id"], row["progressed"]) for row in before] == [
        ("s1", False),
        ("s2", True),
    ]
    s2_requested = next(
        row["requested_at"] for row in before if row["season_id"] == "s2"
    )
    await drain_once()
    after = await sql(
        store,
        "SELECT season_id,requested_at,last_ended_at IS NOT NULL AS progressed"
        " FROM stat_rating_rebuilds ORDER BY season_id",
    )
    assert [(row["season_id"], row["progressed"]) for row in after] == [
        ("s1", True),
        ("s2", False),
    ]
    assert (
        next(row["requested_at"] for row in after if row["season_id"] == "s2")
        == s2_requested
    )
    monkeypatch.undo()
    monkeypatch.setattr(core, "STAT_REBUILD_BATCH", 1)
    deadline = time.monotonic() + 30
    while True:
        if await sql(store, "SELECT count(*) AS n FROM stat_rating_rebuilds") == [
            {"n": 0}
        ]:
            break
        assert time.monotonic() < deadline, "rating rebuild did not finish"
        await asyncio.sleep(0.2)
    snap = await sql(
        store,
        "SELECT season_id,uuid,rating,rd,volatility,rated_campaigns FROM stat_ratings ORDER BY uuid",
    )
    season = next(s for s in core.stat_seasons() if s["id"] == "s1")
    async with await psycopg.AsyncConnection.connect(
        store["admin"],
        options="-c search_path=control,pg_catalog",
        row_factory=psycopg.rows.dict_row,
    ) as conn:
        async with conn.transaction():
            await core._stat_rebuild_ratings(conn, season)
    assert (
        await sql(
            store,
            "SELECT season_id,uuid,rating,rd,volatility,rated_campaigns FROM stat_ratings ORDER BY uuid",
        )
        == snap
    )


async def test_stats_c4_resume_race_aborts_pass(store, monkeypatch):
    # Round 4 scenario, round-5 mechanism: a reset landing between a batch's
    # read and its commit bumps generation, so the guarded write misses and
    # the batch rolls back to its savepoint (no raise): the pass drops its
    # work instead of committing ratings the next pass would rate twice
    # (stat_rating_changes PK collision). Fail-before: the old
    # requested_at guard raised _StatRebuildRace here.
    monkeypatch.setattr(core, "STAT_REBUILD_BATCH", 1)
    real_drain = core.stat_rebuild_drain

    async def frozen(conn):
        return None

    monkeypatch.setattr(core, "stat_rebuild_drain", frozen)

    async def drain_once():
        async with await psycopg.AsyncConnection.connect(
            store["admin"],
            options="-c search_path=control,pg_catalog",
            row_factory=psycopg.rows.dict_row,
        ) as conn:
            async with conn.transaction():
                await real_drain(conn)

    await _stats_u3_seed(store)
    for event, hour in (
        ("99999991-9999-4999-8999-999999999999", "13"),
        ("99999992-9999-4999-8999-999999999999", "14"),
        ("99999993-9999-4999-8999-999999999999", "15"),
    ):
        created = await request(
            store,
            "POST",
            "/v2/stats/results",
            _stats_c4_campaign_body(event, f"2026-11-11T{hour}:00:00Z", "BLUE"),
            "stats-u3-producer",
        )
        assert created.status_code == 201, created.text
    assert (
        await request(
            store,
            "POST",
            "/v2/stats/results/void",
            {"serverId": _U3_SERVER, "eventId": _U3_C1, "voided": True},
            "admin",
        )
    ).status_code == 200
    await drain_once()
    real_rate = core._stat_rate
    reset_done = False

    async def resetting_rate(conn, clean, ended_ms):
        nonlocal reset_done
        if not reset_done:
            reset_done = True
            async with await psycopg.AsyncConnection.connect(
                store["admin"],
                options="-c search_path=control,pg_catalog",
                row_factory=psycopg.rows.dict_row,
            ) as reset_conn:
                async with reset_conn.transaction():
                    # A reset behind the cursor lands mid-batch: it restarts
                    # the replay and bumps generation via the real path.
                    from datetime import datetime, timezone

                    await core._stat_enqueue_rebuild(
                        reset_conn,
                        "s2",
                        _U3_SERVER,
                        _U3_C1,
                        datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc),
                    )
        return await real_rate(conn, clean, ended_ms)

    monkeypatch.setattr(core, "_stat_rate", resetting_rate)
    before = await sql(
        store, "SELECT generation FROM stat_rating_rebuilds WHERE season_id='s2'"
    )
    await drain_once()
    assert reset_done
    # No raise: the batch rolled back, so its campaign has no ratings, and
    # the queue row kept the reset (NULL cursor, bumped generation).
    assert await sql(
        store,
        "SELECT count(*) AS n FROM stat_rating_changes WHERE event_id=%s",
        ("99999992-9999-4999-8999-999999999999",),
    ) == [{"n": 0}]
    after = await sql(
        store,
        "SELECT generation,last_ended_at FROM stat_rating_rebuilds WHERE season_id='s2'",
    )
    assert after == [{"generation": before[0]["generation"] + 1, "last_ended_at": None}]
    monkeypatch.undo()
    monkeypatch.setattr(core, "STAT_REBUILD_BATCH", 1)
    monkeypatch.setattr(core, "stat_rebuild_drain", frozen)
    for _ in range(4):
        await drain_once()
    assert await sql(store, "SELECT count(*) AS n FROM stat_rating_rebuilds") == [
        {"n": 0}
    ]
    for event in (
        "99999991-9999-4999-8999-999999999999",
        "99999992-9999-4999-8999-999999999999",
        "99999993-9999-4999-8999-999999999999",
    ):
        assert await sql(
            store,
            "SELECT count(*) AS n FROM stat_rating_changes WHERE event_id=%s",
            (event,),
        ) == [{"n": 2}], event
    snap = await sql(
        store,
        "SELECT season_id,uuid,rating,rd,volatility,rated_campaigns FROM stat_ratings ORDER BY uuid",
    )
    season = next(s for s in core.stat_seasons() if s["id"] == "s2")
    async with await psycopg.AsyncConnection.connect(
        store["admin"],
        options="-c search_path=control,pg_catalog",
        row_factory=psycopg.rows.dict_row,
    ) as conn:
        async with conn.transaction():
            await core._stat_rebuild_ratings(conn, season)
    assert (
        await sql(
            store,
            "SELECT season_id,uuid,rating,rd,volatility,rated_campaigns FROM stat_ratings ORDER BY uuid",
        )
        == snap
    )


async def test_stats_c5_equal_cursor_void_restarts_replay(store, monkeypatch):
    # Round 5 / bot 4544506235: a re-enqueue whose from-point EQUALS the
    # cursor restarts the replay (<=), so voiding exactly the last replayed
    # campaign re-rates it away. Fail-before: strict < kept the cursor, the
    # next batch selected >(cursor) = nothing, and the voided campaign kept
    # its rating forever.
    from datetime import datetime

    real_drain = core.stat_rebuild_drain

    async def frozen(conn):
        return None

    monkeypatch.setattr(core, "stat_rebuild_drain", frozen)

    async def drain_once():
        async with await psycopg.AsyncConnection.connect(
            store["admin"],
            options="-c search_path=control,pg_catalog",
            row_factory=psycopg.rows.dict_row,
        ) as conn:
            async with conn.transaction():
                await real_drain(conn)

    await _stats_u3_seed(store)
    for event, hour in (
        ("99999961-9999-4999-8999-999999999999", "13"),
        ("99999962-9999-4999-8999-999999999999", "14"),
    ):
        created = await request(
            store,
            "POST",
            "/v2/stats/results",
            _stats_c4_campaign_body(event, f"2026-11-11T{hour}:00:00Z", "BLUE"),
            "stats-u3-producer",
        )
        assert created.status_code == 201, created.text
    assert (
        await request(
            store,
            "POST",
            "/v2/stats/results/void",
            {"serverId": _U3_SERVER, "eventId": _U3_C1, "voided": True},
            "admin",
        )
    ).status_code == 200
    await drain_once()
    assert await sql(
        store,
        "SELECT last_ended_at AT TIME ZONE 'UTC' AS cursor,last_server_id,last_event_id"
        " FROM stat_rating_rebuilds WHERE season_id='s2'",
    ) == [
        {
            "cursor": datetime(2026, 11, 11, 14, 0),
            "last_server_id": _U3_SERVER,
            "last_event_id": "99999962-9999-4999-8999-999999999999",
        }
    ]
    # Void exactly the cursor campaign: the cursor must restart, not stick.
    assert (
        await request(
            store,
            "POST",
            "/v2/stats/results/void",
            {
                "serverId": _U3_SERVER,
                "eventId": "99999962-9999-4999-8999-999999999999",
                "voided": True,
            },
            "admin",
        )
    ).status_code == 200
    assert await sql(
        store,
        "SELECT last_ended_at,last_server_id,last_event_id FROM stat_rating_rebuilds WHERE season_id='s2'",
    ) == [{"last_ended_at": None, "last_server_id": None, "last_event_id": None}]
    monkeypatch.undo()
    await _stats_wait_idle(store)
    assert await sql(
        store,
        "SELECT count(*) AS n FROM stat_rating_changes WHERE event_id=%s",
        ("99999962-9999-4999-8999-999999999999",),
    ) == [{"n": 0}]
    assert await sql(
        store,
        "SELECT count(*) AS n FROM stat_rating_changes WHERE event_id=%s",
        ("99999961-9999-4999-8999-999999999999",),
    ) == [{"n": 2}]
    assert await sql(store, "SELECT count(*) AS n FROM stat_rating_rebuilds") == [
        {"n": 0}
    ]
    snap = await sql(
        store,
        "SELECT season_id,uuid,rating,rd,volatility,rated_campaigns FROM stat_ratings ORDER BY uuid",
    )
    season = next(s for s in core.stat_seasons() if s["id"] == "s2")
    async with await psycopg.AsyncConnection.connect(
        store["admin"],
        options="-c search_path=control,pg_catalog",
        row_factory=psycopg.rows.dict_row,
    ) as conn:
        async with conn.transaction():
            await core._stat_rebuild_ratings(conn, season)
    assert (
        await sql(
            store,
            "SELECT season_id,uuid,rating,rd,volatility,rated_campaigns FROM stat_ratings ORDER BY uuid",
        )
        == snap
    )


async def test_stats_c5_single_worker_lock_excludes_second_replica(store):
    # Round 5 / bot 4544506243: exactly one rebuild worker runs across CP
    # replicas. The loop holds _stat_try_worker_lock for its whole life, so
    # while it runs a second replica's try-lock fails instead of replaying
    # concurrently from a stale cursor.
    from cpv2.core import _stat_try_worker_lock

    async def open_conn():
        return await psycopg.AsyncConnection.connect(
            store["admin"],
            options="-c search_path=control,pg_catalog",
            row_factory=psycopg.rows.dict_row,
        )

    probe = await open_conn()
    second = await open_conn()
    try:
        deadline = time.monotonic() + 15
        while await _stat_try_worker_lock(probe):
            # We beat the app worker to the lock: hand it back and wait
            # until it holds the lock for its whole life.
            await probe.execute(
                "SELECT pg_advisory_unlock(hashtext('stats-rebuild-worker'),1)"
            )
            assert time.monotonic() < deadline, "app worker never took the lock"
            await asyncio.sleep(0.05)
        assert await _stat_try_worker_lock(second) is False
    finally:
        await probe.close()
        await second.close()


async def test_stats_read_provision_scopes(store):
    from cpv2.auth import STATS_READ_SCOPES

    assert STATS_READ_SCOPES == {"stats.read"}
    with pytest.raises(ValueError, match="unbound site credential"):
        await provision(
            store["admin"],
            {
                "client": {
                    "id": "stats-bound",
                    "via": "game",
                    "ceiling": ["stats.read"],
                },
                "ceiling": ["stats.read"],
                "environment": "prod",
                "backend": "game",
                "resource": _U3_SERVER,
            },
        )
    with pytest.raises(ValueError, match="service credential ceiling"):
        await provision(
            store["admin"],
            {
                "client": {
                    "id": "stats-void-svc",
                    "via": "game",
                    "ceiling": ["stats.void"],
                },
                "ceiling": ["stats.void"],
                "environment": "prod",
                "backend": "game",
                "resource": "*",
            },
        )


_DIAG_SERVER = "22222222-2222-2222-2222-222222222222"
_DIAG_EVENT = "11111111-1111-1111-1111-111111111111"


def _diag_body(now_ms=None, **over):
    now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
    body = {
        "schemaVersion": 1,
        "serverId": _DIAG_SERVER,
        "startedAt": now_ms - 3600000,
        "samples": [
            {
                "at": now_ms - 60000,
                "tps": 19.5,
                "msptAvg": 21.0,
                "msptP95": 30.0,
                "msptMax": 340.0,
                "players": 12,
                "heapUsedMb": 1800,
                "heapMaxMb": 3072,
                "gcPauseMs": 5,
            }
        ],
        "events": [
            {
                "id": _DIAG_EVENT,
                "at": now_ms - 30000,
                "kind": "freeze",
                "durationMs": 3400,
                "source": "Server thread",
                "message": "tick stuck, see http://10.0.0.5:8080/logs",
                "repeats": 2,
            }
        ],
    }
    body.update(over)
    return body


async def test_stats_diag_ingest_roundtrip_idempotent_and_redacted(store):
    # Producer diagnostics (coordination#29 U4): same bytes as the site
    # POST /api/stats/diagnostics, same idempotency, secrets redacted.
    await _stats_token(store, _DIAG_SERVER, "stats-diag")
    body = _diag_body()
    created = await request(store, "POST", "/v2/stats/diagnostics", body, "stats-diag")
    assert created.status_code == 200, created.text
    assert created.json() == {"samples": 1, "events": 1}
    samples = await sql(
        store, "SELECT tps,mspt_p95,players,started_at FROM stat_samples"
    )
    assert len(samples) == 1
    assert samples[0]["tps"] == 19.5
    stored = await sql(
        store, "SELECT kind,duration_ms,source,message,repeats FROM stat_events"
    )
    assert len(stored) == 1
    assert stored[0]["message"] == "tick stuck, see [url]", stored
    assert (stored[0]["kind"], stored[0]["duration_ms"], stored[0]["repeats"]) == (
        "freeze",
        3400,
        2,
    )
    replayed = await request(store, "POST", "/v2/stats/diagnostics", body, "stats-diag")
    assert replayed.status_code == 200, replayed.text
    assert replayed.json() == {"samples": 1, "events": 1}
    assert await sql(store, "SELECT count(*) AS n FROM stat_samples") == [{"n": 1}]
    assert await sql(store, "SELECT count(*) AS n FROM stat_events") == [{"n": 1}]


async def test_stats_diag_ingest_validation(store):
    await _stats_token(store, _DIAG_SERVER, "stats-diag-valid")
    now_ms = int(time.time() * 1000)
    old = now_ms - 8 * 86400000
    cases = [
        {"schemaVersion": 2},
        {"serverId": "not-a-uuid"},
        {"samples": "nope"},
        {"samples": [{"at": now_ms}] * 121},
        {"samples": [{"at": now_ms, "tps": -1, "msptAvg": 1, "msptMax": 1}]},
        {
            "samples": [
                {"at": now_ms, "tps": 20, "msptAvg": 1, "msptMax": 1, "players": 1.5}
            ]
        },
        {"events": [{"id": _DIAG_EVENT, "at": now_ms, "kind": "oops", "message": "x"}]},
        {
            "events": [
                {"id": _DIAG_EVENT, "at": now_ms, "kind": "error", "message": "   "}
            ]
        },
        {
            "events": [
                {"id": _DIAG_EVENT, "at": now_ms, "kind": "freeze", "message": "x"}
            ]
        },
        {"events": [{"id": "nope", "at": now_ms, "kind": "error", "message": "x"}]},
        {
            "samples": [
                {"at": now_ms + 10 * 60000, "tps": 20, "msptAvg": 1, "msptMax": 1}
            ]
        },
    ]
    for patch in cases:
        body = _diag_body(now_ms, **patch)
        response = await request(
            store, "POST", "/v2/stats/diagnostics", body, "stats-diag-valid"
        )
        assert response.status_code == 400, (patch, response.text)
        assert response.json() == {"error": "invalid_diagnostics"}, response.text
    # Out-of-retention items are dropped, not refused (like the site).
    dropped = await request(
        store,
        "POST",
        "/v2/stats/diagnostics",
        _diag_body(
            now_ms, samples=[{"at": old, "tps": 20, "msptAvg": 1, "msptMax": 1}]
        ),
        "stats-diag-valid",
    )
    assert dropped.status_code == 200, dropped.text
    assert dropped.json() == {"samples": 0, "events": 1}
    assert await sql(store, "SELECT count(*) AS n FROM stat_samples") == [{"n": 0}]


async def test_stats_diag_ingest_rbac(store):
    await _stats_token(store, _DIAG_SERVER, "stats-diag-rbac")
    body = _diag_body()
    for role in ("ordinary", "builder", "moderator", "admin", "game-agent"):
        response = await request(store, "POST", "/v2/stats/diagnostics", body, role)
        assert response.status_code == 403, (role, response.text)
    assert (
        await request(store, "POST", "/v2/stats/diagnostics", body, "owner")
    ).status_code == 403
    assert (
        await store["client"].post("/v2/stats/diagnostics", json=body)
    ).status_code == 401
    other = "33333333-3333-3333-3333-333333333333"
    await _stats_token(store, other, "stats-diag-other")
    forged = await request(
        store, "POST", "/v2/stats/diagnostics", body, "stats-diag-other"
    )
    assert forged.status_code == 403, forged.text


async def test_stats_diag_retention_prunes_by_age_and_severity(store, monkeypatch):
    # Age prune mirrors the site saveReport windows (7d samples, 14d events).
    await _stats_token(store, _DIAG_SERVER, "stats-diag-retain")
    now_ms = int(time.time() * 1000)
    old_sample = now_ms - 8 * 86400000
    old_event = now_ms - 15 * 86400000
    async with await psycopg.AsyncConnection.connect(store["admin"]) as conn:
        await conn.execute(
            "INSERT INTO control.stat_samples(server_id,at,tps,mspt_avg,mspt_max) VALUES(%s,%s,20,1,1)",
            (_DIAG_SERVER, datetime.fromtimestamp(old_sample / 1000, tz=timezone.utc)),
        )
        await conn.execute(
            "INSERT INTO control.stat_events(server_id,event_id,at,kind,message,repeats) VALUES(%s,%s,%s,'error','old',1)",
            (
                _DIAG_SERVER,
                "00000000-0000-0000-0000-000000000000",
                datetime.fromtimestamp(old_event / 1000, tz=timezone.utc),
            ),
        )
        await conn.commit()
    response = await request(
        store, "POST", "/v2/stats/diagnostics", _diag_body(now_ms), "stats-diag-retain"
    )
    assert response.status_code == 200, response.text
    assert await sql(store, "SELECT count(*) AS n FROM stat_samples") == [{"n": 1}]
    events = await sql(store, "SELECT message FROM stat_events")
    assert [row["message"] for row in events] == ["tick stuck, see [url]"]
    # Row-count prune keeps the severity-ordered newest window, like the site
    # (crash/error before freeze before warning): with a cap of 2 the freeze
    # and warning rows go even though they are newer than nothing here.
    monkeypatch.setattr(core, "DIAG_MAX_EVENTS", 2)
    kinds = ["warning", "freeze", "error", "crash"]
    async with await psycopg.AsyncConnection.connect(store["admin"]) as conn:
        for index, kind in enumerate(kinds):
            await conn.execute(
                "INSERT INTO control.stat_events(server_id,event_id,at,kind,message,repeats) VALUES(%s,%s,%s,%s,'k',1)",
                (
                    _DIAG_SERVER,
                    f"22222222-2222-2222-2222-22222222222{index}",
                    datetime.fromtimestamp(
                        (now_ms - (index + 1) * 1000) / 1000, tz=timezone.utc
                    ),
                    kind,
                ),
            )
        await conn.commit()
    pruned = await request(
        store,
        "POST",
        "/v2/stats/diagnostics",
        _diag_body(now_ms, events=[]),
        "stats-diag-retain",
    )
    assert pruned.status_code == 200, pruned.text
    kept = await sql(store, "SELECT kind FROM control.stat_events ORDER BY kind")
    assert sorted(row["kind"] for row in kept) == ["crash", "error"]


async def test_stats_diag_read_matches_site_contract(store):
    await _stats_token(store, _DIAG_SERVER, "stats-diag-read")
    await _stats_reader_token(store)
    now_ms = int(time.time() * 1000)
    posted = await request(
        store,
        "POST",
        "/v2/stats/diagnostics",
        _diag_body(
            now_ms,
            samples=[
                {"at": now_ms - 2 * 3600000, "tps": 20, "msptAvg": 10, "msptMax": 100}
            ],
            events=[],
        ),
        "stats-diag-read",
    )
    assert posted.status_code == 200, posted.text
    posted = await request(
        store, "POST", "/v2/stats/diagnostics", _diag_body(now_ms), "stats-diag-read"
    )
    assert posted.status_code == 200, posted.text
    view = await request(store, "GET", "/v2/stats/diagnostics", None, "stats-reader")
    assert view.status_code == 200, view.text
    data = view.json()
    assert data["schemaVersion"] == 1 and data["hours"] == 24
    assert data["lastSampleAt"] == now_ms - 60000
    assert len(data["samples"]) == 2 and len(data["events"]) == 1
    sample = data["samples"][1]
    assert sample["serverId"] == _DIAG_SERVER
    assert (sample["at"], sample["tps"], sample["msptAvg"], sample["msptP95"]) == (
        now_ms - 60000,
        19.5,
        21.0,
        30.0,
    )
    assert (
        sample["players"],
        sample["heapUsedMb"],
        sample["heapMaxMb"],
        sample["gcPauseMs"],
    ) == (12, 1800, 3072, 5)
    assert sample["startedAt"] == now_ms - 3600000
    event = data["events"][0]
    assert (event["id"], event["kind"], event["durationMs"]) == (
        _DIAG_EVENT,
        "freeze",
        3400,
    )
    assert event["message"] == "tick stuck, see [url]"
    assert (event["source"], event["repeats"]) == ("Server thread", 2)
    # The hours window filters samples only; the journal and the last-sample
    # marker still cover everything, like the site view.
    narrow = await request(
        store, "GET", "/v2/stats/diagnostics?hours=1", None, "stats-reader"
    )
    assert narrow.status_code == 200, narrow.text
    assert [row["at"] for row in narrow.json()["samples"]] == [now_ms - 60000]
    assert len(narrow.json()["events"]) == 1
    assert narrow.json()["lastSampleAt"] == now_ms - 60000
    wide = await request(
        store, "GET", "/v2/stats/diagnostics?hours=168", None, "stats-reader"
    )
    assert wide.status_code == 200, wide.text
    for bad in ("abc", "0", "169"):
        rejected = await request(
            store, "GET", f"/v2/stats/diagnostics?hours={bad}", None, "stats-reader"
        )
        assert rejected.status_code == 400, (bad, rejected.text)
    # Reads ride the unbound stats.read credential or a staff role; the
    # per-server producer credential and unrelated roles stay rejected.
    assert (
        await request(store, "GET", "/v2/stats/diagnostics", None, "stats-diag-read")
    ).status_code == 403
    assert (
        await request(store, "GET", "/v2/stats/diagnostics", None, "admin")
    ).status_code == 200
    assert (
        await request(store, "GET", "/v2/stats/diagnostics", None, "ordinary")
    ).status_code == 403


async def test_stats_diag_ingest_accepts_full_size_report(store):
    # A max-size producer report (120 samples + 200 full events) fits the
    # 1 MiB route allowance, like the site 1 MiB ingest limit.
    await _stats_token(store, _DIAG_SERVER, "stats-diag-full")
    now_ms = int(time.time() * 1000)
    body = _diag_body(
        now_ms,
        samples=[
            {"at": now_ms - (i + 1) * 1000, "tps": 20, "msptAvg": 10, "msptMax": 100}
            for i in range(120)
        ],
        events=[
            {
                "id": f"33333333-3333-3333-3333-{i:012d}",
                "at": now_ms - (i + 1) * 1000,
                "kind": "error",
                "message": "x" * 4000,
            }
            for i in range(200)
        ],
    )
    response = await request(
        store, "POST", "/v2/stats/diagnostics", body, "stats-diag-full"
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"samples": 120, "events": 200}


def suggest_body(store, key, text, **extra):
    return {
        "idempotencyKey": key,
        "environment": "prod",
        "backend": "game",
        "consumerId": "game",
        "generation": str(store["generation"]),
        "input": text,
        **extra,
    }


def log_batch(store, key, entries, **extra):
    return {
        "environment": "prod",
        "backend": "game",
        "consumerId": "game",
        "generation": str(store["generation"]),
        "entries": entries,
        **extra,
    }


def log_entry(now_ms, message, level="INFO", logger="Minecraft"):
    return {"at": now_ms, "level": level, "logger": logger, "message": message}


async def test_console_suggest_round_trip_and_validation(store):
    # Moderators hold no console scope; unknown consumers and control
    # characters are refused before any operation exists.
    assert (
        await request(
            store,
            "POST",
            "/v2/console/suggest",
            suggest_body(store, "s0", "ti"),
            "moderator",
        )
    ).status_code == 403
    bad_consumer = await request(
        store,
        "POST",
        "/v2/console/suggest",
        suggest_body(store, "s1", "time set", consumerId="nope"),
    )
    assert bad_consumer.status_code == 409, bad_consumer.text
    bad_input = await request(
        store, "POST", "/v2/console/suggest", suggest_body(store, "s2", "time\nstop")
    )
    assert bad_input.status_code == 422, bad_input.text
    assert not await sql(store, "SELECT * FROM operations WHERE kind='console.suggest'")
    # Slow game: the POST waits for the ack instead of returning a receipt.
    pending = asyncio.create_task(
        store["client"].post(
            "/v2/console/suggest",
            json=suggest_body(store, "s3", "time s"),
            headers=headers(store),
        )
    )
    await asyncio.sleep(0.2)
    frames = await envelopes(store)
    suggest = [f for f in frames if f["payload"].get("kind") == "console.suggest"]
    assert len(suggest) == 1, [f["payload"].get("kind") for f in frames]
    assert suggest[0]["payload"] == {
        "kind": "console.suggest",
        "target": "*",
        "input": "time s",
    }
    assert suggest[0]["executable"]
    answer = {"from": 5, "suggestions": [{"text": "set", "hint": "time set"}]}
    await ack_chain(store, suggest[0], output=json.dumps(answer))
    response = await asyncio.wait_for(pending, 10)
    assert response.status_code == 200, response.text
    assert response.json() == answer
    # A malformed game answer is a 502, never rendered raw.
    pending = asyncio.create_task(
        store["client"].post(
            "/v2/console/suggest",
            json=suggest_body(store, "s4", "wea"),
            headers=headers(store),
        )
    )
    await asyncio.sleep(0.2)
    frames = await envelopes(store)
    # Non-executable frames (the acked s3 one) carry no payload.
    broken = next(f for f in frames if (f["payload"] or {}).get("input") == "wea")
    await ack_chain(store, broken, output="not-json{{")
    response = await asyncio.wait_for(pending, 10)
    assert response.status_code == 502, response.text


async def test_console_suggest_timeout_without_game(store):
    response = await store["client"].post(
        "/v2/console/suggest",
        json=suggest_body(store, "s-timeout", "time s"),
        headers=headers(store),
        timeout=15,
    )
    assert response.status_code == 504, response.text


async def test_console_suggest_survives_full_agent_streams(store):
    # Both agent stream slots taken: the completion waits on its own waiter
    # namespace instead of 504ing for lack of a stream slot.
    wakeups = store["app"].state.wakeups
    first, second = wakeups.subscribe("game"), wakeups.subscribe("game")
    try:
        pending = asyncio.create_task(
            store["client"].post(
                "/v2/console/suggest",
                json=suggest_body(store, "s-streams-full", "time s"),
                headers=headers(store),
            )
        )
        await asyncio.sleep(0.2)
        frames = await envelopes(store)
        suggest = [f for f in frames if f["payload"].get("kind") == "console.suggest"]
        assert len(suggest) == 1, [f["payload"].get("kind") for f in frames]
        answer = {"from": 5, "suggestions": [{"text": "set", "hint": "time set"}]}
        await ack_chain(store, suggest[0], output=json.dumps(answer))
        response = await asyncio.wait_for(pending, 10)
        assert response.status_code == 200, response.text
        assert response.json() == answer
        assert not wakeups.suggest_waiters
    finally:
        wakeups.unsubscribe("game", first)
        wakeups.unsubscribe("game", second)


async def test_console_log_push_and_tail(store):
    now_ms = int(time.time() * 1000)
    batch = log_batch(
        store,
        "log",
        [log_entry(now_ms - 2000, "Starting server"), log_entry(now_ms, "Done")],
    )
    # The game loop sends no generation (only its credential proves it);
    # an explicit one must still match.
    del batch["generation"]
    pushed = await request(store, "POST", "/v2/console/logs", batch, "game-agent")
    assert pushed.status_code == 201, pushed.text
    assert pushed.json() == {"accepted": 2, "next": 2}
    tail = await request(store, "GET", "/v2/console/logs?consumerId=game&since=0")
    assert tail.status_code == 200, tail.text
    assert tail.json() == {
        "entries": [
            {
                "seq": 1,
                "at": (now_ms - 2000) // 1000 * 1000,
                "level": "INFO",
                "logger": "Minecraft",
                "message": "Starting server",
            },
            {
                "seq": 2,
                "at": now_ms // 1000 * 1000,
                "level": "INFO",
                "logger": "Minecraft",
                "message": "Done",
            },
        ],
        "next": 2,
    }
    # Cursors only move forward; an empty page reports the latest sequence.
    again = await request(store, "GET", "/v2/console/logs?consumerId=game&since=2")
    assert again.json() == {"entries": [], "next": 2}
    assert (
        await request(store, "GET", "/v2/console/logs?consumerId=game&since=-1")
    ).status_code == 422
    assert (
        await request(store, "GET", "/v2/console/logs?consumerId=nope&since=0")
    ).status_code == 404
    assert (
        await request(
            store, "GET", "/v2/console/logs?consumerId=game&since=0", None, "moderator"
        )
    ).status_code == 403
    # Another consumer's credential cannot append to this ring.
    foreign = log_batch(store, "log", [log_entry(now_ms, "x")], consumerId="workshop")
    assert (
        await request(store, "POST", "/v2/console/logs", foreign, "game-agent")
    ).status_code == 403
    # A stale generation fails closed instead of appending.
    stale = log_batch(store, "log", [log_entry(now_ms, "x")])
    stale["generation"] = "00000000-0000-0000-0000-000000000000"
    assert (
        await request(store, "POST", "/v2/console/logs", stale, "game-agent")
    ).status_code == 409
    # Malformed batches never touch the ring.
    for bad in (
        {"entries": []} | {"consumerId": "game"},
        log_batch(store, "log", [{"at": now_ms}]),
        log_batch(store, "log", [log_entry(now_ms, "x" * 2001)]),
        log_batch(store, "log", [log_entry(now_ms, "x") for _ in range(201)]),
    ):
        response = await request(store, "POST", "/v2/console/logs", bad, "game-agent")
        assert response.status_code == 422, response.text


async def test_console_log_retention_bounds_the_ring(store):
    now_ms = int(time.time() * 1000)
    async with await psycopg.AsyncConnection.connect(
        store["admin"],
        options="-c search_path=control,pg_catalog",
        row_factory=psycopg.rows.dict_row,
    ) as conn:
        await conn.execute(
            "INSERT INTO console_log(consumer_id,seq,at,level,logger,message) VALUES('game',1,now()-make_interval(hours=>25),'INFO','old','gone')"
        )
        await conn.execute(
            "INSERT INTO console_log(consumer_id,seq,at,level,logger,message) VALUES('game',5000,now(),'INFO','new','kept')"
        )
        await conn.execute(
            "INSERT INTO console_log_seq(consumer_id,next_seq) VALUES('game',5000)"
        )
        await conn.commit()
    pushed = await request(
        store,
        "POST",
        "/v2/console/logs",
        log_batch(store, "log", [log_entry(now_ms, "fresh")]),
        "game-agent",
    )
    assert pushed.json()["next"] == 5001, pushed.text
    kept = await sql(
        store,
        "SELECT seq,message FROM console_log WHERE consumer_id='game' ORDER BY seq",
    )
    assert [(r["seq"], r["message"]) for r in kept] == [(5000, "kept"), (5001, "fresh")]


async def test_console_log_cursor_survives_full_retention(store):
    # Retention may age out every row: the next batch must continue the
    # persisted cursor, not restart at 1 where a polling site would miss it.
    now_ms = int(time.time() * 1000)
    first = await request(
        store,
        "POST",
        "/v2/console/logs",
        log_batch(
            store,
            "cursor",
            [log_entry(now_ms - 2000, "one"), log_entry(now_ms, "two")],
        ),
        "game-agent",
    )
    assert first.json() == {"accepted": 2, "next": 2}, first.text
    await sql(store, "DELETE FROM console_log WHERE consumer_id='game'")
    second = await request(
        store,
        "POST",
        "/v2/console/logs",
        log_batch(store, "cursor2", [log_entry(now_ms, "three")]),
        "game-agent",
    )
    assert second.json() == {"accepted": 1, "next": 3}, second.text
    tail = await request(store, "GET", "/v2/console/logs?consumerId=game&since=2")
    assert tail.status_code == 200, tail.text
    assert [e["seq"] for e in tail.json()["entries"]] == [3], tail.text
    assert tail.json()["next"] == 3


async def test_console_tail_never_skips_racing_batch(store, monkeypatch):
    # A batch committing between the page and cursor reads must not be
    # skipped: the cursor is read first, so the page snapshot always covers
    # it. The spy injects the commit on the losing side of the race for
    # both statement orders: before the page fetch when the cursor was
    # already read (fixed order), after it when the cursor is still pending
    # (old order, which then advances next past the unseen row).
    now_ms = int(time.time() * 1000)
    pushed = await request(
        store,
        "POST",
        "/v2/console/logs",
        log_batch(store, "log", [log_entry(now_ms, "one"), log_entry(now_ms, "two")]),
        "game-agent",
    )
    assert pushed.json()["next"] == 2, pushed.text
    real_one, real_rows = core.one, core.rows
    state = {"cursor_read": False, "injected": False}

    async def inject_batch():
        async with await psycopg.AsyncConnection.connect(
            store["admin"], options="-c search_path=control,pg_catalog"
        ) as writer:
            await writer.execute(
                "INSERT INTO console_log(consumer_id,seq,at,level,logger,message) VALUES('game',3,now(),'INFO','Minecraft','three')"
            )
            await writer.execute(
                "UPDATE console_log_seq SET next_seq=3 WHERE consumer_id='game'"
            )
            await writer.commit()

    async def spy_one(conn, query, args=()):
        result = await real_one(conn, query, args)
        if "FROM console_log_seq" in query:
            state["cursor_read"] = True
        return result

    async def spy_rows(conn, query, args=()):
        if (
            "FROM console_log WHERE" in query
            and state["cursor_read"]
            and not state["injected"]
        ):
            state["injected"] = True
            await inject_batch()
        result = await real_rows(conn, query, args)
        if (
            "FROM console_log WHERE" in query
            and not state["cursor_read"]
            and not state["injected"]
        ):
            state["injected"] = True
            await inject_batch()
        return result

    monkeypatch.setattr(core, "one", spy_one)
    monkeypatch.setattr(core, "rows", spy_rows)
    tail = await request(store, "GET", "/v2/console/logs?consumerId=game&since=2")
    assert state["injected"], "the racing batch was not injected"
    assert [e["seq"] for e in tail.json()["entries"]] == [3], tail.text
    assert tail.json()["next"] == 3, tail.text
    steady = await request(store, "GET", "/v2/console/logs?consumerId=game&since=3")
    assert steady.json() == {"entries": [], "next": 3}, steady.text


@asynccontextmanager
async def public_app(store, monkeypatch, **env):
    """A second create_app from the same image with CP_PUBLIC_ONLY=1: the
    deployment under test, sharing the store database."""
    for name, value in {"CP_PUBLIC_ONLY": "1", **env}.items():
        monkeypatch.setenv(name, value)
    app = create_app(store["runtime"])
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="https://control.example.test",
        ) as client:
            yield {"app": app, "client": client}


async def pub_request(pub, store, method, path, body=None, role=None, extra=None):
    test_headers = {}
    if role is not None:
        test_headers["Authorization"] = "Bearer " + store["tokens"][role]
    test_headers.update(extra or {})
    return await pub["client"].request(method, path, json=body, headers=test_headers)


async def test_public_instance_serves_only_exact_allowlist(store, monkeypatch):
    await service_token(store, "launcher", ["stats.read"])
    await service_token(store, "agent-read", ["console.read"])
    await service_token(store, "agent-run", ["console.read", "console.run"], via="mcp")
    epoch = "00000000-0000-0000-0000-000000000000"
    async with public_app(store, monkeypatch) as pub:
        # Agent/site/admin routes never pass on the public instance, even
        # with the owner token.
        for method, path in (
            ("POST", "/v2/actions/moderation.say"),
            ("POST", "/v2/console/suggest"),
            ("POST", "/v2/console/logs"),
            ("GET", "/v2/console/logs"),
            ("GET", f"/v2/agents/game/events?epoch={epoch}&cursor=0"),
            ("GET", "/v2/agents/game/snapshot"),
            ("POST", "/v2/agents/game/acks"),
            ("GET", f"/v2/operations/{epoch}"),
            ("POST", "/v2/workshop/game"),
            ("GET", "/v2/workshop/game/desired?consumerId=ws-game"),
            ("PUT", "/v2/workshop/game/state/game-ready"),
            ("GET", f"/v2/workshop/game/{epoch}/events"),
            ("GET", "/v2/settings/catalog"),
            ("GET", "/v2/openapi.json"),
            ("GET", "/v1/openapi.json"),
            ("GET", "/v2/stats/hitreg"),
            ("GET", "/v2/stats/diagnostics"),
            ("POST", "/v2/stats/results"),
            ("GET", "/v2/me"),
            ("GET", "/v1/gate"),
        ):
            response = await pub_request(pub, store, method, path, None, "owner")
            assert response.status_code == 404, (method, path, response.text)
        # The read-only console line passes with the read token and its own
        # operation polls on the public instance too.
        line = await pub_request(
            pub,
            store,
            "POST",
            "/v2/actions/console.run",
            console_body(store, "p1", "list"),
            "agent-read",
        )
        assert line.status_code == 202, line.text
        op_id = line.json()["operationId"]
        op = await pub_request(
            pub, store, "GET", f"/v2/operations/{op_id}", None, "agent-read"
        )
        assert op.status_code == 200, op.text
        # A read-scoped credential cannot run a non-read-only line there.
        denied = await pub_request(
            pub,
            store,
            "POST",
            "/v2/actions/console.run",
            console_body(store, "p2", "save-all"),
            "agent-read",
        )
        assert denied.status_code == 403, denied.text
        # Someone else's operation does not read back.
        foreign = await pub_request(
            pub, store, "GET", f"/v2/operations/{op_id}", None, "agent-run"
        )
        assert foreign.status_code == 403, foreign.text
        # Per-token public budget: 60/min; the 61st is refused, while the
        # same token still passes internally (separate budgets).
        await service_token(store, "flooder", ["stats.read"])
        for _ in range(60):
            response = await pub_request(
                pub, store, "GET", "/v2/stats/seasons", None, "flooder"
            )
            assert response.status_code == 200, response.text
        assert (
            await pub_request(pub, store, "GET", "/v2/stats/seasons", None, "flooder")
        ).status_code == 429
        assert (
            await request(store, "GET", "/v2/stats/seasons", None, "flooder")
        ).status_code == 200
        # Every response carries the hardening headers.
        health = await pub_request(pub, store, "GET", "/health")
        assert health.status_code == 200, health.text
        assert health.json() == {"status": "ok"}, health.text
        for header, value in (
            ("strict-transport-security", "max-age=31536000; includeSubDomains"),
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", "DENY"),
            ("referrer-policy", "no-referrer"),
            ("content-security-policy", "default-src 'none'; frame-ancestors 'none'"),
            ("cache-control", "no-store"),
        ):
            assert health.headers[header] == value, header


async def test_internal_instance_ignores_public_header(store):
    # The header is meaningless to the internal instance: deployment decides.
    for marker in ("1", "0", "true", " 1 ", "1, 1"):
        extra = {"X-CP-Public": marker}
        me = await request(store, "GET", "/v2/me", None, "owner", extra)
        assert me.status_code == 200, (marker, me.text)
        run = await request(
            store,
            "POST",
            "/v2/actions/console.run",
            console_body(store, f"h-{marker[:2]}", "list"),
            "owner",
            extra,
        )
        assert run.status_code == 202, (marker, run.text)
        # And anonymous stats reads stay internal-only: 401, not 200.
        anon = await store["client"].get("/v2/stats/seasons", headers=extra)
        assert anon.status_code == 401, (marker, anon.text)


async def test_public_hitreg_and_diagnostics_stay_staff_only(store, monkeypatch):
    await service_token(store, "analyst", ["stats.read"])
    async with public_app(store, monkeypatch) as pub:
        for path in ("/v2/stats/hitreg", "/v2/stats/diagnostics"):
            response = await pub_request(pub, store, "GET", path, None, "analyst")
            assert response.status_code == 404, (path, response.text)
    # Same token, same reads stay reachable on the internal instance.
    assert (
        await request(store, "GET", "/v2/stats/hitreg", None, "analyst")
    ).status_code == 200


async def test_public_anonymous_stats_reads(store, monkeypatch):
    async with public_app(store, monkeypatch) as pub:
        assert (
            await pub_request(pub, store, "GET", "/v2/stats/seasons")
        ).status_code == 200
        assert (
            await pub_request(pub, store, "GET", "/v2/stats/leaderboard")
        ).status_code == 200
        # Unknown player: the route is reached without a token (404 from the
        # lookup, not 401 from auth).
        player = await pub_request(pub, store, "GET", f"/v2/stats/players/{uuid4()}")
        assert player.status_code == 404, player.text
        assert player.json() == {"error": "player_not_found"}, player.text
        # A scoped-but-wrong token still 403s: anonymous does not launder scope.
        assert (
            await pub_request(pub, store, "GET", "/v2/stats/seasons", None, "ordinary")
        ).status_code == 403
    # Internal stays authenticated: no token, no read.
    assert (await store["client"].get("/v2/stats/seasons")).status_code == 401


async def test_public_auth_failures_do_not_touch_internal_budget(store, monkeypatch):
    async with public_app(store, monkeypatch) as pub:
        # 101 garbage bearers burn the public unauthenticated budget (100):
        # the last ones 429 while the internal budget stays untouched.
        statuses = [
            (
                await pub["client"].get(
                    "/v2/stats/seasons",
                    headers={"Authorization": f"Bearer junk-{i}"},
                )
            ).status_code
            for i in range(101)
        ]
        assert 429 in statuses, statuses[-5:]
        # An internal caller with a wrong bearer still gets 401, never 429
        # from public traffic.
        wrong = await store["client"].get(
            "/v2/me", headers={"Authorization": "Bearer wrong"}
        )
        assert wrong.status_code == 401, wrong.text
        assert wrong.json() == {"error": "unauthorized"}, wrong.text


def _fake_request(*, public, xff="", peer="198.51.100.9"):
    return SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(public_only=public, public_trusted=())
        ),
        headers={"x-forwarded-for": xff},
        client=SimpleNamespace(host=peer),
    )


def test_public_client_address_trust_and_ipv6_buckets():
    proxy = ipaddress.ip_network("10.0.0.0/8")
    direct = _fake_request(public=False, xff="203.0.113.9", peer="10.1.2.3")
    assert cpv2_app.client_address(direct) == "10.1.2.3"
    untrusted = _fake_request(public=True, xff="203.0.113.9", peer="10.1.2.3")
    assert cpv2_app.client_address(untrusted) == "10.1.2.3"
    req = _fake_request(public=True, xff="203.0.113.9, 10.1.2.3", peer="10.9.9.9")
    req.app.state.public_trusted = (proxy,)
    assert cpv2_app.client_address(req) == "203.0.113.9"
    # Entries left of the rightmost untrusted one are client-supplied.
    req = _fake_request(
        public=True, xff="192.0.2.1, 203.0.113.9, 10.1.2.3", peer="10.9.9.9"
    )
    req.app.state.public_trusted = (proxy,)
    assert cpv2_app.client_address(req) == "203.0.113.9"
    # A chain shorter than the trusted set falls back to the socket peer.
    req = _fake_request(public=True, xff="", peer="10.9.9.9")
    req.app.state.public_trusted = (proxy,)
    assert cpv2_app.client_address(req) == "10.9.9.9"
    # One /64 is one bucket: distinct addresses in it key together, the
    # next /64 keys apart; mapped v4 keys as v4; ports strip; garbage fails
    # closed to the peer.
    req = _fake_request(public=True, xff="2001:db8:1:1::a", peer="10.9.9.9")
    req.app.state.public_trusted = (proxy,)
    first = cpv2_app.client_address(req)
    req.headers["x-forwarded-for"] = "2001:db8:1:1::b"
    assert cpv2_app.client_address(req) == first
    req.headers["x-forwarded-for"] = "2001:db8:1:2::a"
    assert cpv2_app.client_address(req) != first
    req.headers["x-forwarded-for"] = "::ffff:203.0.113.9"
    assert cpv2_app.client_address(req) == "203.0.113.9"
    req.headers["x-forwarded-for"] = "203.0.113.9:51234"
    assert cpv2_app.client_address(req) == "203.0.113.9"
    req.headers["x-forwarded-for"] = "not-an-ip, 10.1.2.3"
    assert cpv2_app.client_address(req) == "10.9.9.9"


def test_public_allowlist_is_exact_and_uses_raw_scope():
    allowed = cpv2_app.public_allowed
    assert allowed("GET", "/health")
    assert allowed("HEAD", "/v2/stats/seasons")
    assert allowed("GET", "/v2/stats/players/12345678-1234-1234-1234-123456789abc")
    assert allowed("POST", "/v2/actions/console.run")
    assert allowed("GET", "/v2/operations/12345678-1234-1234-1234-123456789abc")
    for method, path in (
        ("GET", "/v2/stats/hitreg"),
        ("GET", "/v2/stats/diagnostics"),
        ("GET", "/openapi.json"),
        ("GET", "/v1/openapi.json"),
        ("POST", "/v2/stats/results"),
        ("POST", "/v2/console/suggest"),
        ("GET", "/v2/stats/players/a/b"),
        ("GET", "/v2/stats/players/"),
        ("GET", "/v2/operations/a/b"),
        ("POST", "/v2/workshop/game"),
        ("GET", "/v2/workshop/game/desired"),
        ("PUT", "/v2/workshop/game/state/game-ready"),
        ("GET", "/v2/workshop/game/12345678-1234-1234-1234-123456789abc/events"),
        ("GET", "/hea%09lth"),
        ("OPTIONS", "/health"),
        ("POST", "/v2/stats/seasons"),
    ):
        assert not allowed(method, path), (method, path)
    # The policy path is the raw scope path: the URL parser drops the tab,
    # the scope keeps it, and the allowlist never sees "/health".
    scope = {"path": "/hea%09lth", "headers": []}
    assert raw_path(SimpleNamespace(scope=scope)) == "/hea%09lth"
    assert not allowed("GET", raw_path(SimpleNamespace(scope=scope)))


async def test_public_operation_reads_are_own_credential_only(store, monkeypatch):
    op = await queued(store)
    path = "/v2/operations/" + op["operationId"]
    # Internal policy is unchanged: privileged readers read foreign operations.
    assert (await request(store, "GET", path, role="owner")).status_code == 200
    assert (await request(store, "GET", path, role="admin")).status_code == 200
    assert (await request(store, "GET", path, role="moderator")).status_code == 200
    async with public_app(store, monkeypatch) as pub:
        # The issuing credential reads its own operation on the public instance.
        own = await pub_request(pub, store, "GET", path, None, "moderator")
        assert own.status_code == 200, own.text
        # operations.read (admin) and audit.read (owner) never widen it there.
        for role in ("owner", "admin", "builder"):
            foreign = await pub_request(pub, store, "GET", path, None, role)
            assert foreign.status_code == 403, (role, foreign.text)
            assert foreign.json() == {"error": "forbidden"}, (role, foreign.text)


async def test_public_stats_cache_ignores_unknown_params(store, monkeypatch):
    calls = 0
    real = core.stat_leaderboard

    async def counting(conn, query):
        nonlocal calls
        calls += 1
        return await real(conn, query)

    monkeypatch.setattr(core, "stat_leaderboard", counting)
    async with public_app(store, monkeypatch) as pub:
        first = await pub_request(pub, store, "GET", "/v2/stats/leaderboard?zzz=1")
        assert first.status_code == 200, first.text
        # A different junk param names the same effective query: a cache hit,
        # not a fresh aggregate.
        second = await pub_request(pub, store, "GET", "/v2/stats/leaderboard?zzz=2")
        assert second.status_code == 200, second.text
        assert calls == 1, calls
        assert second.json() == first.json()
        # Effective filters still key apart.
        third = await pub_request(pub, store, "GET", "/v2/stats/leaderboard?limit=1")
        assert third.status_code == 200, third.text
        assert calls == 2, calls


async def test_public_stats_concurrent_misses_share_one_aggregate(store, monkeypatch):
    calls = 0
    entered, release = asyncio.Event(), asyncio.Event()
    real = core.stat_leaderboard

    async def gated(conn, query):
        nonlocal calls
        calls += 1
        entered.set()
        await asyncio.wait_for(release.wait(), 10)
        return await real(conn, query)

    monkeypatch.setattr(core, "stat_leaderboard", gated)
    async with public_app(store, monkeypatch) as pub:

        async def opener():
            await asyncio.wait_for(entered.wait(), 10)
            release.set()

        task = asyncio.create_task(opener())
        try:
            first, second = await asyncio.gather(
                pub_request(pub, store, "GET", "/v2/stats/leaderboard"),
                pub_request(pub, store, "GET", "/v2/stats/leaderboard"),
            )
        finally:
            release.set()
            await asyncio.gather(task, return_exceptions=True)
        assert first.status_code == 200, first.text
        assert second.status_code == 200, second.text
        assert calls == 1, calls
        assert first.json() == second.json()


async def test_public_stats_cache_serves_anonymous(store, monkeypatch):
    calls = 0
    real_seasons = core.stat_seasons

    def counting():
        nonlocal calls
        calls += 1
        return real_seasons()

    monkeypatch.setattr(core, "stat_seasons", counting)
    async with public_app(store, monkeypatch) as pub:
        assert (
            await pub_request(pub, store, "GET", "/v2/stats/seasons")
        ).status_code == 200
        assert (
            await pub_request(pub, store, "GET", "/v2/stats/seasons")
        ).status_code == 200
        assert calls == 1
        await service_token(store, "reader", ["stats.read"])
        assert (
            await pub_request(pub, store, "GET", "/v2/stats/seasons", None, "reader")
        ).status_code == 200
        assert calls == 2


async def test_console_run_requires_actor_unless_agent_client(store):
    await service_token(store, "bare", ["console.read", "console.run"])
    denied = await request(
        store,
        "POST",
        "/v2/actions/console.run",
        console_body(store, "m1", "save-all"),
        "bare",
    )
    assert denied.status_code == 403, denied.text
    assert denied.json() == {"error": "service_actor_required"}, denied.text
    # Read-only lines still run actorless on any service credential.
    tick = await request(
        store,
        "POST",
        "/v2/actions/console.run",
        console_body(store, "m2", "tick query"),
        "bare",
    )
    assert tick.status_code == 202, tick.text
    # The agent client (via "mcp", e.g. the approval-relay token) runs
    # actorless lines; the site principal must assert its human.
    await service_token(store, "agent", ["console.read", "console.run"], via="mcp")
    run = await request(
        store,
        "POST",
        "/v2/actions/console.run",
        console_body(store, "m3", "save-all"),
        "agent",
    )
    assert run.status_code == 202, run.text


def test_observer_stream_pool_is_separate():
    wakeups = delivery.Wakeups("dbname=unused")
    held = []
    try:
        for i in range(32):
            held.append((f"game-{i}", wakeups.subscribe(f"game-{i}")))
            held.append((f"game-{i}", wakeups.subscribe(f"game-{i}")))
        with pytest.raises(Problem):
            wakeups.subscribe("game-new")
        # Observers draw from their own pool while agents are full.
        for i in range(16):
            held.append((f"observer:{i}", wakeups.subscribe(f"observer:{i}")))
            held.append((f"observer:{i}", wakeups.subscribe(f"observer:{i}")))
        with pytest.raises(Problem):
            wakeups.subscribe("observer:full")
        with pytest.raises(Problem):
            wakeups.subscribe("observer:0")
    finally:
        for consumer, waiter in held:
            wakeups.unsubscribe(consumer, waiter)
    assert not wakeups.waiters


async def test_suggest_cancellation_releases_waiter(store, monkeypatch):
    # A cancellation while write waits on the database must release the
    # preallocated waiter: 64 such cancellations used to exhaust the slots.
    entered, release = asyncio.Event(), asyncio.Event()

    async def hanging(conn, identity, attempt, body):
        entered.set()
        await asyncio.wait_for(release.wait(), 10)
        raise AssertionError("unreachable: cancelled first")

    monkeypatch.setattr(core, "console_suggest", hanging)
    wakeups = store["app"].state.wakeups
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(
            store["client"].post(
                "/v2/console/suggest",
                json=suggest_body(store, "s-cancel", "time s"),
                headers=headers(store),
            ),
            5,
        )
    release.set()
    assert not wakeups.suggest_waiters


async def test_suggest_takes_waiter_slot_before_enqueue(store):
    wakeups = store["app"].state.wakeups
    held = [wakeups.subscribe_suggest("game") for _ in range(64)]
    try:
        response = await store["client"].post(
            "/v2/console/suggest",
            json=suggest_body(store, "s-full", "time s"),
            headers=headers(store),
        )
        assert response.status_code == 429, response.text
        # Nothing was enqueued for a completion that could never wait.
        assert not await sql(
            store, "SELECT * FROM operations WHERE kind='console.suggest'"
        ), response.text
    finally:
        for waiter in held:
            wakeups.unsubscribe_suggest("game", waiter)
    assert not wakeups.suggest_waiters


async def test_trailing_slash_never_redirects(store, monkeypatch):
    await service_token(store, "slash", ["stats.read"])
    internal = await request(store, "GET", "/v2/stats/seasons/", None, "slash")
    assert internal.status_code == 404, internal.text
    assert "location" not in internal.headers
    async with public_app(store, monkeypatch) as pub:
        public = await pub_request(
            pub, store, "GET", "/v2/stats/seasons/", None, "slash"
        )
        assert public.status_code == 404, public.text
        assert "location" not in public.headers


async def test_console_log_ingest_redacts_addresses(store):
    now_ms = int(time.time() * 1000)
    message = (
        "conn from 203.0.113.9 password=Hunter2Hunter2Hunter2Hunter2Hunter2 "
        "see https://internal/x and 2001:db8::5"
    )
    batch = log_batch(store, "log", [log_entry(now_ms, message)])
    assert (
        await request(store, "POST", "/v2/console/logs", batch, "game-agent")
    ).status_code == 201
    tail = await request(store, "GET", "/v2/console/logs?consumerId=game&since=0")
    assert tail.status_code == 200, tail.text
    stored = tail.json()["entries"][0]["message"]
    assert "203.0.113.9" not in stored, stored
    assert "2001:db8::5" not in stored, stored
    assert "Hunter2" not in stored, stored
    assert "https://internal/x" not in stored, stored
    assert "[ip]" in stored and "[secret]" in stored and "[url]" in stored, stored


async def test_public_entrypoint_rejects_stats_mutations(store, monkeypatch):
    # Method-scoped allowlist: even a credential holding the mutation scope
    # cannot invoke it through the public entrypoint.
    server = "22222222-2222-2222-2222-222222222222"
    await _stats_token(store, server)
    await _stats_token(store, _DIAG_SERVER, "stats-diag")
    async with public_app(store, monkeypatch) as pub:
        created = await pub_request(
            pub,
            store,
            "POST",
            "/v2/stats/results",
            _stats_campaign_body(),
            "stats-producer",
        )
        assert created.status_code == 404, created.text
        assert created.json() == {"error": "not_found"}
        diag = await pub_request(
            pub, store, "POST", "/v2/stats/diagnostics", _diag_body(), "stats-diag"
        )
        assert diag.status_code == 404, diag.text
        assert diag.json() == {"error": "not_found"}
        void = await pub_request(
            pub,
            store,
            "POST",
            "/v2/stats/results/void",
            {
                "serverId": server,
                "eventId": "11111111-1111-1111-1111-111111111111",
                "voided": True,
            },
            "admin",
        )
        assert void.status_code == 404, void.text
        assert void.json() == {"error": "not_found"}
    # Same mutations stay reachable on the internal instance (auth decides).
    assert (
        await request(
            store, "POST", "/v2/stats/results", _stats_campaign_body(), "stats-producer"
        )
    ).status_code == 201


@pytest.fixture
def frozen_limits_window(monkeypatch):
    """Pin the Limits minute window: a rollover mid-test clears every bucket."""
    fixed = time.monotonic()

    class Clock:
        def __getattr__(self, name):
            return getattr(time, name)

        @staticmethod
        def monotonic():
            return fixed

    monkeypatch.setattr(cpv2_app, "time", Clock())


async def test_public_traffic_does_not_consume_shared_budget(
    store, monkeypatch, frozen_limits_window
):
    await service_token(store, "launcher", ["stats.read"])
    async with public_app(store, monkeypatch) as pub:
        for _ in range(10):
            response = await pub_request(
                pub, store, "GET", "/v2/stats/seasons", None, "launcher"
            )
            assert response.status_code == 200, response.text
        assert pub["app"].state.limiter.total == 0
    internal = await request(store, "GET", "/v2/stats/seasons", None, "launcher")
    assert internal.status_code == 200, internal.text
    assert store["app"].state.limiter.total == 1


async def test_public_and_internal_buckets_are_fully_isolated(
    store, monkeypatch, frozen_limits_window
):
    # Public traffic must never consume an internal bucket and vice versa:
    # each side 429s on its own exhausted budget while the other still
    # passes. Buckets are filled directly (same 600/request limits the
    # pipeline enforces) to keep the test to a handful of requests.
    await service_token(store, "launcher", ["stats.read"])
    await service_token(store, "launcher-b", ["stats.read"])
    async with public_app(store, monkeypatch) as pub:
        app = pub["app"]
        assert (
            await pub_request(pub, store, "GET", "/v2/stats/seasons", None, "launcher")
        ).status_code == 200
        assert ("client", "launcher") not in store["app"].state.limiter.buckets
        assert store["app"].state.limiter.total == 0
        assert ("client", "launcher") in app.state.pub_limiter.buckets
        before = dict(app.state.pub_limiter.buckets)
        assert (
            await request(store, "GET", "/v2/stats/seasons", None, "launcher")
        ).status_code == 200
        assert dict(app.state.pub_limiter.buckets) == before
        assert ("client", "launcher") in store["app"].state.limiter.buckets
        # Exhausting the public per-client bucket denies public requests
        # while internal requests from another client still pass.
        for _ in range(600):
            try:
                app.state.pub_limiter.check(
                    ("client", "launcher-b"), global_count=False, limit=600
                )
            except Problem:
                break
        assert (
            await pub_request(
                pub, store, "GET", "/v2/stats/seasons", None, "launcher-b"
            )
        ).status_code == 429
        assert (
            await request(store, "GET", "/v2/stats/seasons", None, "launcher-b")
        ).status_code == 200


async def test_workshop_game_migration_adds_capabilities_idempotently(store):
    generation = str(store["generation"])
    for cid, caps, resource in (
        ("legacy-ws-game", ["console.run"], "workshop"),
        ("legacy-game-main", ["console.run", "moderation.say"], "*"),
        ("legacy-ws-ctrl", ["workshop.members"], "workshop"),
        ("legacy-ws-other", ["console.run"], "other"),
    ):
        await provision(
            store["admin"],
            {
                "client": {
                    "id": cid,
                    "via": "game",
                    "ceiling": ["agents.acks", "agents.events"],
                },
                "ceiling": ["agents.acks", "agents.events"],
                "environment": "prod",
                "backend": "game",
                "resource": resource,
                "consumer": {"id": cid, "generation": generation, "capabilities": caps},
            },
        )
    migration = (
        Path(__file__).resolve().parents[1] / "migrations/014_workshop_game.sql"
    ).read_text()
    migration = "\n".join(
        line
        for line in migration.splitlines()
        if not line.startswith("SET search_path")
    )
    for _ in range(2):
        await sql(store, migration)
    rows_ = {
        r["id"]: r["capabilities"]
        for r in await sql(
            store,
            "SELECT id, capabilities FROM consumers WHERE id LIKE 'legacy-ws-%%' OR id = 'legacy-game-main'",
        )
    }
    assert rows_["legacy-ws-game"] == [
        "console.run",
        "workshop.game",
        "workshop.ready",
    ]
    assert rows_["legacy-game-main"] == ["console.run", "moderation.say"]
    assert rows_["legacy-ws-ctrl"] == ["workshop.members"]
    assert rows_["legacy-ws-other"] == ["console.run"]


async def test_workshop_game_state_rejects_other_resource_consumer(store):
    generation = str(store["generation"])
    store["tokens"]["foreign-agent"] = await provision(
        store["admin"],
        {
            "client": {
                "id": "foreign-agent",
                "via": "game",
                "ceiling": ["agents.events", "agents.acks"],
            },
            "ceiling": ["agents.events", "agents.acks"],
            "environment": "prod",
            "backend": "game",
            "resource": "other",
            "consumer": {
                "id": "foreign-agent",
                "generation": generation,
                "capabilities": ["workshop.ready"],
            },
        },
    )
    snapshot = await request(
        store, "GET", "/v2/agents/foreign-agent/snapshot", role="foreign-agent"
    )
    assert snapshot.status_code == 200
    assert "workshopDesired" not in snapshot.json()
    desired = await request(
        store,
        "GET",
        "/v2/workshop/game/desired?consumerId=foreign-agent",
        role="foreign-agent",
    )
    assert desired.status_code == 409
    put = await request(
        store,
        "PUT",
        "/v2/workshop/game/state/game-ready",
        {"consumerId": "foreign-agent", "generation": generation, "value": {}},
        "foreign-agent",
    )
    assert put.status_code == 409


async def test_workshop_game_dispatch_sse_and_state(store):
    from types import SimpleNamespace

    generation = str(store["generation"])
    await _workshop_service(
        store,
        "ws-controller",
        ["workshop.gate", "workshop.report", "workshop.game"],
        resource="workshop",
    )
    await _workshop_service(store, "ws-site-reader", ["workshop.read"])
    store["tokens"]["ws-game-agent"] = await provision(
        store["admin"],
        {
            "client": {
                "id": "ws-game",
                "via": "game",
                "ceiling": ["agents.events", "agents.acks"],
            },
            "ceiling": ["agents.events", "agents.acks"],
            "environment": "prod",
            "backend": "game",
            "resource": "workshop",
            "consumer": {
                "id": "ws-game",
                "generation": generation,
                "capabilities": ["console.run", "workshop.game", "workshop.ready"],
            },
        },
    )

    body = {
        "idempotencyKey": "ws-save-1",
        "environment": "prod",
        "backend": "game",
        "consumerId": "ws-game",
        "generation": generation,
        "gameOp": "save-flush",
    }
    # Human owners and non-controller credentials never invoke workshop.game.
    assert (
        await request(store, "POST", "/v2/workshop/game", body, "owner")
    ).status_code == 403
    assert (
        await request(store, "POST", "/v2/workshop/game", body, "ws-site-reader")
    ).status_code == 403
    # Target consumer must carry workshop.game capability and cover workshop.
    assert (
        await request(
            store,
            "POST",
            "/v2/workshop/game",
            body | {"idempotencyKey": "ws-wrong-consumer", "consumerId": "game"},
            "ws-controller",
        )
    ).status_code == 409

    accepted = await request(store, "POST", "/v2/workshop/game", body, "ws-controller")
    assert accepted.status_code == 202, accepted.text
    op_id = accepted.json()["operationId"]
    # Exact idempotent replay returns the same receipt; conflict returns 409.
    replay = await request(store, "POST", "/v2/workshop/game", body, "ws-controller")
    assert replay.status_code == 202 and replay.json()["operationId"] == op_id
    conflict = await request(
        store,
        "POST",
        "/v2/workshop/game",
        body | {"gameOp": "stop"},
        "ws-controller",
    )
    assert conflict.status_code == 409

    [frame] = await envelopes(store, cid="ws-game")
    assert frame["payload"] == {
        "kind": "workshop.game",
        "target": "workshop",
        "gameOp": "save-flush",
    }

    # SSE settled stream wakes on ACK without polling and denies foreign callers.
    assert (
        await request(
            store, "GET", f"/v2/workshop/game/{op_id}/events", role="ws-site-reader"
        )
    ).status_code == 403
    assert (
        await request(
            store, "GET", f"/v2/workshop/game/{op_id}/events", role="ws-game-agent"
        )
    ).status_code == 403
    async with store["app"].state.db.transaction() as conn:
        ctrl_identity = await authenticate(conn, store["tokens"]["ws-controller"])
    game_events_endpoint = next(
        route.endpoint
        for route in store["app"].routes
        if route.path == "/v2/workshop/game/{operation_id}/events"
    )
    req = SimpleNamespace(
        state=SimpleNamespace(
            identity=ctrl_identity, token=store["tokens"]["ws-controller"]
        )
    )
    sse_resp = await game_events_endpoint(UUID(op_id), req)
    iterator = sse_resp.body_iterator
    try:
        for st in delivery.STATES:
            ack_req = ack_body(frame, st)
            if st == "effective":
                ack_req["output"] = "saved"
            ack_res = await request(
                store, "POST", "/v2/agents/ws-game/acks", ack_req, "ws-game-agent"
            )
            assert ack_res.status_code == 200, ack_res.text
        settled_chunk = await asyncio.wait_for(anext(iterator), 5)
        assert "event: settled\n" in settled_chunk
        settled_data = json.loads(settled_chunk.split("data: ", 1)[1])
        assert settled_data == {
            "operationId": op_id,
            "status": "effective",
            "state": "effective",
            "code": "ok",
            "output": "saved",
        }
    finally:
        await iterator.aclose()

    job_id = str(uuid4())
    limbo = await request(
        store,
        "POST",
        "/v2/workshop/game",
        body
        | {
            "idempotencyKey": "ws-export-1",
            "gameOp": "export-limbo",
            "job": job_id,
        },
        "ws-controller",
    )
    assert limbo.status_code == 202, limbo.text
    [limbo_frame] = await envelopes(store, cid="ws-game", cursor=1)
    assert limbo_frame["payload"] == {
        "kind": "workshop.game",
        "target": "workshop",
        "gameOp": "export-limbo",
        "job": job_id,
    }

    # game-desired flows controller -> CP -> ws-game (snapshot + /desired),
    # while game-ready/game-activity accept only the bound ws-game consumer.
    assert (
        await request(
            store,
            "PUT",
            "/v2/workshop/state/game-ready",
            {"value": {"running": True}},
            "ws-controller",
        )
    ).status_code == 403
    desired_doc = {
        "schema": 1,
        "selected": {"profile": "workshop", "generation": "gen-7", "session": "s1"},
    }
    assert (
        await request(
            store,
            "PUT",
            "/v2/workshop/state/game-desired",
            {"value": desired_doc},
            "ws-controller",
        )
    ).status_code == 200

    desired_res = await request(
        store,
        "GET",
        f"/v2/workshop/game/desired?consumerId=ws-game&generation={generation}",
        role="ws-game-agent",
    )
    assert desired_res.status_code == 200, desired_res.text
    assert desired_res.json()["initialized"] is True
    assert desired_res.json()["value"] == desired_doc
    ws_snap = (
        await request(store, "GET", "/v2/agents/ws-game/snapshot", role="ws-game-agent")
    ).json()
    assert ws_snap["workshopDesired"]["value"] == desired_doc
    main_snap = (
        await request(store, "GET", "/v2/agents/game/snapshot", role="game-agent")
    ).json()
    assert "workshopDesired" not in main_snap
    assert (
        await request(
            store,
            "GET",
            "/v2/workshop/game/desired?consumerId=game",
            role="game-agent",
        )
    ).status_code == 409
    assert (
        await request(
            store,
            "GET",
            "/v2/workshop/game/desired?consumerId=ws-game",
            role="game-agent",
        )
    ).status_code == 403

    ready_doc = {
        "schema": 1,
        "running": True,
        "profile": "workshop",
        "generation": "gen-7",
        "session": "s1",
        "release": "v9.1.0",
        "updatedAt": 1_700_000_000_000,
    }
    activity_doc = {"schema": 1, "activeAt": 1_700_000_000_000, "players": 0}
    assert (
        await request(
            store,
            "PUT",
            "/v2/workshop/game/state/game-ready",
            {
                "consumerId": "ws-game",
                "generation": generation,
                "value": ready_doc,
            },
            "ws-controller",
        )
    ).status_code == 403
    assert (
        await request(
            store,
            "PUT",
            "/v2/workshop/game/state/status",
            {"consumerId": "ws-game", "generation": generation, "value": {}},
            "ws-game-agent",
        )
    ).status_code == 404
    assert (
        await request(
            store,
            "PUT",
            "/v2/workshop/game/state/game-ready",
            {
                "consumerId": "ws-game",
                "generation": str(uuid4()),
                "value": ready_doc,
            },
            "ws-game-agent",
        )
    ).status_code == 409
    assert (
        await request(
            store,
            "PUT",
            "/v2/workshop/game/state/game-ready",
            {
                "consumerId": "ws-game",
                "generation": generation,
                "value": {"blob": "x" * 20000},
            },
            "ws-game-agent",
        )
    ).status_code == 422

    async with store["app"].state.db.transaction() as conn:
        reader_id = await authenticate(conn, store["tokens"]["ws-site-reader"])
    state_events_endpoint = next(
        route.endpoint
        for route in store["app"].routes
        if route.path == "/v2/workshop/state/events"
    )
    reader_req = SimpleNamespace(
        state=SimpleNamespace(
            identity=reader_id, token=store["tokens"]["ws-site-reader"]
        )
    )
    # Catch current sequence before subscribing so we observe pushes live.
    before_state = (
        await request(
            store,
            "GET",
            "/v2/workshop/state?names=game-desired,game-ready,game-activity",
            role="ws-site-reader",
        )
    ).json()["documents"]
    cursor = before_state["game-desired"]["seq"]
    state_sse = await state_events_endpoint(reader_req, after=cursor)
    state_iter = state_sse.body_iterator
    try:
        r_ready = await request(
            store,
            "PUT",
            "/v2/workshop/game/state/game-ready",
            {"consumerId": "ws-game", "generation": generation, "value": ready_doc},
            "ws-game-agent",
        )
        assert r_ready.status_code == 200 and r_ready.json()["changed"] is True
        r_act = await request(
            store,
            "PUT",
            "/v2/workshop/game/state/game-activity",
            {
                "consumerId": "ws-game",
                "generation": generation,
                "value": activity_doc,
            },
            "ws-game-agent",
        )
        assert r_act.status_code == 200 and r_act.json()["changed"] is True

        pushed = [await asyncio.wait_for(anext(state_iter), 5) for _ in range(2)]
        assert [json.loads(c.split("data: ", 1)[1])["name"] for c in pushed] == [
            "game-ready",
            "game-activity",
        ]
    finally:
        await state_iter.aclose()

    docs = (
        await request(
            store,
            "GET",
            "/v2/workshop/state?names=game-desired,game-ready,game-activity",
            role="ws-site-reader",
        )
    ).json()["documents"]
    assert docs["game-ready"]["value"] == ready_doc
    assert docs["game-activity"]["value"] == activity_doc
