"""Real PostgreSQL + ASGI tests; no production services or executor effects."""

import asyncio
import base64
import hashlib
import json
import os
import random
import secrets
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
from datetime import timedelta
from pathlib import Path
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
from cpv2.app import create_app
from cpv2.auth import (
    OWNER_SCOPES,
    ROLE_SCOPES,
    SERVICE_SCOPES,
    Problem,
    authenticate,
    now,
    verifier,
)
from cpv2.db import migrate, one
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
    assert (
        os.environ.get("BLOCKFIELD_BOAT_VM") == "1" or os.environ.get("CI") == "true"
    ), "VM/CI only"
    Path(".cache").mkdir(exist_ok=True)
    subprocess.run(["ss", "-ltnp"], check=True, capture_output=True, timeout=5)
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
            "/v2/settings/gameplay/arena",
            patch(value={"ai": {"hardLimit": 200}}),
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
    path = "/v2/settings/gameplay/arena"
    body = patch(value={"ai": {"hardLimit": 200}})
    assert (await request(store, "PATCH", path, body, "owner")).status_code == 403
    for opts in ({"origin": "https://site.example.test"}, {"uv": False}):
        proof = await assertion(store, "PATCH", path, body, **opts)
        assert (
            await request(store, "PATCH", path, body, "owner", proof)
        ).status_code == 403
    proof = await assertion(store, "PATCH", path, body)
    changed_body = patch(value={"ai": {"hardLimit": 300}})
    assert (
        await request(store, "PATCH", path, changed_body, "owner", proof)
    ).status_code == 403
    response = await request(store, "PATCH", path, body, "owner", proof)
    assert response.status_code == 202, response.text
    # Idempotent retrieval is allowed; it cannot authorize a second operation.
    assert (
        await request(store, "PATCH", path, body, "owner", proof)
    ).json() == response.json()
    second = patch(key="replay", revision=1, value={"ai": {"hardLimit": 400}})
    assert (
        await request(store, "PATCH", path, second, "owner", proof)
    ).status_code == 403


async def test_protected_rollback_and_normalized_parent_patch(store):
    path = "/v2/settings/gameplay/arena"
    first = patch(value={"ai": {"hardLimit": 200}})
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
    second = patch("owner-second", 1, {"ai": {"hardLimit": 300}})
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
        {"ai": {"hardLimit": 400, "budget": 100}},
        {"ai": None},
        {"lobby": {"owner": True}},
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
            store, "PATCH", path, patch("invalid", 1, {"ai": {"budget": 101}})
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
            "body": patch(value={"ai": {"hardLimit": 200}}),
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
    path = "/v2/settings/gameplay/arena"
    body = patch("c14-malformed", value={"ai": {"hardLimit": 200}})
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
    path = "/v2/settings/gameplay/arena"
    body = patch("c18-protected", value={"ai": {"hardLimit": 200}})
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
    path = "/v2/settings/gameplay/arena"
    body = patch("c19-both", value={"ai": {"hardLimit": 200}})
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


WORKSHOP_MAP_CREATE = {
    "mapOp": "map-create",
    "mapId": "arena1",
    "name": "Arena 1",
    "supportedModes": ["tdm", "room"],
    "expectedRevision": 3,
}
WORKSHOP_MAP_PROPERTIES = {
    "mapOp": "map-properties",
    "mapId": "arena1",
    "name": "Arena One",
    "workingCopyId": "e10438e4-797b-4971-88cf-ecec6a8fa171",
    "expectedRevision": 4,
}


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
        ("moderator", "map", {**WORKSHOP_MAP_CREATE, "mapId": "hub"}),
        ("moderator", "map", {**WORKSHOP_MAP_CREATE, "mapId": "Arena!"}),
        ("moderator", "map", {**WORKSHOP_MAP_CREATE, "name": " §bad"}),
        ("moderator", "map", {**WORKSHOP_MAP_CREATE, "supportedModes": []}),
        (
            "moderator",
            "map",
            {**WORKSHOP_MAP_CREATE, "supportedModes": ["tdm", "nope"]},
        ),
        ("moderator", "map", {**WORKSHOP_MAP_CREATE, "supportedModes": ["tdm", "tdm"]}),
        # Unhashable elements must 422, not 500 (set() runs on validated strs).
        ("moderator", "map", {**WORKSHOP_MAP_CREATE, "supportedModes": [[]]}),
        ("moderator", "map", {**WORKSHOP_MAP_PROPERTIES, "workingCopyId": "nope"}),
        ("moderator", "map", {**WORKSHOP_MAP_PROPERTIES, "expectedRevision": -1}),
        ("moderator", "map", {**WORKSHOP_MAP_CREATE, "target": "arena1"}),
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
    # Mode and keys are never service-holdable: provisioning such a ceiling
    # is refused, and act-only credentials cannot mint them either.
    with pytest.raises(ValueError, match="service credential ceiling"):
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
                "resource": "*",
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
    # Members needs the admin-only workshop.members scope, which no service
    # credential may hold: rejected before any owner step-up is evaluated.
    assert response.status_code == 403, response.text
    assert response.json()["error"] == "forbidden"


async def test_c20_health_reports_database_outage(store, monkeypatch):
    # CP-H5: the probe fails closed (503, no internals) when the DB is gone.
    response = await store["client"].get("/health")
    assert response.status_code == 200, response.text
    assert response.json() == {"status": "ok", "schema": 5}
    await store["app"].state.db.close()
    # Success is cached briefly so public probe floods skip the DB.
    assert (await store["client"].get("/health")).status_code == 200
    now = cpv2_app._health_clock()
    monkeypatch.setattr(cpv2_app, "_health_clock", lambda: now + 6)
    broken = await store["client"].get("/health")
    assert broken.status_code == 503, broken.text
    assert broken.json() == {"status": "unavailable", "schema": 5}


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


async def test_settings_patch_nested_delete_reset_and_invalid_delete(store):
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
    # Delete that breaks an invariant is rejected: budget above a deleted hardLimit.
    gpath = "/v2/settings/gameplay/arena"
    first = patch("g-seed", 0, {"ai": {"budget": 200, "hardLimit": 300}})
    proof = await assertion(store, "PATCH", gpath, first)
    assert (
        await request(store, "PATCH", gpath, first, "owner", proof)
    ).status_code == 202
    bad = patch("g-bad", 1, {"ai": {"hardLimit": None}})
    assert (await request(store, "PATCH", gpath, bad, "owner")).status_code == 422


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


async def test_cpp1r2_service_workshop_op_fenced_at_delivery(store):
    # Accept-time per-kind scopes are not enough on their own: a NULL-account
    # (service-issued) operation that is not the workshop gate leg must stay
    # rejected at delivery, so its frame is never executable.
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
    assert not frame["executable"]
    assert frame["payload"] is None


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
    # Voiding the rated campaign replays the season: MMR goes away.
    campaign_void = {"serverId": _U3_SERVER, "eventId": _U3_C1, "voided": True}
    response = await request(
        store, "POST", "/v2/stats/results/void", campaign_void, "admin"
    )
    assert response.status_code == 200, response.text
    assert response.json()["rebuilt"] == "s2"
    after_a, history_after = await mmr_of(_U3_PA)
    assert after_a is None and history_after == []
    # Double void conflicts; restoring replays the same ratings back.
    conflict = await request(
        store, "POST", "/v2/stats/results/void", campaign_void, "admin"
    )
    assert conflict.status_code == 409, conflict.text
    restore = {"serverId": _U3_SERVER, "eventId": _U3_C1, "voided": False}
    response = await request(store, "POST", "/v2/stats/results/void", restore, "admin")
    assert response.status_code == 200, response.text
    assert response.json()["rebuilt"] == "s2"
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
