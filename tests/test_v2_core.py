"""Real PostgreSQL + ASGI tests; no production services or executor effects."""

import asyncio
import hashlib
import json
import os
import random
import sqlite3
import struct
import subprocess
import tempfile
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

import api
from cpv2 import core, delivery
from cpv2.admin import bootstrap, provision
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
                    "ceiling": sorted(SERVICE_SCOPES),
                },
                "ceiling": sorted(SERVICE_SCOPES),
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
                    ],
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
    legacy = api.Store(str(path))
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
    legacy = api.Store(str(path))
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
    legacy = api.Store(str(path))
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
    legacy = api.Store(str(path))
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
    legacy = api.Store(str(path))
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
    legacy = api.Store(str(path))
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
        assert op["required_scope"] == "settings.protected.write", op["required_scope"]
        assert await delivery.valid_operation(conn, op) == "rejected"
