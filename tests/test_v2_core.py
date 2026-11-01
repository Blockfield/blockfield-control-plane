"""Real PostgreSQL + ASGI tests; no production services or executor effects."""

import asyncio
import hashlib
import json
import os
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
    assert (
        await request(
            store, "POST", "/v2/agents/game/acks", ack_body(value), "game-agent"
        )
    ).status_code == 409
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
    assert (
        await request(
            store, "POST", "/v2/agents/game/acks", ack_body(settings[0]), "game-agent"
        )
    ).status_code == 409


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
