import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from psycopg.types.json import Jsonb
from pydantic import ValidationError

from cpv2.auth import (
    ROLE_SCOPES,
    Problem,
    audit,
    covers,
    invalidate,
    now,
    step_up,
    verifier,
)
from cpv2.db import one, record, rows
from cpv2.settings import DEFINITIONS, changed, digest, merge


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
    return {
        "initialized": False,
        "revision": 0,
        "value": definition.model().model_dump(),
        "value_hash": digest(definition.model().model_dump()),
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
    data = model.model_dump(mode="json")
    env, backend = data["environment"], data["backend"]
    identity.require(definition.write, env, backend, target)
    op, duplicate = (
        (None, False)
        if validate
        else await operation(
            conn,
            identity,
            f"settings.{namespace}.{'rollback' if rollback else 'patch'}",
            target,
            data,
            definition.write,
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
        candidate = merge(before["value"], data["patch"])
    try:
        after = definition.model.model_validate(candidate).model_dump()
    except ValidationError:
        raise Problem("invalid_settings", 422) from None
    diff = changed(before["value"], after)
    protected = any(field in definition.owner_paths for field in diff)
    if protected:
        identity.require("settings.protected.write", env, backend, target)
        if not validate:
            await step_up(
                conn, identity, assertion, "POST" if rollback else "PATCH", path, data
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
            identity.actor,
            data["revision"] if rollback else None,
            before.get("state_since", now())
            if namespace == "gate" and before["value"]["mode"] == after["mode"]
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


async def grant_change(conn, identity, attempt, model, assertion, path):
    data = model.model_dump(mode="json")
    env, backend, target = data["environment"], data["backend"], data["resource"]
    scope = "staff.admin.manage" if data["role"] == "admin" else "staff.lower.manage"
    identity.require(scope, env, backend, target)
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


async def action(conn, identity, attempt, kind, model):
    if kind not in ("moderation.kick", "moderation.ban"):
        raise Problem("unknown_action", 404)
    data = model.model_dump(mode="json")
    identity.require(kind, model.environment, model.backend, model.target)
    op, duplicate = await operation(
        conn,
        identity,
        kind,
        model.target,
        data,
        kind,
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
        or kind not in consumer["capabilities"]
    ):
        raise Problem("consumer_generation_or_capability", 409)
    unsettled = await one(
        conn,
        "SELECT count(*) AS n FROM outbox o JOIN operations p ON p.id=o.operation_id WHERE o.consumer_id=%s AND p.kind IN ('moderation.kick','moderation.ban') AND p.deadline>now() AND NOT EXISTS(SELECT 1 FROM consumer_acks a WHERE a.consumer_id=o.consumer_id AND a.sequence=o.sequence AND a.state IN ('effective','rejected','unknown'))",
        (model.consumerId,),
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
        {
            "kind": kind,
            "target": model.target,
            "playerId": data["playerId"],
            "reason": model.reason,
        },
    )
    return await finish(
        conn,
        attempt,
        identity,
        op,
        {
            "payloadHash": digest(
                {
                    "kind": kind,
                    "target": model.target,
                    "playerId": data["playerId"],
                    "reason": model.reason,
                }
            )
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
