import asyncio
from collections import defaultdict
from contextlib import suppress
from datetime import datetime, timedelta
from uuid import uuid4

import psycopg
from psycopg.types.json import Jsonb

from cpv2.auth import Identity, Problem, audit, is_owner_session, now
from cpv2.core import current_settings, event
from cpv2.db import one, rows
from cpv2.settings import canonical, digest

STATES = ("received", "validated", "applied", "effective")
TERMINAL = {"rejected", "unknown", "effective", "expired"}


class Wakeups:
    """Notifications carry wakeups only; committed per-consumer rows carry delivery."""

    def __init__(self, dsn):
        self.dsn = dsn
        self.waiters = defaultdict(set)
        self.ready = asyncio.Event()
        self.task = None

    async def start(self):
        self.task = asyncio.create_task(self.listen())
        await asyncio.wait_for(self.ready.wait(), 10)

    async def close(self):
        if self.task:
            self.task.cancel()
            with suppress(asyncio.CancelledError):
                await self.task

    async def listen(self):
        while True:
            try:
                async with await psycopg.AsyncConnection.connect(
                    self.dsn, autocommit=True, connect_timeout=5
                ) as conn:
                    await conn.execute("LISTEN cp_events")
                    self.ready.set()
                    for waiters in self.waiters.values():
                        for waiter in waiters:
                            waiter.set()
                    async for notification in conn.notifies():
                        ids = (
                            [notification.payload]
                            if notification.payload
                            else list(self.waiters)
                        )
                        for cid in ids:
                            for waiter in self.waiters.get(cid, ()):
                                waiter.set()
            except psycopg.Error:
                # Bounded stream recovery sweep also drains while LISTEN reconnects.
                await asyncio.sleep(1)

    def subscribe(self, consumer):
        if (
            sum(len(items) for items in self.waiters.values()) >= 64
            or len(self.waiters.get(consumer, ())) >= 2
        ):
            raise Problem("stream_limit", 429)
        waiter = asyncio.Event()
        self.waiters[consumer].add(waiter)
        return waiter

    def unsubscribe(self, consumer, waiter):
        self.waiters[consumer].discard(waiter)
        if not self.waiters[consumer]:
            del self.waiters[consumer]


async def consumer_for(conn, identity, consumer_id, scope):
    c = await one(conn, "SELECT * FROM consumers WHERE id=%s", (consumer_id,))
    if (
        not c
        or c["credential_id"] != identity.credential["id"]
        or identity.credential["kind"] != "service"
    ):
        raise Problem("consumer_identity_mismatch")
    identity.require(scope, c["environment"], c["backend"], c["resource"])
    return c


async def valid_operation(conn, op):
    if op["deadline"] <= now():
        return "expired"
    c = await one(conn, "SELECT * FROM credentials WHERE id=%s", (op["credential_id"],))
    if not c or c["revoked_at"] or c["expires_at"] <= now():
        return "rejected"
    # Service-issued operation (e.g. the workshop gate leg): no human
    # account exists, so delivery rechecks the provisioned scope exactly
    # like the accept-time check. A narrowed or revoked credential, or a
    # narrowed client ceiling, fences the frame; nothing here mints
    # human authority.
    if op["account_id"] is None:
        if c["kind"] != "service":
            return "rejected"
        c = await one(
            conn,
            "SELECT * FROM credentials WHERE id=%s FOR SHARE",
            (op["credential_id"],),
        )
        if c["revoked_at"] or c["expires_at"] <= now():
            return "rejected"
        client = await one(conn, "SELECT * FROM clients WHERE id=%s", (c["client_id"],))
        identity = Identity(c, client, None, [], False)
    else:
        account = await one(
            conn, "SELECT * FROM accounts WHERE id=%s FOR SHARE", (op["account_id"],)
        )
        if (
            not account
            or account["status"] != "active"
            or account["is_test"]
            or account["authorization_epoch"] != op["authorization_epoch"]
        ):
            return "rejected"
        c = await one(
            conn,
            "SELECT * FROM credentials WHERE id=%s FOR SHARE",
            (op["credential_id"],),
        )
        if c["revoked_at"] or c["expires_at"] <= now():
            return "rejected"
        client = await one(conn, "SELECT * FROM clients WHERE id=%s", (c["client_id"],))
        grants = await rows(
            conn,
            "SELECT * FROM role_grants WHERE account_id=%s AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>%s)",
            (account["id"], now()),
        )
        owner = is_owner_session(
            client,
            c,
            await one(
                conn,
                "SELECT 1 FROM owner_memberships WHERE account_id=%s",
                (account["id"],),
            ),
        )
        identity = Identity(c, client, account, grants, owner)
    # required_scope lists every permission the accepted diff required
    # (comma-joined); losing any one of them fences the frame.
    if not all(
        identity.allows(scope, op["environment"], op["backend"], op["resource"])
        for scope in op["required_scope"].split(",")
    ):
        return "rejected"
    if c["parent_id"]:
        parent = await one(
            conn, "SELECT * FROM credentials WHERE id=%s", (c["parent_id"],)
        )
        if not parent or parent["revoked_at"] or parent["expires_at"] <= now():
            return "rejected"
    # Rechecked after the issuer locks above: a deadline crossed while waiting
    # must settle as expired, never as authorized.
    if op["deadline"] <= now():
        return "expired"
    return None


async def batch(conn, identity, cid, epoch, cursor, *, live=False):
    c = await consumer_for(conn, identity, cid, "agents.events")
    if (
        c["epoch"] != epoch
        or cursor > (c["next_sequence"] - 1 if live else c["received_cursor"])
        or cursor < 0
    ):
        raise Problem("snapshot_required", 409)
    records = await rows(
        conn,
        "SELECT o.*,p.deadline,p.authorization_epoch FROM outbox o JOIN operations p ON p.id=o.operation_id WHERE consumer_id=%s AND sequence>%s ORDER BY sequence LIMIT 64",
        (cid, cursor),
    )
    # Lock every shared operation in one global (id) order before touching any
    # of them: two consumers draining the same fan-out in different sequence
    # orders must never take these locks in opposite orders and deadlock.
    by_id = (
        {
            o["id"]: o
            for o in await rows(
                conn,
                "SELECT * FROM operations WHERE id = ANY(%s) ORDER BY id FOR UPDATE",
                (sorted({r["operation_id"] for r in records}),),
            )
        }
        if records
        else {}
    )
    result = []
    for record in records:
        op = by_id[record["operation_id"]]
        reason = await valid_operation(conn, op)
        stale = record["generation"] != c["generation"] or record["epoch"] != c["epoch"]
        if stale:
            reason = "rejected"
        if record["revision"]:
            payload = record["payload"]
            head = await one(
                conn,
                "SELECT revision FROM settings_heads WHERE namespace=%s AND environment=%s AND backend=%s AND target=%s",
                (
                    payload["namespace"],
                    c["environment"],
                    c["backend"],
                    payload["target"],
                ),
            )
            if head["revision"] != record["revision"] and not reason:
                # Authorization/expiry verdicts are terminal: a newer revision
                # must not whitewash a revoked or expired issuer.
                reason = "superseded"
        # A stale generation/epoch is this consumer's verdict only: it must not move
        # the shared operation status while sibling consumers still execute it.
        # Nor may it demote an effect a sibling already recorded: op status
        # derives from all per-consumer receipts, never from one late verdict.
        if (
            reason in ("expired", "rejected")
            and not stale
            and op["status"] not in TERMINAL
        ):
            effected = await one(
                conn,
                "SELECT 1 FROM consumer_acks a JOIN outbox o ON o.consumer_id=a.consumer_id AND o.sequence=a.sequence WHERE o.operation_id=%s AND a.state IN ('applied','effective','unknown')",
                (op["id"],),
            )
            if not effected:
                await event(conn, op["id"], reason)
        terminal = await one(
            conn,
            "SELECT state FROM consumer_acks WHERE consumer_id=%s AND sequence=%s AND state IN ('effective','rejected','unknown')",
            (cid, record["sequence"]),
        )
        executable = not reason and not terminal
        if live:
            await audit(
                conn,
                uuid4(),
                identity,
                "agents.stream",
                cid,
                "stream_offered",
                {
                    "sequence": record["sequence"],
                    "generation": str(record["generation"]),
                    "revision": record["revision"],
                    "payloadHash": record["payload_hash"],
                    "executable": executable,
                },
                op["id"],
            )
        result.append(
            {
                "schema": 2,
                "epoch": str(record["epoch"]),
                "sequence": record["sequence"],
                "operationId": str(record["operation_id"]),
                "audience": cid,
                "generation": str(record["generation"]),
                "revision": record["revision"],
                "payloadHash": record["payload_hash"],
                "authorizationEpoch": record["authorization_epoch"],
                "expiresAt": record["deadline"].isoformat(),
                "executable": executable,
                "reason": reason or ("already_terminal" if terminal else None),
                "payload": record["payload"] if executable else None,
            }
        )
    return result


async def acknowledge(conn, identity, attempt, cid, model):
    c = await consumer_for(conn, identity, cid, "agents.acks")
    c = await one(conn, "SELECT * FROM consumers WHERE id=%s FOR UPDATE", (cid,))
    record = await one(
        conn,
        "SELECT * FROM outbox WHERE consumer_id=%s AND sequence=%s",
        (cid, model.sequence),
    )
    if (
        not record
        or model.revision != record["revision"]
        or model.payloadHash != record["payload_hash"]
    ):
        raise Problem("receipt_mismatch", 409)
    body = model.model_dump(mode="json")
    fingerprint = digest(body)
    prior = await one(
        conn,
        "SELECT receipt_hash FROM consumer_acks WHERE consumer_id=%s AND sequence=%s AND state=%s",
        (cid, model.sequence, model.state),
    )
    if prior:
        # Exact historical duplicates succeed before any new-transition
        # generation/epoch rules; a changed duplicate still conflicts.
        if prior["receipt_hash"] != fingerprint:
            raise Problem("receipt_conflict", 409)
        return {"state": model.state, "sequence": model.sequence}
    current = (
        (model.epoch, model.generation)
        == (c["epoch"], c["generation"])
        == (
            record["epoch"],
            record["generation"],
        )
    )
    retired = (record["epoch"], record["generation"]) != (
        c["epoch"],
        c["generation"],
    )
    if not current and (
        not retired
        or (model.epoch, model.generation)
        not in (
            (record["epoch"], record["generation"]),
            (c["epoch"], c["generation"]),
        )
        or model.state not in ("rejected", "unknown")
    ):
        # Retired frames settle only through a documented endpoint identity
        # (historical or current) with a terminal receipt, never as new work.
        raise Problem("receipt_mismatch", 409)
    op = await one(
        conn,
        "SELECT * FROM operations WHERE id=%s FOR UPDATE",
        (record["operation_id"],),
    )
    existing = await rows(
        conn,
        "SELECT state FROM consumer_acks WHERE consumer_id=%s AND sequence=%s",
        (cid, model.sequence),
    )
    states = {item["state"] for item in existing}
    if states & TERMINAL:
        raise Problem("receipt_terminal", 409)
    if model.state == "rejected" and states & {"applied", "effective"}:
        # A rejection cannot erase a recorded effect; report uncertainty instead.
        raise Problem("receipt_terminal", 409)
    if model.state in STATES:
        index = STATES.index(model.state)
        if index and STATES[index - 1] not in states:
            raise Problem("receipt_order", 409)
        if model.state == "received" and model.sequence != c["received_cursor"] + 1:
            raise Problem("receipt_gap", 409)
        # Post-policy received/validated are recorded as historical facts: the
        # executor reports what it did before losing authorization. Execution
        # itself stays fenced at batch time, so recording grants nothing.
    elif model.sequence != c["received_cursor"] + 1 and "received" not in states:
        raise Problem("receipt_gap", 409)
    actual = datetime.fromisoformat(model.actualAt)
    if actual > now() + timedelta(seconds=5) or actual < op["created_at"]:
        raise Problem("receipt_time", 422)
    await conn.execute(
        "INSERT INTO consumer_acks(consumer_id,sequence,state,receipt_hash,result,actual_at) VALUES(%s,%s,%s,%s,%s,%s)",
        (
            cid,
            model.sequence,
            model.state,
            fingerprint,
            Jsonb({"code": model.result}),
            actual,
        ),
    )
    if model.state in ("received", "rejected", "unknown"):
        # A factual receipt above a hole must not authorize skipping that hole on reconnect.
        missing = await one(
            conn,
            "SELECT min(o.sequence) AS sequence FROM outbox o WHERE o.consumer_id=%s AND o.sequence>%s AND NOT EXISTS(SELECT 1 FROM consumer_acks a WHERE a.consumer_id=o.consumer_id AND a.sequence=o.sequence AND a.state IN ('received','rejected','unknown'))",
            (cid, c["received_cursor"]),
        )
        cursor = (
            missing["sequence"] - 1
            if missing["sequence"] is not None
            else c["next_sequence"] - 1
        )
        await conn.execute(
            "UPDATE consumers SET received_cursor=%s,last_heartbeat=now() WHERE id=%s",
            (cursor, cid),
        )
    targets = await rows(
        conn,
        "SELECT o.consumer_id,COALESCE((SELECT state FROM consumer_acks a WHERE a.consumer_id=o.consumer_id AND a.sequence=o.sequence ORDER BY CASE state WHEN 'unknown' THEN 6 WHEN 'rejected' THEN 5 WHEN 'effective' THEN 4 WHEN 'applied' THEN 3 WHEN 'validated' THEN 2 ELSE 1 END DESC LIMIT 1),'accepted') AS state FROM outbox o WHERE operation_id=%s",
        (op["id"],),
    )
    status_list = [r["state"] for r in targets]
    if len(set(status_list)) == 1:
        status = status_list[0]
    elif any(s in ("unknown", "rejected") for s in status_list) or (
        any(s in ("applied", "effective") for s in status_list)
        and any(s in ("accepted", "received", "validated") for s in status_list)
    ):
        status = "partial"
    else:
        status = min(status_list, key=lambda s: ("accepted", *STATES).index(s))
    await event(conn, op["id"], status, {"consumer": cid, "state": model.state})
    await audit(
        conn,
        attempt,
        identity,
        "agents.ack",
        cid,
        model.state,
        {
            "sequence": model.sequence,
            "payloadHash": model.payloadHash,
            "actualAt": model.actualAt,
            "code": model.result,
        },
        op["id"],
    )
    await conn.execute("SELECT pg_notify('cp_events',%s)", (cid,))
    return {"state": model.state, "sequence": model.sequence}


async def snapshot(conn, identity, cid):
    # One consistent snapshot for cursor and settings: under read-committed a
    # concurrent settings write could otherwise pair new values with an old
    # cursor (or omit a value the cursor already acknowledges).
    await conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
    c = await consumer_for(conn, identity, cid, "agents.events")
    result = []
    for namespace in ("gameplay", "gate"):
        if f"settings.{namespace}" not in c["capabilities"]:
            continue
        settings = await rows(
            conn,
            "SELECT r.target,r.revision,r.value,r.value_hash FROM settings_heads h JOIN settings_revisions r USING(namespace,environment,backend,target,revision) WHERE namespace=%s AND environment=%s AND backend=%s AND (%s='*' OR target=%s OR target='*')",
            (namespace, c["environment"], c["backend"], c["resource"], c["resource"]),
        )
        if namespace == "gate" and not any(r["target"] == "*" for r in settings):
            # A resource-scoped consumer bootstraps the same global gate as '*',
            # but never another environment's: resolve from the consumer scope.
            gate = await current_settings(
                conn, "gate", c["environment"], c["backend"], "*"
            )
            if gate["initialized"]:
                settings.append(
                    {
                        "target": "*",
                        "revision": gate["revision"],
                        "value": gate["value"],
                        "value_hash": gate["value_hash"],
                    }
                )
        result.extend({"namespace": namespace, **r} for r in settings)
    # Deterministic wire order: the snapshot hash must not depend on the
    # database's physical return order. Documented as (namespace, target).
    result.sort(key=lambda r: (r["namespace"], r["target"]))
    # A snapshot bootstraps desired state only; it never advances receipt ACKs.
    return {
        "schema": 2,
        "audience": cid,
        "epoch": str(c["epoch"]),
        "generation": str(c["generation"]),
        "cursor": c["received_cursor"],
        "settings": result,
        "hash": digest(result),
    }


def sse(envelope):
    return f"id: {envelope['epoch']}:{envelope['sequence']}\nevent: control\ndata: {canonical(envelope)}\n\n"
