"""Offline migration/bootstrap/provisioning. Never loaded by the HTTP service."""

import argparse
import asyncio
import json
import os
import secrets
import stat
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlparse
from uuid import UUID, uuid4

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from webauthn.helpers import base64url_to_bytes
from webauthn.helpers.decode_credential_public_key import decode_credential_public_key

from cpv2.auth import (
    OWNER_SCOPES,
    ROLE_SCOPES,
    SERVICE_SCOPES,
    SITE_SESSIONS_SCOPES,
    SITE_SETTINGS_SCOPES,
    STAFF_SCOPES,
    STATS_READ_SCOPES,
    STATS_SCOPES,
    invalidate,
    now,
    verifier,
)
from cpv2.core import service_principal_id
from cpv2.db import history, migrate, one, record


def private_file(path):
    path = Path(path)
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_mode & 0o077
        or info.st_uid != os.getuid()
    ):
        raise ValueError("credential input must be an owned regular private file")
    return path.read_text()


def _checked_credential(credential):
    key = base64url_to_bytes(credential["publicKey"])
    decode_credential_public_key(key)
    base64url_to_bytes(credential["id"])
    origin = urlparse(credential["origin"])
    rp_id = credential["rpId"]
    if (
        origin.scheme != "https"
        or not origin.hostname
        or origin.path != ""
        or origin.query
        or origin.fragment
        or origin.username
        or not (origin.hostname == rp_id or origin.hostname.endswith("." + rp_id))
    ):
        raise ValueError(
            "owner credential requires an independent HTTPS origin and matching RP ID"
        )
    return key, credential["id"], rp_id, credential["origin"]


async def bootstrap(dsn, account_id, name, credential):
    key, credential_id, rp_id, origin = _checked_credential(credential)
    async with (
        await psycopg.AsyncConnection.connect(
            dsn, row_factory=dict_row, options="-c search_path=control,pg_catalog"
        ) as conn,
        history(conn),
    ):
        await conn.execute("SELECT pg_advisory_xact_lock(278003)")
        if await one(conn, "SELECT 1 FROM owner_memberships LIMIT 1"):
            raise ValueError(
                "already bootstrapped; recovery requires separately reviewed offline migration"
            )
        await conn.execute(
            "INSERT INTO accounts(id,display_name) VALUES(%s,%s) ON CONFLICT DO NOTHING",
            (account_id, name),
        )
        attempt = uuid4()
        for outcome in ("pending", "accepted"):
            if outcome == "accepted":
                await conn.execute(
                    "INSERT INTO owner_memberships(account_id) VALUES(%s)",
                    (account_id,),
                )
                await conn.execute(
                    "INSERT INTO owner_credentials(id,account_id,public_key,rp_id,origin) VALUES(%s,%s,%s,%s,%s)",
                    (credential["id"], account_id, key, rp_id, credential["origin"]),
                )
            await record(
                conn,
                "INSERT INTO audit_events(attempt_id,actor,via,request_id,action,target,outcome,detail) VALUES(%s,%s,'recovery',%s,'owner.bootstrap',%s,%s,%s)",
                (
                    attempt,
                    account_id,
                    attempt,
                    str(account_id),
                    outcome,
                    Jsonb({"credentialFingerprint": verifier(credential["publicKey"])}),
                ),
            )
        # Sessions provisioned before the account became owner must not ride
        # into owner authority: revoke every pre-bootstrap credential.
        await invalidate(conn, account_id)


# The owner list names both founders explicitly (control-plane#11): the
# first founder comes from bootstrap(), the second from here. Founder
# identities travel in the operator's offline config (account UUID, display
# name, verified WebAuthn registration) — never in code. Two seats, no
# more: a further owner is a separately reviewed offline migration, like
# bootstrap recovery.
async def enroll_owner(dsn, account_id, name, credential):
    key, credential_id, rp_id, origin = _checked_credential(credential)
    async with (
        await psycopg.AsyncConnection.connect(
            dsn, row_factory=dict_row, options="-c search_path=control,pg_catalog"
        ) as conn,
        history(conn),
    ):
        await conn.execute("SELECT pg_advisory_xact_lock(278003)")
        owners = await one(conn, "SELECT count(*) AS n FROM owner_memberships")
        if owners["n"] == 0:
            raise ValueError("not bootstrapped; the first owner comes from bootstrap")
        if await one(
            conn, "SELECT 1 FROM owner_memberships WHERE account_id=%s", (account_id,)
        ):
            raise ValueError("already an owner")
        if owners["n"] >= 2:
            raise ValueError("the owner list holds both founders; no further owners")
        await conn.execute(
            "INSERT INTO accounts(id,display_name) VALUES(%s,%s) ON CONFLICT DO NOTHING",
            (account_id, name),
        )
        attempt = uuid4()
        for outcome in ("pending", "accepted"):
            if outcome == "accepted":
                await conn.execute(
                    "INSERT INTO owner_memberships(account_id) VALUES(%s)",
                    (account_id,),
                )
                await conn.execute(
                    "INSERT INTO owner_credentials(id,account_id,public_key,rp_id,origin) VALUES(%s,%s,%s,%s,%s)",
                    (credential_id, account_id, key, rp_id, origin),
                )
            await record(
                conn,
                "INSERT INTO audit_events(attempt_id,actor,via,request_id,action,target,outcome,detail) VALUES(%s,%s,'recovery',%s,'owner.enroll',%s,%s,%s)",
                (
                    attempt,
                    account_id,
                    attempt,
                    str(account_id),
                    outcome,
                    Jsonb({"credentialFingerprint": verifier(credential["publicKey"])}),
                ),
            )
        await invalidate(conn, account_id)


async def provision(dsn, spec, bearer_sink=None):
    """Operator-only seed for accounts/clients/executors; no HTTP minting authority."""
    token, _ = await _provision(dsn, spec, bearer_sink)
    return token


# Service credentials (account-less) live at most 30 days and are re-issued
# monthly; human session credentials stay at 24h, like staff rotation.
SERVICE_TTL_CAP = 30 * 86400
HUMAN_TTL_CAP = 86400


async def revoke(dsn, credential_id):
    """Offline revocation; idempotent, refuses unknown ids. No HTTP route."""
    async with (
        await psycopg.AsyncConnection.connect(
            dsn, row_factory=dict_row, options="-c search_path=control,pg_catalog"
        ) as conn,
        history(conn),
    ):
        row = await one(
            conn,
            "SELECT revoked_at FROM credentials WHERE id=%s FOR UPDATE",
            (credential_id,),
        )
        if not row:
            raise ValueError("unknown credential")
        await conn.execute(
            "UPDATE credentials SET revoked_at=coalesce(revoked_at,now()) WHERE id=%s",
            (credential_id,),
        )
        await conn.execute("SELECT pg_notify('cp_events', '')")
        attempt = uuid4()
        await record(
            conn,
            "INSERT INTO audit_events(attempt_id,via,request_id,action,target,outcome,detail) VALUES(%s,'recovery',%s,'credentials.revoke',%s,'accepted',%s)",
            (
                attempt,
                attempt,
                str(credential_id),
                Jsonb({"alreadyRevoked": row["revoked_at"] is not None}),
            ),
        )
    return credential_id


async def _provision(dsn, spec, bearer_sink=None):
    """Same as provision() but also returns the credential id for the receipt."""
    token, cid = "cp2_" + secrets.token_urlsafe(32), uuid4()
    async with (
        await psycopg.AsyncConnection.connect(
            dsn, row_factory=dict_row, options="-c search_path=control,pg_catalog"
        ) as conn,
        history(conn),
    ):
        client = spec["client"]
        # Re-provisioning the same client id updates its registration: the
        # client ceiling caps every credential of that client, so keeping a
        # stale row would silently ignore an operator narrowing the authority.
        await conn.execute(
            "INSERT INTO clients(id,via,ceiling,human) VALUES(%s,%s,%s,%s) ON CONFLICT(id) DO UPDATE SET via=EXCLUDED.via,ceiling=EXCLUDED.ceiling,human=EXCLUDED.human",
            (
                client["id"],
                client["via"],
                client["ceiling"],
                client.get("human", False),
            ),
        )
        account_id = UUID(spec["accountId"]) if spec.get("accountId") else None
        if account_id:
            created = await one(
                conn,
                "INSERT INTO accounts(id,display_name) VALUES(%s,%s) ON CONFLICT DO NOTHING RETURNING id",
                (account_id, spec["displayName"]),
            )
            account = await one(
                conn,
                "SELECT * FROM accounts WHERE id=%s FOR UPDATE",
                (account_id,),
            )
            if account["is_test"] or account["status"] != "active":
                raise ValueError("ineligible account")
            epoch = account["authorization_epoch"]
            if spec.get("grants") and not created:
                # A new account cannot have sessions yet; only a pre-existing
                # account needs rotation before new grants take effect.
                # New grants must not ride into existing sessions: rotate the
                # epoch and revoke exactly like a grant change does, then issue
                # this credential at the updated epoch.
                await invalidate(conn, account_id)
                epoch = (
                    await one(
                        conn,
                        "SELECT authorization_epoch AS epoch FROM accounts WHERE id=%s",
                        (account_id,),
                    )
                )["epoch"]
            for grant in spec.get("grants", []):
                if grant["role"] not in ROLE_SCOPES:
                    raise ValueError("owner membership only via bootstrap")
                await conn.execute(
                    "INSERT INTO role_grants(id,account_id,role,environment,backend,resource,grantor,revision) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
                    (
                        uuid4(),
                        account_id,
                        grant["role"],
                        grant["environment"],
                        grant["backend"],
                        grant["resource"],
                        UUID(grant["grantor"]),
                        epoch,
                    ),
                )
        else:
            epoch = None
            if set(spec["ceiling"]) - (
                SERVICE_SCOPES
                | STAFF_SCOPES
                | SITE_SETTINGS_SCOPES
                | SITE_SESSIONS_SCOPES
                | STATS_SCOPES
                | STATS_READ_SCOPES
            ) or client.get("human"):
                raise ValueError("service credential ceiling")
            if (
                STAFF_SCOPES
                | SITE_SETTINGS_SCOPES
                | SITE_SESSIONS_SCOPES
                | STATS_READ_SCOPES
            ) & set(spec["ceiling"]) and spec["resource"] != "*":
                raise ValueError("site scopes need an unbound site credential")
            if STATS_SCOPES & set(spec["ceiling"]) and spec["resource"] == "*":
                raise ValueError("stats.ingest needs a bound producer credential")
            # The service principal row lives here, not at runtime: this path
            # runs privileged while the service (cp_runtime) cannot INSERT accounts.
            principal, name = service_principal_id(client["id"])
            await conn.execute(
                "INSERT INTO accounts(id,display_name) VALUES(%s,%s) ON CONFLICT DO NOTHING",
                (principal, name),
            )
        if set(spec["ceiling"]) - (
            OWNER_SCOPES
            if account_id
            else SERVICE_SCOPES
            | STAFF_SCOPES
            | SITE_SETTINGS_SCOPES
            | SITE_SESSIONS_SCOPES
            | STATS_SCOPES
            | STATS_READ_SCOPES
        ):
            raise ValueError("unknown scope")
        ttl = spec.get("expiresInSeconds", 3600)
        if type(ttl) is not int or not 1 <= ttl <= (
            HUMAN_TTL_CAP if account_id else SERVICE_TTL_CAP
        ):
            raise ValueError("invalid credential lifetime")
        await conn.execute(
            "INSERT INTO credentials(id,verifier,account_id,client_id,ceiling,environment,backend,resource,kind,authorization_epoch,expires_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                cid,
                verifier(token),
                account_id,
                client["id"],
                spec["ceiling"],
                spec["environment"],
                spec["backend"],
                spec["resource"],
                "session" if account_id else "service",
                epoch,
                now() + timedelta(seconds=ttl),
            ),
        )
        if spec.get("consumer"):
            if account_id:
                raise ValueError("consumer requires its own service credential")
            c = spec["consumer"]
            await conn.execute(
                "INSERT INTO consumers(id,credential_id,environment,backend,resource,generation,epoch,capabilities) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    c["id"],
                    cid,
                    spec["environment"],
                    spec["backend"],
                    spec["resource"],
                    UUID(c["generation"]),
                    uuid4(),
                    c["capabilities"],
                ),
            )
        attempt = uuid4()
        await record(
            conn,
            "INSERT INTO audit_events(attempt_id,via,request_id,action,target,outcome,detail) VALUES(%s,'recovery',%s,'credentials.provision',%s,'accepted',%s)",
            (
                attempt,
                attempt,
                str(cid),
                Jsonb(
                    {
                        "subjectAccount": str(account_id) if account_id else None,
                        "source": "offline_operator",
                    }
                ),
            ),
        )
        if bearer_sink is not None:
            # The bearer reaches its file before the transaction commits, so a
            # later write failure rolls the credential back instead of leaving
            # a live credential nobody holds.
            bearer_sink(token)
    return token, cid


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database-file",
        required=True,
        help="private file with the migration-role DSN",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    migrate_cmd = commands.add_parser("migrate")
    migrate_cmd.add_argument(
        "--database",
        required=True,
        help="expected dedicated control database name; the migration refuses any other database",
    )
    boot = commands.add_parser("bootstrap")
    boot.add_argument("--account", type=UUID, required=True)
    boot.add_argument("--name", required=True)
    boot.add_argument(
        "--credential-file",
        required=True,
        help="offline-verified WebAuthn registration: id/publicKey (base64url COSE), rpId, origin",
    )
    enroll = commands.add_parser("enroll-owner")
    enroll.add_argument("--account", type=UUID, required=True)
    enroll.add_argument("--name", required=True)
    enroll.add_argument(
        "--credential-file",
        required=True,
        help="offline-verified WebAuthn registration of the second founder",
    )
    issue = commands.add_parser("provision")
    issue.add_argument("--spec-file", required=True)
    issue.add_argument("--token-file", required=True)
    revoke_cmd = commands.add_parser("revoke")
    revoke_cmd.add_argument(
        "--credential-id",
        type=UUID,
        required=True,
        help="offline revocation; idempotent, refuses unknown ids",
    )
    legacy = commands.add_parser("import-u1")
    legacy.add_argument("--sqlite", required=True)
    args = parser.parse_args()
    dsn = private_file(args.database_file).strip()
    if args.command == "migrate":
        await migrate(dsn, args.database)
    elif args.command == "bootstrap":
        await bootstrap(
            dsn, args.account, args.name, json.loads(private_file(args.credential_file))
        )
    elif args.command == "enroll-owner":
        await enroll_owner(
            dsn, args.account, args.name, json.loads(private_file(args.credential_file))
        )
    elif args.command == "provision":
        # Reserve the output before committing an otherwise unreachable credential.
        fd = os.open(
            args.token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )

        def sink(token):
            with os.fdopen(fd, "w") as stream:
                stream.write(token + "\n")
                stream.flush()
                os.fsync(stream.fileno())

        try:
            token, cid = await _provision(
                dsn, json.loads(private_file(args.spec_file)), bearer_sink=sink
            )
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(args.token_file)
            except OSError:
                pass
            raise
        # Receipt on stdout, never the token: credential id plus the
        # verifier prefix for the operator's records.
        print(
            json.dumps(
                {
                    "credentialId": str(cid),
                    "fingerprint": verifier(token)[:16],
                },
                sort_keys=True,
            )
        )
    elif args.command == "revoke":
        cid = await revoke(dsn, args.credential_id)
        print(json.dumps({"credentialId": str(cid)}, sort_keys=True))
    else:
        from cpv2.legacy import import_u1

        print(json.dumps(await import_u1(dsn, args.sqlite), sort_keys=True))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (ValueError, psycopg.Error, OSError):
        raise SystemExit(
            "offline command failed; inspect inputs and database with the owner tool (credentials suppressed)"
        ) from None
