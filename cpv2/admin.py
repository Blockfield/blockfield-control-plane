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

from cpv2.auth import OWNER_SCOPES, ROLE_SCOPES, SERVICE_SCOPES, now, verifier
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


async def bootstrap(dsn, account_id, name, credential):
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
            "INSERT INTO accounts(id,display_name) VALUES(%s,%s)", (account_id, name)
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


async def provision(dsn, spec):
    """Operator-only seed for accounts/clients/executors; no HTTP minting authority."""
    token, cid = "cp2_" + secrets.token_urlsafe(32), uuid4()
    async with (
        await psycopg.AsyncConnection.connect(
            dsn, row_factory=dict_row, options="-c search_path=control,pg_catalog"
        ) as conn,
        history(conn),
    ):
        client = spec["client"]
        await conn.execute(
            "INSERT INTO clients(id,via,ceiling,human) VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING",
            (
                client["id"],
                client["via"],
                client["ceiling"],
                client.get("human", False),
            ),
        )
        account_id = UUID(spec["accountId"]) if spec.get("accountId") else None
        if account_id:
            await conn.execute(
                "INSERT INTO accounts(id,display_name) VALUES(%s,%s) ON CONFLICT DO NOTHING",
                (account_id, spec["displayName"]),
            )
            account = await one(
                conn, "SELECT * FROM accounts WHERE id=%s", (account_id,)
            )
            if account["is_test"] or account["status"] != "active":
                raise ValueError("ineligible account")
            epoch = account["authorization_epoch"]
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
            if set(spec["ceiling"]) - SERVICE_SCOPES or client.get("human"):
                raise ValueError("service credential ceiling")
        if set(spec["ceiling"]) - (OWNER_SCOPES if account_id else SERVICE_SCOPES):
            raise ValueError("unknown scope")
        ttl = spec.get("expiresInSeconds", 3600)
        if type(ttl) is not int or not 1 <= ttl <= 86400:
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
    return token


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database-file",
        required=True,
        help="private file with the migration-role DSN",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("migrate")
    boot = commands.add_parser("bootstrap")
    boot.add_argument("--account", type=UUID, required=True)
    boot.add_argument("--name", required=True)
    boot.add_argument(
        "--credential-file",
        required=True,
        help="offline-verified WebAuthn registration: id/publicKey (base64url COSE), rpId, origin",
    )
    issue = commands.add_parser("provision")
    issue.add_argument("--spec-file", required=True)
    issue.add_argument("--token-file", required=True)
    legacy = commands.add_parser("import-u1")
    legacy.add_argument("--sqlite", required=True)
    args = parser.parse_args()
    dsn = private_file(args.database_file).strip()
    if args.command == "migrate":
        await migrate(dsn)
    elif args.command == "bootstrap":
        await bootstrap(
            dsn, args.account, args.name, json.loads(private_file(args.credential_file))
        )
    elif args.command == "provision":
        # Reserve the output before committing an otherwise unreachable credential.
        fd = os.open(
            args.token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(fd, "w") as stream:
            stream.write(
                await provision(dsn, json.loads(private_file(args.spec_file))) + "\n"
            )
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
