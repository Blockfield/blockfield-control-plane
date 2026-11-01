"""One-shot, read-only SQLite import; old actors remain unverified provenance."""

import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from cpv2.db import one
from cpv2.settings import digest


def millis(value):
    return (
        datetime.fromtimestamp(value / 1000, timezone.utc)
        if value is not None
        else None
    )


async def import_u1(dsn, path):
    path = Path(path).resolve(strict=True)
    # The operator fences the old writer and supplies a checkpointed backup.
    source_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    with sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True) as source:
        source.row_factory = sqlite3.Row
        tables = {
            name: [
                dict(row)
                for row in source.execute(f"SELECT * FROM {name} ORDER BY rowid")
            ]
            for name in ("tokens", "gate_state", "gate_log", "audit")
        }
    if len(tables["gate_state"]) != 1:
        raise ValueError("invalid legacy gate")
    state = tables["gate_state"][0]
    if (
        type(state["revision"]) is not int
        or state["revision"] < 0
        or state["mode"] not in ("open", "draining", "maintenance")
    ):
        raise ValueError("invalid legacy state")
    manifest = {
        name: {"count": len(values), "hash": digest(values)}
        for name, values in tables.items()
    }
    async with await psycopg.AsyncConnection.connect(
        dsn, row_factory=dict_row, options="-c search_path=control,pg_catalog"
    ) as conn:
        await conn.execute("SELECT pg_advisory_xact_lock(278004)")
        prior = await one(
            conn,
            "SELECT manifest FROM legacy_imports WHERE source_hash=%s",
            (source_hash,),
        )
        if prior:
            if prior["manifest"] != manifest:
                raise ValueError("import manifest mismatch")
            return manifest
        if await one(
            conn,
            "SELECT 1 FROM legacy_imports UNION ALL SELECT 1 FROM settings_heads LIMIT 1",
        ):
            raise ValueError("import requires an unused staging store")
        await conn.execute(
            "INSERT INTO legacy_imports VALUES(%s,%s,now())",
            (source_hash, Jsonb(manifest)),
        )
        for name, values in tables.items():
            for index, value in enumerate(values):
                await conn.execute(
                    "INSERT INTO legacy_records VALUES(%s,%s,%s,%s)",
                    (source_hash, name, str(index), Jsonb(value)),
                )
        await conn.execute(
            "INSERT INTO legacy_gate(value) VALUES(%s)",
            (Jsonb({k: state[k] for k in ("revision", "mode", "message", "since")}),),
        )
        await conn.execute(
            "INSERT INTO settings_heads VALUES('gate','prod','game','*',%s)",
            (state["revision"],),
        )
        for token in tables["tokens"]:
            if "gate:read" in token["scopes"].split(","):
                await conn.execute(
                    "INSERT INTO legacy_read_tokens VALUES(%s,%s,%s,%s)",
                    (
                        token["verifier_hash"],
                        token["name"],
                        millis(token["expires_at"]),
                        millis(token["revoked_at"]),
                    ),
                )
        # Verify persisted counts/hashes instead of treating a successful INSERT as acceptance.
        for name in tables:
            cursor = await conn.execute(
                "SELECT body FROM legacy_records WHERE source_hash=%s AND kind=%s ORDER BY legacy_id::integer",
                (source_hash, name),
            )
            copied = [r["body"] for r in await cursor.fetchall()]
            if {"count": len(copied), "hash": digest(copied)} != manifest[name]:
                raise ValueError("import verification failed")
    return manifest
