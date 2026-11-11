import hashlib
from contextlib import asynccontextmanager
from contextvars import ContextVar
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

ROOT = Path(__file__).resolve().parents[1]
_HISTORY = ContextVar("cp_history", default=None)
# Ordered control-schema migrations; version N is list index N-1.
MIGRATIONS = [
    "001_core.sql",
    "002_site_sessions.sql",
    "003_site_stats.sql",
    "004_schema_migrations_read.sql",
]


@asynccontextmanager
async def history(conn):
    pending = []
    token = _HISTORY.set((conn, pending))
    try:
        yield
        if pending:
            # Allocate history IDs only after business locks, just before commit.
            # Holding this lock through commit prevents late commits behind a cursor.
            await conn.execute("SELECT pg_advisory_xact_lock(278005)")
            for query, args in pending:
                await conn.execute(query, args)
    finally:
        _HISTORY.reset(token)


async def record(conn, query, args):
    context = _HISTORY.get()
    if context is None or context[0] is not conn:
        raise RuntimeError("history record requires a managed transaction")
    context[1].append((query, args))


class Database:
    def __init__(self, dsn):
        self.pool = AsyncConnectionPool(
            dsn,
            min_size=1,
            max_size=8,
            open=False,
            timeout=5,
            kwargs={
                "row_factory": dict_row,
                "options": "-c search_path=pg_catalog,control,pg_temp -c statement_timeout=5000",
            },
        )

    async def open(self):
        await self.pool.open(wait=True, timeout=10)

    async def close(self):
        await self.pool.close()

    @asynccontextmanager
    async def transaction(self):
        async with self.pool.connection() as conn:
            async with conn.transaction(), history(conn):
                yield conn


async def one(conn, query, args=()):
    return await (await conn.execute(query, args)).fetchone()


async def rows(conn, query, args=()):
    return await (await conn.execute(query, args)).fetchall()


async def migrate(dsn, expected_database):
    migrations = MIGRATIONS
    checksums = {
        name: hashlib.sha256((ROOT / "migrations" / name).read_bytes()).hexdigest()
        for name in migrations
    }
    async with await psycopg.AsyncConnection.connect(dsn, row_factory=dict_row) as conn:
        actual = await one(conn, "SELECT current_database() AS name")
        if actual["name"] != expected_database:
            raise RuntimeError(
                f"refusing to migrate database {actual['name']!r}: expected the dedicated control database {expected_database!r}"
            )
        await conn.execute("SELECT pg_advisory_xact_lock(278002)")
        exists = await one(
            conn, "SELECT to_regclass('control.schema_migrations') AS name"
        )
        if exists["name"]:
            for version, name in enumerate(migrations, start=1):
                record = await one(
                    conn,
                    "SELECT checksum FROM control.schema_migrations WHERE version=%s",
                    (version,),
                )
                if record:
                    if record["checksum"] != checksums[name]:
                        raise RuntimeError("migration checksum mismatch")
                    continue
                await conn.execute(
                    (ROOT / "migrations" / name).read_bytes().decode(), prepare=False
                )
                await conn.execute(
                    "INSERT INTO control.schema_migrations VALUES(%s,%s)",
                    (version, checksums[name]),
                )
            return
        await conn.execute(
            (ROOT / "migrations/001_core.sql").read_bytes().decode(), prepare=False
        )
        await conn.execute(
            "INSERT INTO control.schema_migrations VALUES(1,%s)",
            (checksums["001_core.sql"],),
        )
        from cpv2.settings import DEFINITIONS
        from psycopg.types.json import Jsonb

        for name, definition in DEFINITIONS.items():
            await conn.execute(
                "INSERT INTO control.setting_definitions VALUES(%s,1,%s,%s,%s,%s,%s,%s,%s)",
                (
                    name,
                    Jsonb(definition.model.model_json_schema()),
                    Jsonb(definition.model().model_dump()),
                    definition.read,
                    definition.write,
                    list(definition.owner_paths),
                    definition.timing,
                    definition.sensitivity,
                ),
            )
        await conn.execute(
            (ROOT / "migrations/002_site_sessions.sql").read_bytes().decode(),
            prepare=False,
        )
        await conn.execute(
            "INSERT INTO control.schema_migrations VALUES(2,%s)",
            (checksums["002_site_sessions.sql"],),
        )
        await conn.execute(
            (ROOT / "migrations/003_site_stats.sql").read_bytes().decode(),
            prepare=False,
        )
        await conn.execute(
            "INSERT INTO control.schema_migrations VALUES(3,%s)",
            (checksums["003_site_stats.sql"],),
        )
        await conn.execute(
            (ROOT / "migrations/004_schema_migrations_read.sql").read_bytes().decode(),
            prepare=False,
        )
        await conn.execute(
            "INSERT INTO control.schema_migrations VALUES(4,%s)",
            (checksums["004_schema_migrations_read.sql"],),
        )
