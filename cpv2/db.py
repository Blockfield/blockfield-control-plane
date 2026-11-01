import hashlib
from contextlib import asynccontextmanager
from contextvars import ContextVar
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

ROOT = Path(__file__).resolve().parents[1]
_HISTORY = ContextVar("cp_history", default=None)


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


async def migrate(dsn):
    source = (ROOT / "migrations/001_core.sql").read_bytes()
    checksum = hashlib.sha256(source).hexdigest()
    async with await psycopg.AsyncConnection.connect(dsn, row_factory=dict_row) as conn:
        await conn.execute("SELECT pg_advisory_xact_lock(278002)")
        exists = await one(
            conn, "SELECT to_regclass('control.schema_migrations') AS name"
        )
        if exists["name"]:
            record = await one(
                conn, "SELECT checksum FROM control.schema_migrations WHERE version=1"
            )
            if not record or record["checksum"] != checksum:
                raise RuntimeError("migration checksum mismatch")
            return
        await conn.execute(source.decode(), prepare=False)
        await conn.execute(
            "INSERT INTO control.schema_migrations VALUES(1,%s)", (checksum,)
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
