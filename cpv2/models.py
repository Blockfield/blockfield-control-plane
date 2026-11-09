from typing import Annotated, Literal
from uuid import UUID

from pydantic import BeforeValidator, Field, field_validator

from cpv2.settings import Strict


def parse_uuid(value):
    if isinstance(value, UUID):
        return value
    if not isinstance(value, str):
        raise ValueError("UUID string required")
    return UUID(value)


ID = Annotated[UUID, BeforeValidator(parse_uuid)]


class Mutation(Strict):
    idempotencyKey: str = Field(min_length=1, max_length=128)
    environment: str = Field(default="prod", min_length=1, max_length=64)
    backend: str = Field(default="game", min_length=1, max_length=64)


class SettingsChange(Mutation):
    expectedRevision: int = Field(ge=0, le=9223372036854775807)
    patch: dict


class Rollback(Mutation):
    expectedRevision: int = Field(ge=0, le=9223372036854775807)
    revision: int = Field(ge=1, le=9223372036854775807)


class GrantChange(Mutation):
    accountId: ID
    expectedRevision: int = Field(ge=1, le=9223372036854775807)
    role: Literal["builder", "moderator", "admin"]
    resource: str = Field(min_length=1, max_length=128)
    revoke: bool = False
    # Service-asserted acting account (site principal only). Direct callers
    # are authenticated and must never send it.
    actorAccountId: ID | None = None


class TestStatus(Mutation):
    expectedRevision: int = Field(ge=1, le=9223372036854775807)
    isTest: Literal[True]
    reason: str = Field(min_length=1, max_length=500)
    expiresInSeconds: int = Field(ge=1, le=86400)


class Action(Mutation):
    consumerId: str = Field(min_length=1, max_length=128)
    generation: ID
    target: str = Field(min_length=1, max_length=128)
    playerId: ID
    reason: str = Field(default="", max_length=500)
    expiresInSeconds: int = Field(default=30, ge=1, le=60)
    # Service-asserted acting account (site principal only). Direct callers
    # are authenticated and must never send it.
    actorAccountId: ID | None = None


class ModerationAction(Mutation):
    # Site RCON replacements (say/list/pardon/team-kick/class-lock/unlock,
    # range/stop-room): per-kind fields, validated in core.action like
    # WorkshopAction. playerId stays for kick/ban only; the rest address
    # server-side nicknames/ids the mod resolves itself.
    consumerId: str = Field(min_length=1, max_length=128)
    generation: ID
    target: str = Field(min_length=1, max_length=128)
    text: str | None = None
    player: str | None = None
    classId: str | None = None
    op: str | None = None
    roomId: str | None = None
    outcome: str | None = None
    reason: str = Field(default="", max_length=500)
    expiresInSeconds: int = Field(default=30, ge=1, le=60)
    # Service-asserted acting account (site principal only). Direct callers
    # are authenticated and must never send it.
    actorAccountId: ID | None = None


class WorkshopAction(Mutation):
    consumerId: str = Field(min_length=1, max_length=128)
    generation: ID
    target: str = Field(default="*", min_length=1, max_length=128)
    actor: dict | None = None
    members: list | None = None
    message: str | None = None
    release: str | None = None
    record: dict | None = None
    expiresInSeconds: int = Field(default=30, ge=1, le=60)


class Ack(Strict):
    epoch: ID
    sequence: int = Field(ge=1)
    generation: ID
    revision: int | None = Field(default=None, ge=1)
    payloadHash: str = Field(pattern="^[0-9a-f]{64}$")
    state: Literal[
        "received", "validated", "applied", "effective", "rejected", "unknown"
    ]
    actualAt: str
    result: Literal[
        "ok", "invalid_schema", "stale_generation", "apply_failed", "effect_uncertain"
    ] = "ok"

    @field_validator("actualAt")
    @classmethod
    def timestamp(cls, value):
        from datetime import datetime

        result = datetime.fromisoformat(value)
        if result.tzinfo is None:
            raise ValueError("timezone required")
        return value


class Challenge(Strict):
    method: Literal["POST", "PATCH", "DELETE"]
    path: str = Field(min_length=1, max_length=256)
    body: dict


class Delegation(Mutation):
    scopes: list[str] = Field(min_length=1, max_length=20)
    resource: str = Field(min_length=1, max_length=128)
    expiresInSeconds: int = Field(default=300, ge=1, le=900)


class OperationReceipt(Strict):
    operationId: ID
    revision: int | None
    status: Literal[
        "accepted",
        "received",
        "validated",
        "applied",
        "effective",
        "rejected",
        "expired",
        "unknown",
        "partial",
    ]
    result: dict


class SettingsView(Strict):
    initialized: bool
    revision: int
    value: dict
    hash: str
    application: str


class AckReceipt(Strict):
    state: Literal[
        "received", "validated", "applied", "effective", "rejected", "unknown"
    ]
    sequence: int
