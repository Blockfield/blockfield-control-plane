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
    # Service-asserted acting account (site principal only). Direct callers
    # are authenticated and must never send it.
    actorAccountId: ID | None = None


class GateToggle(Mutation):
    # Single-call gate update: absolute desired state, no client-side read.
    # The server reads the head under lock (see core.gate_toggle), so the
    # site needs one POST instead of GET /v1/gate + PATCH.
    mode: str = Field(pattern="^(open|draining|maintenance)$")
    message: str = Field(default="", max_length=500)
    # Service-asserted acting account (site principal only). Direct callers
    # are authenticated and must never send it.
    actorAccountId: ID | None = None


class Rollback(Mutation):
    expectedRevision: int = Field(ge=0, le=9223372036854775807)
    revision: int = Field(ge=1, le=9223372036854775807)
    # Service-asserted acting account (site principal only). Direct callers
    # are authenticated and must never send it.
    actorAccountId: ID | None = None


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


class ConsoleRun(Mutation):
    # Owner console line for one game consumer (coordination#35). core.action
    # classifies it against the read-only allowlist: console.read covers the
    # allowlist, console.run anything else.
    # No target: a console line acts on the whole server, so it is always
    # authorized at resource "*" (core.action).
    consumerId: str = Field(min_length=1, max_length=128)
    generation: ID
    command: str = Field(min_length=1, max_length=1000)
    expiresInSeconds: int = Field(default=30, ge=1, le=60)
    # Service-asserted acting account (site principal only); the actor must be
    # an owner. Agent tokens provisioned for console scopes send none.
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
    # Remaining inbox kinds (map/sessions/ai-key/mode): kind-specific shapes
    # are validated in core.workshop_op, which rejects unknown combinations.
    mapOp: str | None = None
    mapId: str | None = None
    name: str | None = None
    supportedModes: list | None = None
    workingCopyId: str | None = None
    expectedRevision: int | None = None
    offset: int | None = None
    limit: int | None = None
    provider: str | None = None
    key: str | None = None
    profile: str | None = None
    recover: bool | None = None
    session: str | None = None
    maps: list | None = None
    branches: dict | None = None
    sessionId: str | None = None
    candidateId: str | None = None
    modeId: str | None = None
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
    # Command output (list, maintenance status, console lines). Informational:
    # stored with the receipt, excluded from its fingerprint, so the same
    # receipt resent without the text (the executor keeps none) still matches.
    # Requests are capped at 32 KiB; the game also keeps the encoded text under it.
    output: str | None = Field(default=None, max_length=16384)

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


class SiteSessionCreate(Strict):
    # Sealed Drasl token as stored by the site today (opaque to CP, AES-GCM
    # sealed hex.hex); CP never decrypts, only stores and returns it.
    sealedToken: str = Field(min_length=1, max_length=4096)
    playerUuid: str = Field(min_length=1, max_length=128)


class StatVoid(Strict):
    # Void/restore one ingested result (site setVoided contract): voiding a
    # rated campaign enqueues its season for the background rebuild loop.
    serverId: ID
    eventId: ID
    voided: bool


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


def request_body(model):
    """The normalized body a request is fingerprinted and challenged by.

    SettingsChange and Rollback gained actorAccountId later: when it is absent
    their body must stay byte-identical to the pre-actor shape, so a retry of an
    operation accepted before the upgrade still matches its stored hash. GateToggle
    gained it the same way. The owner step-up challenge (auth.normalized_action)
    and the write path (core.settings_change) both use this, so they always hash
    the same body. Other models already carried the field and keep their shape.
    """
    data = model.model_dump(mode="json")
    if (
        isinstance(model, (SettingsChange, Rollback, GateToggle))
        and data.get("actorAccountId") is None
    ):
        data.pop("actorAccountId", None)
    return data
