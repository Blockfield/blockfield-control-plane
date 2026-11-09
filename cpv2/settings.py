import copy
import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    @model_validator(mode="after")
    def representable(self):
        # The request hash, canonical JSON and PostgreSQL text/jsonb/bigint
        # columns cannot represent NUL, lone surrogates or out-of-range
        # integers: reject them as invalid requests before hashing/inserting.
        def check(value):
            if isinstance(value, str):
                if "\x00" in value:
                    raise ValueError("NUL byte not representable")
                try:
                    value.encode("utf-8")
                except UnicodeEncodeError:
                    raise ValueError("unpaired surrogate not representable") from None
            elif isinstance(value, bool):
                pass
            elif isinstance(value, float):
                if not math.isfinite(value):
                    raise ValueError("non-finite number not representable")
            elif isinstance(value, int):
                if not -(2**63) <= value <= 2**63 - 1:
                    raise ValueError("integer outside bigint range")
            elif isinstance(value, dict):
                for key, item in value.items():
                    check(key)
                    check(item)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    check(item)
            return value

        check(self.model_dump())
        return self


class Lobby(Strict):
    pvpEnabled: bool = False


class Match(Strict):
    maxPlayers: int = Field(default=32, ge=2, le=128)
    respawnSeconds: int = Field(default=5, ge=0, le=120)


class AI(Strict):
    budget: int = Field(default=0, ge=0, le=100000)
    hardLimit: int = Field(default=100, ge=0, le=100000)

    @model_validator(mode="after")
    def ceiling(self):
        if self.budget > self.hardLimit:
            raise ValueError("budget exceeds hardLimit")
        return self


class Gameplay(Strict):
    lobby: Lobby = Field(default_factory=Lobby)
    match: Match = Field(default_factory=Match)
    ai: AI = Field(default_factory=AI)


class Gate(Strict):
    mode: str = Field(default="maintenance", pattern="^(open|draining|maintenance)$")
    message: str = Field(default="", max_length=500)


class WorkshopGateMember(Strict):
    # Same identity rule the workshop controller enforces on its ACL
    # (core.WORKSHOP_NAME); stored normalized like the consumer member().
    draslId: str = Field(pattern="^[0-9a-f]{32}$")
    name: str = Field(pattern="^[A-Za-z0-9_]{3,16}$")

    @field_validator("draslId", mode="before")
    @classmethod
    def normalize_drasl(cls, value):
        if isinstance(value, str):
            return value.replace("-", "").lower()
        return value


class WorkshopGate(Strict):
    # Workshop leg of the proxy gate (gate settings at target "workshop"):
    # the controller states the file gate carried, plus its member ACL.
    # STARTING is the legacy phase-name spelling the old file accepted.
    state: str = Field(
        default="closed",
        pattern="^(builders|testers|closed|sleeping|starting)$",
    )
    message: str = Field(default="", max_length=500)
    allowed: list[WorkshopGateMember] = Field(default_factory=list, max_length=256)

    @field_validator("state", mode="before")
    @classmethod
    def normalize_state(cls, value):
        if value == "STARTING":
            return "starting"
        return value


# Site settings.json sections as v2 namespaces. Shapes and limits mirror the
# site writers (blockfield-site src/lib/admin.ts validateSettings and friends)
# and the server reader
# (blockfield-server mod-server/.../server/policy/AdminSettings.java), which is
# tolerant (clamps, keeps previous) where the site and CP reject. Nullable
# room/deathmatch fields mirror the reader: absent means no constraint.


class Rooms(Strict):
    maxRooms: int | None = Field(default=None, ge=1, le=16)
    idleCloseSeconds: int | None = Field(default=None, ge=30, le=3600)
    abandonCloseSeconds: int | None = Field(default=None, ge=5, le=600)


class Deathmatch(Strict):
    minPlayers: int | None = Field(default=None, ge=1, le=24)
    streakRewards: list | None = None

    @model_validator(mode="after")
    def streak_table(self):
        # Mirrors blockfield-server AdminSettings.streakTable (PR #346): the
        # table is atomic server-side, so CP rejects a bad table the same way
        # instead of forwarding it. Registry membership (minus air) stays
        # server-side; CP checks the id shape only.
        if self.streakRewards is None:
            return self
        if len(self.streakRewards) > 64:
            raise ValueError("deathmatch.streakRewards: at most 64 entries")
        for index, entry in enumerate(self.streakRewards):
            _streak_entry(entry, index)
        return self


_THROWABLE_ITEM = "lrtactical:throwable"
_STREAK_ITEM_ID = re.compile(r"^[a-z0-9_.-]+:[a-z0-9/._-]+$")
_MAX_JAVA_INT = 2**31 - 1


def _streak_entry(entry, index):
    path = f"deathmatch.streakRewards[{index}]"
    if not isinstance(entry, dict):
        raise ValueError(f"{path}: expected object")
    kills = entry.get("kills")
    if (
        isinstance(kills, bool)
        or not isinstance(kills, int)
        or not 1 <= kills <= _MAX_JAVA_INT
    ):
        raise ValueError(f"{path}.kills: expected integer >= 1")
    item_id = entry.get("id")
    if not isinstance(item_id, str) or not _STREAK_ITEM_ID.fullmatch(item_id.strip()):
        raise ValueError(f"{path}.id: expected item id")
    count = entry.get("count", 1)
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or not 1 <= count <= _MAX_JAVA_INT
    ):
        raise ValueError(f"{path}.count: expected integer >= 1")
    if "scale" not in entry or not isinstance(entry["scale"], bool):
        raise ValueError(f"{path}.scale: expected boolean")
    throwable_id = entry.get("throwable_id")
    if item_id.strip() == _THROWABLE_ITEM:
        if not isinstance(throwable_id, str) or not throwable_id.strip():
            raise ValueError(f"{path}.throwable_id: required for throwable")
    elif throwable_id is not None:
        raise ValueError(f"{path}.throwable_id: only the throwable item takes one")
    message = entry.get("message", "")
    if not isinstance(message, str):
        raise ValueError(f"{path}.message: expected string")


_CLASS_ID = re.compile(r"^[a-z0-9_]{1,32}$")
_CLASS_COST_IDS = ("tech", "sniper", "drone")
# blockfield-server AdminSettings.DEFAULT_CLASS_COSTS.
_DEFAULT_CLASS_COSTS = {"tech": 600, "sniper": 800, "drone": 1200}


class ClassLocks(Strict):
    # Site validates the pattern only; "known class" needs the live registry.
    classLocks: list[str] = Field(default_factory=list)
    classCosts: dict[str, int] = Field(
        default_factory=lambda: dict(_DEFAULT_CLASS_COSTS)
    )

    @model_validator(mode="after")
    def locks_and_costs(self):
        if len(self.classLocks) > 64 or len(set(self.classLocks)) != len(
            self.classLocks
        ):
            raise ValueError("classLocks: at most 64 distinct ids")
        if any(not _CLASS_ID.fullmatch(entry) for entry in self.classLocks):
            raise ValueError("classLocks: invalid class id")
        if any(key not in _CLASS_COST_IDS for key in self.classCosts):
            raise ValueError("classCosts: known kit price only")
        if any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= 10000
            for value in self.classCosts.values()
        ):
            raise ValueError("classCosts: expected known kit price 0-10000")
        return self


# (kind, min, max); mirrors site BALANCE and the server BALANCE_KEYS spec.
_BALANCE_INT = {
    "max_tickets": (1, 100000),
    "ticket_bleed_multiplier": (0, 100),
    "ticket_bleed_timer_seconds": (1, 600),
    "death_ticket_cost": (0, 1000),
    "capture_speed_percent_per_tick": (1, 100),
    "uncapture_speed_percent_per_tick": (1, 100),
    "score_per_kill": (0, 10000),
    "score_per_capture": (0, 10000),
    "score_per_uncapture": (0, 10000),
    "preparation_time_seconds": (0, 600),
    "transition_time_seconds": (0, 600),
    "spawn_shield_duration_seconds": (0, 60),
    "safe_spawn_threshold": (0, 100),
    "max_players_per_team": (1, 64),
    "min_players_per_team": (1, 64),
    "base_spawn_time_seconds": (0, 300),
    "spawn_time_per_point_seconds": (0, 300),
    "ready_countdown_seconds": (0, 300),
    "reserve_seconds": (0, 3600),
    "ready_timeout_seconds": (10, 3600),
}
_BALANCE_DOUBLE = {
    "score_per_obj_sec": (0, 1000),
    "base_warn_radius": (0, 1000),
    "base_kill_radius": (0, 1000),
}
_BALANCE_BOOL = ("enable_spawn_shield", "shuffle_teams_between_rounds")
# The mod's CampaignConfig defaults: it fills a missing half of a pair with these.
_PAIR_DEFAULTS = {
    "min_players_per_team": 1,
    "max_players_per_team": 16,
    "base_warn_radius": 100.0,
    "base_kill_radius": 80.0,
}
_CAMPAIGN_ID = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


class Campaign(Strict):
    campaignBalance: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def balance(self):
        if len(self.campaignBalance) > 64:
            raise ValueError("campaignBalance: at most 64 campaigns")
        for campaign, values in self.campaignBalance.items():
            if campaign != "*" and not _CAMPAIGN_ID.fullmatch(campaign):
                raise ValueError(f"campaignBalance: invalid campaign {campaign!r}")
            if not isinstance(values, dict):
                raise ValueError(f"campaignBalance.{campaign}: expected object")
            for key, value in values.items():
                if key in _BALANCE_INT:
                    lo, hi = _BALANCE_INT[key]
                    if isinstance(value, bool) or not isinstance(value, int):
                        raise ValueError(
                            f"campaignBalance.{campaign}.{key}: expected int"
                        )
                    if not lo <= value <= hi:
                        raise ValueError(
                            f"campaignBalance.{campaign}.{key}: out of range"
                        )
                elif key in _BALANCE_DOUBLE:
                    lo, hi = _BALANCE_DOUBLE[key]
                    if (
                        isinstance(value, bool)
                        or not isinstance(value, (int, float))
                        or not math.isfinite(value)
                    ):
                        raise ValueError(
                            f"campaignBalance.{campaign}.{key}: expected number"
                        )
                    if not lo <= value <= hi:
                        raise ValueError(
                            f"campaignBalance.{campaign}.{key}: out of range"
                        )
                elif key in _BALANCE_BOOL:
                    if not isinstance(value, bool):
                        raise ValueError(
                            f"campaignBalance.{campaign}.{key}: expected bool"
                        )
                else:
                    raise ValueError(f"campaignBalance.{campaign}.{key}: unknown key")
            star = self.campaignBalance.get("*", {})
            merged = {
                **_PAIR_DEFAULTS,
                **(star if isinstance(star, dict) else {}),
                **values,
            }
            if merged["min_players_per_team"] > merged["max_players_per_team"]:
                raise ValueError(f"campaignBalance.{campaign}: min team above max team")
            if merged["base_kill_radius"] > merged["base_warn_radius"]:
                raise ValueError(
                    f"campaignBalance.{campaign}: kill radius above warn radius"
                )
        return self


# Site game-names.ts PARCOOL_ACTIONS (the mod's own order); the reader default
# for a missing section is the mod base file (PARCOOL_FILE_DEFAULT).
PARCOOL_ACTIONS = (
    "BreakfallReady",
    "CatLeap",
    "ChargeJump",
    "ClimbPoles",
    "ClimbUp",
    "ClingToCliff",
    "HideInBlock",
    "Crawl",
    "Dive",
    "Dodge",
    "FastRun",
    "FastSwim",
    "Flipping",
    "HangDown",
    "HorizontalWallRun",
    "JumpFromBar",
    "QuickTurn",
    "RideZipline",
    "Roll",
    "SkyDive",
    "Slide",
    "Tap",
    "Vault",
    "VerticalWallRun",
    "WallJump",
    "WallSlide",
    "StartSwimByCrawl",
)


class Parcool(Strict):
    allowedActions: list[str] = Field(
        default_factory=lambda: ["FastRun", "ClingToCliff", "Crawl"]
    )

    @model_validator(mode="after")
    def actions(self):
        if len(set(self.allowedActions)) != len(self.allowedActions):
            raise ValueError("parcool: duplicate actions")
        if any(action not in PARCOOL_ACTIONS for action in self.allowedActions):
            raise ValueError("parcool: unknown action")
        return self


_GUN_ID = re.compile(r"^[a-z0-9_.-]+:[a-z0-9/._-]+$")


def _bounded_json(value, depth=0):
    # The per-field catalog stays server-side; CP enforces the site's outer
    # bounds only (at most 256 guns, byte cap).
    if isinstance(value, dict):
        if depth > 16 or len(value) > 256:
            raise ValueError("gunBalance: too deep or too wide")
        for item in value.values():
            _bounded_json(item, depth + 1)
    elif isinstance(value, (list, tuple)):
        if len(value) > 256:
            raise ValueError("gunBalance: list too long")
        for item in value:
            _bounded_json(item, depth + 1)


class GunBalance(Strict):
    overrides: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def gun_overrides(self):
        if len(self.overrides) > 256:
            raise ValueError("gunBalance: at most 256 guns")
        for gun_id, override in self.overrides.items():
            if (
                not isinstance(gun_id, str)
                or len(gun_id) > 256
                or not _GUN_ID.fullmatch(gun_id)
            ):
                raise ValueError(f"gunBalance: invalid gun id {gun_id!r}")
            if not isinstance(override, dict):
                raise ValueError(f"gunBalance.{gun_id}: expected override object")
        _bounded_json(self.overrides)
        if len(canonical(self.overrides).encode()) > 240000:
            raise ValueError("gunBalance: revision too large")
        return self


# Site kit-schema.ts MODES; per-item validation stays server-side with the
# registry, CP enforces ids, modes and the 1M PUT body cap.
_KIT_MODES = ("campaign", "room", "tdm", "snipers", "awp", "deathmatch", "training")


class Kits(Strict):
    kits: dict = Field(default_factory=dict)
    fixedModeKits: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def kit_changes(self):
        for kit_id, kit in self.kits.items():
            if not isinstance(kit_id, str) or not _CLASS_ID.fullmatch(kit_id):
                raise ValueError(f"kits: invalid kit id {kit_id!r}")
            if not isinstance(kit, dict):
                raise ValueError(f"kits.{kit_id}: expected object")
        for mode, target in self.fixedModeKits.items():
            if mode not in _KIT_MODES:
                raise ValueError(f"fixedModeKits: invalid mode {mode!r}")
            if target is not None and (
                not isinstance(target, str) or not _CLASS_ID.fullmatch(target)
            ):
                raise ValueError(f"fixedModeKits.{mode}: expected kit id or null")
        size = len(
            canonical({"kits": self.kits, "fixedModeKits": self.fixedModeKits}).encode()
        )
        if size > 1048576:
            raise ValueError("kits: revision too large")
        return self


_MAP_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,127}$")


class DisabledMapIds(Strict):
    disabledMapIds: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def maps(self):
        if len(self.disabledMapIds) > 4096:
            raise ValueError("disabledMapIds: at most 4096 ids")
        if len(set(self.disabledMapIds)) != len(self.disabledMapIds):
            raise ValueError("disabledMapIds: expected distinct ids")
        if any(not _MAP_ID.fullmatch(entry) for entry in self.disabledMapIds):
            raise ValueError("disabledMapIds: invalid map id")
        return self


_BUDGET_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_MAX_AI_BUDGET_MICROS = 1000000000000


class AiLimits(Strict):
    # Mirrors site ai-limits.json; every field is money, so all are protected.
    currency: Literal["USD"] = "USD"
    mode: Literal["session", "builder"] = "session"
    sessions: dict[str, int] = Field(default_factory=dict)
    builders: dict[str, int] = Field(default_factory=dict)

    @model_validator(mode="after")
    def budgets(self):
        for scope in (self.sessions, self.builders):
            if len(scope) > 256:
                raise ValueError("ai-limits: at most 256 accounts")
            for account, amount in scope.items():
                if not _BUDGET_UUID.fullmatch(account):
                    raise ValueError("ai-limits: expected UUID accounts")
                if (
                    isinstance(amount, bool)
                    or not isinstance(amount, int)
                    or not 0 <= amount <= _MAX_AI_BUDGET_MICROS
                ):
                    raise ValueError("ai-limits: expected micros 0-1000000000000")
        return self


_WORKSHOP_PROVIDERS = ("openrouter", "vercel-gateway")
_WORKSHOP_PROVIDER_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
_WORKSHOP_RESERVED_IDS = ("ai", "ai-gateway")
_WORKSHOP_MODEL = re.compile(r"^[a-zA-Z0-9._-]{1,64}/[a-zA-Z0-9._/:-]{1,126}$")
_WORKSHOP_NATIVE_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,99}$")


class WorkshopAi(Strict):
    # Nonsecret settings only: provider keys are write-only and never land in
    # settings, the DB, logs or responses (site workshop-ai-policy.ts).
    # Mirrors site WORKSHOP_AI_DEFAULTS and validateWorkshopAiSettings.
    enabled: bool = False
    provider: Literal["openrouter", "vercel-gateway"] = "openrouter"
    generationProvider: str = "openrouter"
    guardProvider: str = "openrouter"
    transcriptionProvider: str = "openrouter"
    providers: list = Field(default_factory=list)
    inputGuardEnabled: bool = False
    generationModel: str = "meta/muse-spark-1.3-contributor"
    guardModel: str = "typesafe/jev-1.13"
    transcriptionModel: str = "openai/whisper-1"
    cleanupModel: str = ""
    cleanupProvider: str = "openrouter"
    maxBlocks: int = Field(default=16384, ge=1, le=32768)
    blocksPerTick: int = Field(default=2048, ge=1, le=16384)
    minimumBuildTicks: int = Field(default=80, ge=40, le=1200)
    applyBudgetMs: int = Field(default=8, ge=1, le=20)
    hourlyRequestLimit: int = Field(default=360, ge=1, le=1000000)
    hourlyPlayerRequestLimit: int = Field(default=60, ge=1, le=1000000)
    maxHourlyBuilders: int = Field(default=4096, ge=1, le=4096)
    # Site accepts any JSON number here; strict ints stay valid under lax.
    generationMaxPricePromptUsdPerM: float = Field(default=0.1, strict=False)
    generationMaxPriceCompletionUsdPerM: float = Field(default=0.2, strict=False)

    @model_validator(mode="after")
    def workshop(self):
        custom = []
        if len(self.providers) > 8:
            raise ValueError("providers: at most 8 entries")
        seen = set()
        for entry in self.providers:
            if not isinstance(entry, dict) or set(entry) != {"id", "label", "baseUrl"}:
                raise ValueError("providers: expected id, label and https baseUrl")
            pid, label, base = entry.get("id"), entry.get("label"), entry.get("baseUrl")
            if (
                not isinstance(pid, str)
                or not _WORKSHOP_PROVIDER_ID.fullmatch(pid)
                or pid in _WORKSHOP_PROVIDERS
                or pid in _WORKSHOP_RESERVED_IDS
                or pid in seen
            ):
                raise ValueError("providers: unique custom id required")
            seen.add(pid)
            if not isinstance(label, str) or not label.strip() or len(label) > 80:
                raise ValueError("providers: label 1-80 chars")
            if not self._base_url(base):
                raise ValueError("providers: https baseUrl without params")
            custom.append(pid)
        known = list(_WORKSHOP_PROVIDERS) + custom
        for field in (
            self.generationProvider,
            self.guardProvider,
            self.transcriptionProvider,
        ):
            if field not in known:
                raise ValueError("workshop-ai: unknown provider reference")
        if self.cleanupProvider not in known:
            raise ValueError("workshop-ai: unknown cleanup provider")
        for field, provider in (
            (self.generationModel, self.generationProvider),
            (self.guardModel, self.guardProvider),
            (self.transcriptionModel, self.transcriptionProvider),
        ):
            if provider in custom:
                if not _WORKSHOP_MODEL.fullmatch(
                    field
                ) and not _WORKSHOP_NATIVE_MODEL.fullmatch(field):
                    raise ValueError("workshop-ai: invalid model")
            elif not _WORKSHOP_MODEL.fullmatch(field):
                raise ValueError("workshop-ai: expected vendor/model")
        if self.cleanupModel != "" and not _WORKSHOP_MODEL.fullmatch(self.cleanupModel):
            if (
                self.cleanupProvider not in custom
                or not _WORKSHOP_NATIVE_MODEL.fullmatch(self.cleanupModel)
            ):
                raise ValueError("workshop-ai: invalid cleanup model")
        for field in (
            self.generationMaxPricePromptUsdPerM,
            self.generationMaxPriceCompletionUsdPerM,
        ):
            if not isinstance(field, (int, float)) or not 0 <= field <= 1000:
                raise ValueError("workshop-ai: price ceiling 0-1000")
        return self

    @staticmethod
    def _base_url(value):
        # shortcut: https-only; revisit when cliproxy is connected.
        if not isinstance(value, str) or not 1 <= len(value) <= 200:
            return False
        try:
            from urllib.parse import urlsplit

            parts = urlsplit(value)
        except ValueError:
            return False
        return (
            parts.scheme == "https"
            and bool(parts.hostname)
            and not parts.username
            and not parts.password
            and not parts.query
            and not parts.fragment
        )


@dataclass(frozen=True)
class Definition:
    model: type[Strict]
    read: str
    write: str
    owner_paths: tuple[str, ...] = ()
    timing: str = "next_tick"
    sensitivity: str = "ordinary"


DEFINITIONS = {
    "gameplay": Definition(
        Gameplay, "settings.read", "settings.gameplay.write", ("ai.hardLimit",)
    ),
    "gate": Definition(Gate, "settings.read", "moderation.ban", timing="live"),
    # Site settings.json sections and policy files. Game settings share the
    # gameplay write scope (site `settings` permission); money and Workshop AI
    # are owner-only via protected paths (site `ai` permission).
    "rooms": Definition(Rooms, "settings.read", "settings.gameplay.write"),
    "deathmatch": Definition(Deathmatch, "settings.read", "settings.gameplay.write"),
    "classLocks": Definition(ClassLocks, "settings.read", "settings.gameplay.write"),
    "campaign": Definition(Campaign, "settings.read", "settings.gameplay.write"),
    "parcool": Definition(Parcool, "settings.read", "settings.gameplay.write"),
    "gunBalance": Definition(GunBalance, "settings.read", "settings.gameplay.write"),
    "kits": Definition(Kits, "settings.read", "settings.gameplay.write"),
    "disabledMapIds": Definition(
        DisabledMapIds, "settings.read", "settings.gameplay.write"
    ),
    "ai-limits": Definition(
        AiLimits,
        "settings.read",
        "settings.gameplay.write",
        ("mode", "sessions", "builders"),
    ),
    "workshop-ai": Definition(
        WorkshopAi,
        "settings.read",
        "settings.gameplay.write",
        (
            "enabled",
            "provider",
            "generationProvider",
            "guardProvider",
            "transcriptionProvider",
            "providers",
            "inputGuardEnabled",
            "generationModel",
            "guardModel",
            "transcriptionModel",
            "cleanupModel",
            "cleanupProvider",
            "maxBlocks",
            "blocksPerTick",
            "minimumBuildTicks",
            "applyBudgetMs",
            "hourlyRequestLimit",
            "hourlyPlayerRequestLimit",
            "maxHourlyBuilders",
            "generationMaxPricePromptUsdPerM",
            "generationMaxPriceCompletionUsdPerM",
        ),
    ),
}


def canonical(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


# Dict fields whose entries store null as a value instead of a delete marker.
# Kits.fixedModeKits.<mode> is "kit id or null": null clears the fixed kit
# but keeps the explicit entry. Everywhere else a patch null deletes the key
# (RFC 7396), then the merged result is validated as usual.
_NULL_VALUED_PARENTS = frozenset({"fixedModeKits"})


def merge(current, patch, _parent=None):
    # RFC 7396 JSON Merge Patch: null deletes the key (recursively), absent
    # keys are untouched, arrays are replaced wholesale.
    result = copy.deepcopy(current)
    for key, value in patch.items():
        if value is None and _parent not in _NULL_VALUED_PARENTS:
            result.pop(key, None)
        elif isinstance(value, dict):
            # RFC 7396: a missing or non-object target merges from {}.
            target = result.get(key)
            result[key] = merge(
                target if isinstance(target, dict) else {}, value, _parent=key
            )
        else:
            result[key] = value
    return result


def changed(before, after, prefix=""):
    result = {}
    for key in before.keys() | after.keys():
        path = f"{prefix}.{key}" if prefix else key
        old, new = before.get(key), after.get(key)
        if isinstance(old, dict) and isinstance(new, dict):
            result.update(changed(old, new, path))
        elif old != new:
            result[path] = {"before": old, "after": new}
    return result
