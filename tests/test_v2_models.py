"""Trust-boundary regressions: U1 had no central authority or strict v2 model."""

import pytest
from pydantic import ValidationError

from cpv2.models import GrantChange, SettingsChange
from cpv2.settings import (
    DEFINITIONS,
    AiLimits,
    Campaign,
    ClassLocks,
    Deathmatch,
    DisabledMapIds,
    Gameplay,
    GunBalance,
    Kits,
    Parcool,
    Rooms,
    WorkshopAi,
    changed,
    merge,
)


def test_owner_is_never_an_ordinary_grant():
    from uuid import uuid4

    for role in ("owner", "OWNER", "superadmin", "admin,owner"):
        with pytest.raises(ValidationError):
            GrantChange(
                idempotencyKey="test",
                accountId=uuid4(),
                expectedRevision=1,
                role=role,
                resource="*",
            )


def test_no_forged_authority_or_numeric_cas_coercion():
    valid = {"idempotencyKey": "x", "expectedRevision": 0, "patch": {}}
    for value in (True, False, 0.0, "0"):
        with pytest.raises(ValidationError):
            SettingsChange(**dict(valid, expectedRevision=value))
    for key in ("actor", "role", "via", "owner", "client", "scopes"):
        with pytest.raises(ValidationError):
            SettingsChange(**dict(valid, **{key: "owner"}))


def test_complete_object_and_nested_diff():
    value = Gameplay().model_dump()
    updated = merge(value, {"ai": {"hardLimit": 200}})
    assert list(changed(value, updated)) == ["ai.hardLimit"]
    with pytest.raises(ValidationError):
        Gameplay.model_validate(merge(value, {"ai": {"budget": 101}}))
    with pytest.raises(ValidationError):
        Gameplay.model_validate(merge(value, {"lobby": {"owner": True}}))


def test_c5_rate_limiter_evicts_lru_instead_of_locking_out_new_keys():
    from cpv2.app import Limits
    from cpv2.auth import Problem

    limiter = Limits()
    for i in range(4096):
        limiter.check(f"key-{i}", global_count=False)
    # A 4097th distinct key must evict the least-recently-used entry, not 429.
    limiter.check("legit-new-session", global_count=False)
    assert "key-0" not in limiter.buckets and len(limiter.buckets) == 4096
    # Per-key limits still bind once a key is established.
    for _ in range(119):
        limiter.check("legit-new-session", global_count=False)
    with pytest.raises(Problem):
        limiter.check("legit-new-session", global_count=False)


def test_c8_shared_budget_ignores_uncounted_checks():
    from cpv2.app import Limits
    from cpv2.auth import Problem

    limiter = Limits()
    for i in range(1000):
        limiter.check(f"authed-{i}")
    limiter.check("health", global_count=False)
    with pytest.raises(Problem):
        limiter.check("one-more")


UUID = "12345678-1234-1234-1234-1234567890ab"
_VALID = {
    "rooms": (
        Rooms,
        {"maxRooms": 4, "idleCloseSeconds": 120, "abandonCloseSeconds": 45},
    ),
    "deathmatch": (Deathmatch, {"minPlayers": 2}),
    "classLocks": (
        ClassLocks,
        {"classLocks": ["tech"], "classCosts": {"tech": 600, "sniper": 800}},
    ),
    "campaign": (
        Campaign,
        {"campaignBalance": {"*": {"max_tickets": 100, "enable_spawn_shield": True}}},
    ),
    "parcool": (Parcool, {"allowedActions": ["FastRun", "Crawl"]}),
    "gunBalance": (
        GunBalance,
        {"overrides": {"tacz:modern_kinetic_gun": {"damage": 5}}},
    ),
    "kits": (
        Kits,
        {"kits": {"assault": {"name": "x"}}, "fixedModeKits": {"campaign": None}},
    ),
    "disabledMapIds": (DisabledMapIds, {"disabledMapIds": ["arena1"]}),
    "ai-limits": (
        AiLimits,
        {"mode": "builder", "sessions": {UUID: 1000}, "builders": {}},
    ),
    "workshop-ai": (WorkshopAi, {"enabled": True, "maxBlocks": 100}),
}
_INVALID = {
    "rooms": {"maxRooms": 0},
    "deathmatch": {"minPlayers": 25},
    "classLocks": {"classLocks": ["Tech!"]},
    "campaign": {"campaignBalance": {"*": {"max_tickets": 0}}},
    "parcool": {"allowedActions": ["Fly"]},
    "gunBalance": {"overrides": {"no-colon": {}}},
    "kits": {"fixedModeKits": {"nope": "assault"}},
    "disabledMapIds": {"disabledMapIds": ["Arena!"]},
    "ai-limits": {"sessions": {"not-a-uuid": 1}},
    "workshop-ai": {"maxBlocks": 0},
}


@pytest.mark.parametrize("namespace", sorted(_VALID))
def test_site_settings_namespaces_validate(namespace):
    model, values = _VALID[namespace]
    assert DEFINITIONS[namespace].model is model
    merged = merge(model().model_dump(mode="json"), values)
    model.model_validate(merged)
    with pytest.raises(ValidationError):
        model.model_validate(
            merge(model().model_dump(mode="json"), _INVALID[namespace])
        )
    with pytest.raises(ValidationError):
        model.model_validate(
            merge(model().model_dump(mode="json"), {"unknownField": True})
        )
