"""Trust-boundary regressions: U1 had no central authority or strict v2 model."""

import pytest
from pydantic import ValidationError

from cpv2.models import (
    Action,
    GrantChange,
    ModerationAction,
    Rollback,
    SettingsChange,
)
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


def test_grant_change_accepts_service_actor_but_rejects_bare_actor():
    from uuid import uuid4

    base = {
        "idempotencyKey": "t",
        "accountId": uuid4(),
        "expectedRevision": 1,
        "role": "builder",
        "resource": "*",
    }
    assert GrantChange(**base).actorAccountId is None
    assert GrantChange(**{**base, "actorAccountId": uuid4()}).actorAccountId is not None
    with pytest.raises(ValidationError):
        GrantChange(**{**base, "actor": "owner"})


def test_action_models_accept_service_actor_but_reject_bare_actor():
    from uuid import uuid4

    kick = {
        "idempotencyKey": "t",
        "consumerId": "site",
        "generation": uuid4(),
        "target": "arena",
        "playerId": uuid4(),
    }
    say = {
        "idempotencyKey": "t",
        "consumerId": "site",
        "generation": uuid4(),
        "target": "arena",
        "text": "Hello players",
    }
    assert Action(**kick).actorAccountId is None
    assert Action(**{**kick, "actorAccountId": uuid4()}).actorAccountId is not None
    assert ModerationAction(**say).actorAccountId is None
    assert (
        ModerationAction(**{**say, "actorAccountId": uuid4()}).actorAccountId
        is not None
    )
    with pytest.raises(ValidationError):
        Action(**{**kick, "actor": "owner"})


def test_settings_changes_accept_service_actor_but_reject_bare_actor():
    from uuid import uuid4

    patch = {"idempotencyKey": "t", "expectedRevision": 0, "patch": {}}
    assert SettingsChange(**patch).actorAccountId is None
    assert (
        SettingsChange(**{**patch, "actorAccountId": uuid4()}).actorAccountId
        is not None
    )
    with pytest.raises(ValidationError):
        SettingsChange(**{**patch, "actor": "owner"})
    rollback = {"idempotencyKey": "t", "expectedRevision": 0, "revision": 1}
    assert Rollback(**rollback).actorAccountId is None
    assert (
        Rollback(**{**rollback, "actorAccountId": uuid4()}).actorAccountId is not None
    )
    with pytest.raises(ValidationError):
        Rollback(**{**rollback, "actor": "owner"})


def test_complete_object_and_nested_diff():
    value = Gameplay().model_dump()
    updated = merge(value, {"match": {"maxPlayers": 64}})
    assert list(changed(value, updated)) == ["match.maxPlayers"]
    with pytest.raises(ValidationError):
        Gameplay.model_validate(merge(value, {"match": {"maxPlayers": 999}}))
    with pytest.raises(ValidationError):
        Gameplay.model_validate(merge(value, {"lobby": {"owner": True}}))


def test_legacy_gameplay_ai_drops_instead_of_failing():
    # coordination#56 removed gameplay.ai: pre-removal rows still store it,
    # so unrelated writes on legacy values must validate with ai dropped.
    legacy = {**Gameplay().model_dump(), "ai": {"budget": 10, "hardLimit": 20}}
    updated = Gameplay.model_validate(merge(legacy, {"match": {"maxPlayers": 16}}))
    assert updated.match.maxPlayers == 16
    assert "ai" not in updated.model_dump()


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


def test_ids_reject_trailing_newline_and_provider_extra_keys():
    limits = AiLimits().model_dump(mode="json")
    with pytest.raises(ValidationError):
        AiLimits.model_validate(merge(limits, {"sessions": {UUID + "\n": 1}}))
    workshop = WorkshopAi().model_dump(mode="json")
    entry = {"id": "my-llm", "label": "Mine", "baseUrl": "https://llm.example.com/v1"}
    WorkshopAi.model_validate(merge(workshop, {"providers": [entry]}))
    with pytest.raises(ValidationError):
        WorkshopAi.model_validate(
            merge(workshop, {"providers": [{**entry, "apiKey": "x"}]})
        )


def test_merge_patch_null_deletes_recursively():
    current = {
        "kits": {"alpha": {"name": "a"}, "beta": {"name": "b"}},
        "fixedModeKits": {"campaign": "alpha", "tdm": None},
    }
    assert merge(current, {"kits": {"beta": None}}) == {
        "kits": {"alpha": {"name": "a"}},
        "fixedModeKits": {"campaign": "alpha", "tdm": None},
    }
    # Nested delete, untouched siblings, missing-key no-op, arrays wholesale.
    assert merge({"a": {"b": 1, "c": 2}}, {"a": {"b": None}}) == {"a": {"c": 2}}
    assert merge({"a": 1}, {"missing": None}) == {"a": 1}
    assert merge({"a": [1, 2]}, {"a": [3]}) == {"a": [3]}
    # Whole-dict reset empties the namespace field for fresh defaults.
    assert merge({"campaignBalance": {"c1": {"a": 1}}}, {"campaignBalance": None}) == {}
    # Null stays a value only under fixedModeKits ("kit id or null").
    assert merge(
        {"fixedModeKits": {"campaign": "alpha"}},
        {"fixedModeKits": {"campaign": None}},
    ) == {"fixedModeKits": {"campaign": None}}
    # A missing or non-object target recurses from {}: nested nulls never persist.
    assert merge(
        {"campaignBalance": {}}, {"campaignBalance": {"c1": {"score_per_kill": None}}}
    ) == {"campaignBalance": {"c1": {}}}
    assert merge({"a": 1}, {"a": {"b": None, "c": 2}}) == {"a": {"c": 2}}
    assert merge({}, {"fixedModeKits": {"tdm": None}}) == {
        "fixedModeKits": {"tdm": None}
    }


def test_merge_delete_validates_like_any_change():
    full = Gameplay().model_dump(mode="json")
    # Deleting match.maxPlayers resets to the 32 default.
    assert (
        Gameplay.model_validate(
            merge(full, {"match": {"maxPlayers": None}})
        ).match.maxPlayers
        == 32
    )
    # Merged output validates like any change: unknown AI accounts rejected.
    with pytest.raises(ValidationError):
        AiLimits.model_validate(
            merge(AiLimits().model_dump(mode="json"), {"sessions": {"nope": 5}})
        )
    # Nullable scalars reset to their None default when deleted.
    rooms = merge(Rooms().model_dump(mode="json"), {"maxRooms": 4})
    assert Rooms.model_validate(merge(rooms, {"maxRooms": None})).maxRooms is None


def test_campaign_pair_checks_use_mod_defaults_for_missing_half():  # The mod fills a missing half from CampaignConfig defaults (warn 100, kill 80, team 1..16).
    for values in (
        {"base_kill_radius": 150},
        {"base_warn_radius": 50},
        {"min_players_per_team": 20},
        {"max_players_per_team": 1, "min_players_per_team": 2},
    ):
        with pytest.raises(ValidationError):
            Campaign.model_validate({"campaignBalance": {"c1": values}})
    with pytest.raises(ValidationError):
        Campaign.model_validate(
            {
                "campaignBalance": {
                    "*": {"base_warn_radius": 200},
                    "c1": {"base_kill_radius": 300},
                }
            }
        )
    Campaign.model_validate({"campaignBalance": {"c1": {"base_kill_radius": 90}}})
    Campaign.model_validate(
        {
            "campaignBalance": {
                "*": {"base_warn_radius": 200},
                "c1": {"base_kill_radius": 150},
            }
        }
    )


def _streak_doc(rewards):
    return {"minPlayers": 2, "streakRewards": rewards}


def _streak_entry(kills, item_id, count=1, scale=True):
    return {"kills": kills, "id": item_id, "count": count, "scale": scale}


def test_deathmatch_streak_rewards_mirror_server():
    # Default-shaped table (blockfield-server KillStreakRewards.defaults) validates,
    # and so does an empty table (disables rewards) and entries with server defaults.
    Deathmatch.model_validate(
        _streak_doc(
            [
                {
                    "kills": 2,
                    "id": "superbwarfare:medical_kit",
                    "count": 1,
                    "scale": True,
                    "message": "${name} — ${streak} подряд!",
                },
                {"kills": 3, "id": "superbwarfare:armor_plate", "scale": True},
                {
                    "kills": 5,
                    "id": "lrtactical:throwable",
                    "count": 1,
                    "scale": False,
                    "throwable_id": "lrtactical:m67",
                },
            ]
        )
    )
    assert Deathmatch.model_validate({"streakRewards": []}).streakRewards == []
    assert Deathmatch().streakRewards is None
    # Well-formed but registry-unknown ids pass CP: membership stays server-side.
    Deathmatch.model_validate(
        _streak_doc([{"kills": 2, "id": "nope:missing", "scale": True}])
    )
    bad_tables = [
        "x",
        [42],
        [_streak_entry(0, "minecraft:stick")],
        [_streak_entry(2, "")],
        [_streak_entry(2, "not an id!!!")],
        [_streak_entry(2, "minecraft:stick", "0")],
        [{"kills": 2, "id": "minecraft:stick", "count": 1}],
        [{"kills": 2, "id": "minecraft:stick", "count": 1, "scale": "yes"}],
        [{"kills": 2, "id": "lrtactical:throwable", "count": 1, "scale": False}],
        [
            {
                "kills": 2,
                "id": "minecraft:stick",
                "count": 1,
                "scale": True,
                "throwable_id": "lrtactical:m67",
            }
        ],
        [
            {
                "kills": 2,
                "id": "minecraft:stick",
                "count": 1,
                "scale": True,
                "message": 5,
            }
        ],
        [_streak_entry(2, "minecraft:stick")]
        + [_streak_entry(True, "minecraft:stick")],
        [_streak_entry(2, "minecraft:stick")] * 65,
    ]
    for bad in bad_tables:
        with pytest.raises(ValidationError):
            Deathmatch.model_validate(_streak_doc(bad))


def test_settings_body_without_actor_keeps_the_pre_actor_fingerprint():
    # A retry of an operation accepted before actorAccountId existed must hash
    # to the stored request: absent actor == old body, byte for byte.
    from uuid import uuid4

    from cpv2.models import request_body as settings_request_body

    base = {"idempotencyKey": "k1", "expectedRevision": 3, "patch": {"mode": "public"}}
    old_shape = {
        "idempotencyKey": "k1",
        "environment": "prod",
        "backend": "game",
        "expectedRevision": 3,
        "patch": {"mode": "public"},
    }
    assert settings_request_body(SettingsChange(**base)) == old_shape
    assert "actorAccountId" not in settings_request_body(
        Rollback(idempotencyKey="k2", expectedRevision=3, revision=2)
    )
    actor = uuid4()
    body = settings_request_body(SettingsChange(**base, actorAccountId=actor))
    assert body["actorAccountId"] == str(actor)


def test_owner_challenge_and_write_hash_the_same_settings_body():
    # Review r4524148929: the step-up challenge body (normalized_action) and the
    # write body must match, or a protected owner write fails its assertion.
    from cpv2.auth import normalized_action
    from cpv2.models import request_body

    body = {"idempotencyKey": "k1", "expectedRevision": 3, "patch": {"mode": "public"}}
    challenged = normalized_action("PATCH", "/v2/settings/gate/*", body)
    assert challenged == request_body(SettingsChange(**body))
    assert "actorAccountId" not in challenged


def test_site_session_create_rejects_empty_or_oversized_token():
    from cpv2.models import SiteSessionCreate

    ok = SiteSessionCreate(sealedToken="ab12.cd34", playerUuid="player-1")
    assert ok.sealedToken == "ab12.cd34"
    with pytest.raises(ValidationError):
        SiteSessionCreate(sealedToken="", playerUuid="player-1")
    with pytest.raises(ValidationError):
        SiteSessionCreate(sealedToken="x" * 4097, playerUuid="player-1")
    with pytest.raises(ValidationError):
        SiteSessionCreate(sealedToken="tok", playerUuid="")


def test_public_per_ip_budget_keys_on_the_forwarded_client_not_the_proxy():
    from types import SimpleNamespace

    from cpv2.app import client_address

    def request(headers, peer="10.0.0.2"):
        return SimpleNamespace(headers=headers, client=SimpleNamespace(host=peer))

    public = {"x-cp-public": "1"}
    # Traefik appends the real peer; a client-supplied left entry is ignored.
    assert (
        client_address(
            request(public | {"x-forwarded-for": "1.1.1.1, 203.0.113.7"}), hops=1
        )
        == "203.0.113.7"
    )
    # Two trusted proxies: the client is the second entry from the right.
    assert (
        client_address(
            request(public | {"x-forwarded-for": "9.9.9.9, 203.0.113.7, 172.16.0.1"}),
            hops=2,
        )
        == "203.0.113.7"
    )
    # Missing, short or malformed chains keep the socket peer.
    assert client_address(request(public), hops=1) == "10.0.0.2"
    assert (
        client_address(request(public | {"x-forwarded-for": "203.0.113.7"}), hops=2)
        == "10.0.0.2"
    )
    assert (
        client_address(request(public | {"x-forwarded-for": "not-an-ip"}), hops=1)
        == "10.0.0.2"
    )
    # Internal requests never trust the header.
    assert (
        client_address(request({"x-forwarded-for": "203.0.113.7"}), hops=1)
        == "10.0.0.2"
    )
