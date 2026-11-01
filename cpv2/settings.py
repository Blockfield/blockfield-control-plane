import copy
import hashlib
import json
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field, model_validator


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
            elif isinstance(value, int):
                if not -(2**63) <= value <= 2**63 - 1:
                    raise ValueError("integer outside bigint range")
            elif isinstance(value, dict):
                for item in value.values():
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


def merge(current, patch):
    result = copy.deepcopy(current)
    for key, value in patch.items():
        result[key] = (
            merge(result.get(key, {}), value)
            if isinstance(value, dict) and isinstance(result.get(key), dict)
            else value
        )
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
