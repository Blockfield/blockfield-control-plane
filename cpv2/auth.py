import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID, uuid4

from psycopg.types.json import Jsonb
from webauthn import verify_authentication_response
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.exceptions import WebAuthnException

from cpv2.db import one, record, rows
from cpv2.settings import digest

AUDIENCE = "blockfield-control-v2"
WORKSHOP_WRITE_SCOPES = {"workshop.message", "workshop.wake", "workshop.cancel"}
WORKSHOP_ADMIN_SCOPES = {"workshop.members", "workshop.release.select"}
ROLE_SCOPES = {
    "builder": {"settings.read", "operations.read", "maps.edit"},
    "moderator": {
        "settings.read",
        "operations.read",
        "maps.edit",
        "moderation.kick",
        *WORKSHOP_WRITE_SCOPES,
    },
    "admin": {
        "settings.read",
        "operations.read",
        "maps.edit",
        "moderation.kick",
        "moderation.ban",
        "settings.gameplay.write",
        "staff.lower.manage",
        "audit.read",
        *WORKSHOP_WRITE_SCOPES,
        *WORKSHOP_ADMIN_SCOPES,
    },
}
OWNER_SCOPES = set().union(*ROLE_SCOPES.values()) | {
    "staff.admin.manage",
    "accounts.test.manage",
    "settings.protected.write",
    "audit.full",
}
SERVICE_SCOPES = {"agents.events", "agents.acks", "gate:read", "workshop.act"}


class Problem(Exception):
    def __init__(self, code, status=403):
        self.code, self.status = code, status


def now():
    return datetime.now(timezone.utc)


def verifier(token):
    return hashlib.sha256(token.encode()).hexdigest()


def covers(granted, wanted):
    return granted == "*" or granted == wanted


def bound(grant, environment, backend, resource):
    return all(
        covers(grant[key], value)
        for key, value in (
            ("environment", environment),
            ("backend", backend),
            ("resource", resource),
        )
    )


def is_owner_session(client, credential, membership):
    # Single owner-eligibility predicate for both the login path
    # (authenticate) and the queued-delivery path (valid_operation): owner
    # authority needs a human session on an interactive/recovery client.
    return bool(
        membership
        and credential["kind"] == "session"
        and not credential["parent_id"]
        and client["human"]
        and client["via"] in ("ui", "cli", "recovery")
    )


@dataclass
class Identity:
    credential: dict
    client: dict
    account: dict | None
    grants: list[dict]
    owner: bool

    @property
    def actor(self):
        return self.account["id"] if self.account else None

    def allows(self, scope, environment, backend, resource):
        c = self.credential
        if (
            scope not in c["ceiling"]
            or scope not in self.client["ceiling"]
            or not bound(c, environment, backend, resource)
        ):
            return False
        if c["kind"] == "service":
            return scope in SERVICE_SCOPES
        if self.owner:
            return scope in OWNER_SCOPES
        return any(
            bound(g, environment, backend, resource) and scope in ROLE_SCOPES[g["role"]]
            for g in self.grants
        )

    def require(self, scope, environment="prod", backend="game", resource="*"):
        if not self.allows(scope, environment, backend, resource):
            raise Problem("forbidden")


async def authenticate(conn, token, *, lock_credential=True):
    c = await one(
        conn,
        "SELECT * FROM credentials WHERE verifier=%s",
        (verifier(token),),
    )
    if (
        not c
        or c["revoked_at"]
        or c["expires_at"] <= now()
        or c["audience"] != AUDIENCE
    ):
        raise Problem("unauthorized", 401)
    # Account-before-credential matches security-change/invalidation lock order.
    account = None
    if c["account_id"]:
        account = await one(
            conn, "SELECT * FROM accounts WHERE id=%s FOR SHARE", (c["account_id"],)
        )
    # Parent-before-child matches session revocation and avoids lock inversion.
    if c["parent_id"]:
        parent = await one(
            conn, "SELECT * FROM credentials WHERE id=%s FOR SHARE", (c["parent_id"],)
        )
        if not parent or parent["revoked_at"] or parent["expires_at"] <= now():
            raise Problem("unauthorized", 401)
    if lock_credential:
        c = await one(
            conn, "SELECT * FROM credentials WHERE id=%s FOR SHARE", (c["id"],)
        )
        if c["revoked_at"] or c["expires_at"] <= now():
            raise Problem("unauthorized", 401)
    client = await one(conn, "SELECT * FROM clients WHERE id=%s", (c["client_id"],))
    if client["audience"] != AUDIENCE:
        raise Problem("unauthorized", 401)
    grants, owner = [], False
    if account:
        if (
            account["status"] != "active"
            or account["authorization_epoch"] != c["authorization_epoch"]
        ):
            raise Problem("authorization_expired", 401)
        if account["is_test"]:
            raise Problem("test_account_privileged_access_denied")
        grants = await rows(
            conn,
            "SELECT * FROM role_grants WHERE account_id=%s AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>%s)",
            (account["id"], now()),
        )
        membership = await one(
            conn,
            "SELECT 1 FROM owner_memberships WHERE account_id=%s",
            (account["id"],),
        )
        owner = is_owner_session(client, c, membership)
    return Identity(c, client, account, grants, owner)


async def audit(
    conn,
    attempt,
    identity,
    action,
    target,
    outcome,
    detail=None,
    operation=None,
    *,
    scope=None,
):
    if scope is None:
        scope = (
            tuple(
                identity.credential[key]
                for key in ("environment", "backend", "resource")
            )
            if identity
            else ("*", "*", "*")
        )
    # Lock foreign-key subjects before the commit-order history lock.
    if identity:
        if identity.actor:
            await conn.execute(
                "SELECT id FROM accounts WHERE id=%s FOR KEY SHARE", (identity.actor,)
            )
        await conn.execute(
            "SELECT id FROM credentials WHERE id=%s FOR KEY SHARE",
            (identity.credential["id"],),
        )
    if operation:
        operation_scope = await one(
            conn,
            "SELECT environment,backend,resource FROM operations WHERE id=%s FOR KEY SHARE",
            (operation,),
        )
        scope = tuple(
            operation_scope[key] for key in ("environment", "backend", "resource")
        )
    await record(
        conn,
        "INSERT INTO audit_events(attempt_id,operation_id,actor,credential_id,client_id,via,request_id,action,target,environment,backend,resource,outcome,detail) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        (
            attempt,
            operation,
            identity.actor if identity else None,
            identity.credential["id"] if identity else None,
            identity.client["id"] if identity else None,
            identity.client["via"] if identity else "unverified",
            attempt,
            action,
            target[:256],
            *scope,
            outcome,
            Jsonb(detail or {}),
        ),
    )


async def invalidate(conn, account):
    await conn.execute(
        "UPDATE accounts SET authorization_epoch=authorization_epoch+1 WHERE id=%s",
        (account,),
    )
    await conn.execute(
        "UPDATE credentials SET revoked_at=now() WHERE account_id=%s AND revoked_at IS NULL",
        (account,),
    )
    await conn.execute("SELECT pg_notify('cp_events', '')")


def action_hash(method, path, body):
    return digest({"audience": AUDIENCE, "method": method, "path": path, "body": body})


def normalized_action(method, path, body):
    from cpv2 import models

    if method == "PATCH" and path.startswith("/v2/settings/"):
        model = models.SettingsChange
    elif (
        method == "POST"
        and path.startswith("/v2/settings/")
        and path.endswith("/rollback")
    ):
        model = models.Rollback
    elif method == "POST" and path == "/v2/staff/grants":
        model = models.GrantChange
    elif (
        method == "POST"
        and path.startswith("/v2/accounts/")
        and path.endswith("/test-status")
    ):
        model = models.TestStatus
    elif method == "POST" and path.startswith("/v2/workshop/"):
        kind = path[len("/v2/workshop/") :]
        kinds = {
            scope.removeprefix("workshop.")
            for scope in WORKSHOP_WRITE_SCOPES | WORKSHOP_ADMIN_SCOPES
        }
        if kind not in kinds:
            raise Problem("invalid_owner_action", 422)
        model = models.WorkshopAction
    else:
        raise Problem("invalid_owner_action", 422)
    try:
        return model.model_validate(body).model_dump(mode="json")
    except ValueError:
        raise Problem("invalid_owner_action", 422) from None


async def challenge(conn, identity, method, path, body):
    if not identity.owner:
        raise Problem("owner_required")
    if not path.startswith("/v2/") or method not in ("POST", "PATCH", "DELETE"):
        raise Problem("invalid_action", 422)
    count = await one(
        conn,
        "SELECT count(*) AS n FROM owner_challenges WHERE credential_id=%s AND used_at IS NULL AND expires_at>now()",
        (identity.credential["id"],),
    )
    if count["n"] >= 8:
        raise Problem("too_many_challenges", 429)
    cid, nonce = uuid4(), secrets.token_bytes(32)
    await conn.execute(
        "INSERT INTO owner_challenges VALUES(%s,%s,%s,%s,%s,now()+interval '60 seconds',NULL)",
        (
            cid,
            identity.actor,
            identity.credential["id"],
            action_hash(method, path, normalized_action(method, path, body)),
            nonce,
        ),
    )
    credentials = await rows(
        conn,
        "SELECT id,rp_id FROM owner_credentials WHERE account_id=%s",
        (identity.actor,),
    )
    if not credentials:
        raise Problem("owner_approval_required")
    return {
        "challengeId": str(cid),
        "challenge": bytes_to_base64url(nonce),
        "rpId": credentials[0]["rp_id"],
        "allowCredentials": [
            {"id": c["id"], "type": "public-key"} for c in credentials
        ],
        "userVerification": "required",
        "timeout": 60000,
    }


async def step_up(conn, identity, assertion, method, path, body):
    if not identity.owner or not assertion:
        raise Problem("owner_approval_required")
    if (
        not isinstance(assertion, dict)
        or not isinstance(assertion.get("challengeId"), str)
        or not isinstance(assertion.get("credential"), dict)
        or not isinstance(assertion["credential"].get("id"), str)
    ):
        raise Problem("invalid_owner_assertion")
    try:
        cid = UUID(assertion["challengeId"])
        response = assertion["credential"]
        record = await one(
            conn, "SELECT * FROM owner_challenges WHERE id=%s FOR UPDATE", (cid,)
        )
        if (
            not record
            or record["used_at"]
            or record["expires_at"] <= now()
            or record["account_id"] != identity.actor
            or record["credential_id"] != identity.credential["id"]
            or record["action_hash"] != action_hash(method, path, body)
        ):
            raise Problem("invalid_owner_assertion")
        key = await one(
            conn,
            "SELECT * FROM owner_credentials WHERE id=%s AND account_id=%s",
            (response["id"], identity.actor),
        )
        if not key:
            raise Problem("invalid_owner_assertion")
        await conn.execute(
            "INSERT INTO owner_assertions VALUES(%s,%s) ON CONFLICT DO NOTHING",
            (key["id"], key["sign_count"]),
        )
        counter = await one(
            conn,
            "SELECT sign_count FROM owner_assertions WHERE credential_id=%s FOR UPDATE",
            (key["id"],),
        )
        verified = verify_authentication_response(
            credential=response,
            expected_challenge=record["challenge"],
            expected_rp_id=key["rp_id"],
            expected_origin=key["origin"],
            credential_public_key=key["public_key"],
            credential_current_sign_count=counter["sign_count"],
            require_user_verification=True,
        )
        await conn.execute(
            "UPDATE owner_assertions SET sign_count=%s WHERE credential_id=%s",
            (verified.new_sign_count, key["id"]),
        )
        await conn.execute(
            "UPDATE owner_challenges SET used_at=now() WHERE id=%s", (cid,)
        )
    except (KeyError, ValueError, TypeError, AttributeError, WebAuthnException):
        raise Problem("invalid_owner_assertion") from None
