import base64
import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from psycopg.types.json import Jsonb
from webauthn import verify_authentication_response
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.exceptions import WebAuthnException

from cpv2.db import one, record, rows
from cpv2.settings import digest

AUDIENCE = "blockfield-control-v2"
WORKSHOP_WRITE_SCOPES = {
    "workshop.message",
    "workshop.wake",
    "workshop.cancel",
    "workshop.map",
    "workshop.sessions",
}
WORKSHOP_ADMIN_SCOPES = {"workshop.members", "workshop.release.select", "workshop.mode"}
# Site RCON replacements every moderator may issue (mirrors site `moderate`).
MODERATION_SCOPES = {
    "moderation.say",
    "moderation.list",
    "moderation.team-kick",
    "moderation.class-lock",
    "moderation.class-unlock",
    "moderation.range",
    "moderation.stop-room",
}
# Pardon needs the site `ban` permission: admin only, like moderation.ban.
MODERATION_ADMIN_SCOPES = {"moderation.pardon"}
# Site moderation via the service principal: a service credential may hold
# any moderation kind, but every call must assert the acting human account
# (see core.action, mirroring grant_change) — the actor's own grants then
# decide, so a moderator actor can never reach admin-only kinds.
SERVICE_MODERATION_SCOPES = {
    "moderation.kick",
    "moderation.ban",
    *MODERATION_SCOPES,
    *MODERATION_ADMIN_SCOPES,
}
ROLE_SCOPES = {
    "builder": {
        "settings.read",
        "operations.read",
        "maps.edit",
        # Sessions queries mirror the site `view` permission: every staff
        # member may page saved drafts, like waking the workshop.
        "workshop.sessions",
    },
    "moderator": {
        "settings.read",
        "operations.read",
        "maps.edit",
        "moderation.kick",
        *MODERATION_SCOPES,
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
        # Stats reads mirror the site leaderboard/player/hit-reg contracts;
        # voids replay MMR like the site admin void. Admins and owners hold
        # both directly; services hold reads only (see STATS_READ_SCOPES).
        "stats.read",
        "stats.void",
        *MODERATION_SCOPES,
        *MODERATION_ADMIN_SCOPES,
        *WORKSHOP_WRITE_SCOPES,
        *WORKSHOP_ADMIN_SCOPES,
        # The workshop controller reports its own gate leg (gate settings at
        # target "workshop"); admins keep manual PATCH access to the same leg.
        "workshop.gate",
    },
}
OWNER_SCOPES = set().union(*ROLE_SCOPES.values()) | {
    "staff.admin.manage",
    "accounts.test.manage",
    "settings.protected.write",
    "audit.full",
    # Workshop AI keys mirror the site `ai` permission: founders only. In no
    # role, so no admin, moderator or service credential can ever hold it.
    "workshop.ai-key",
    # Site player sessions: the site stores sealed Drasl tokens in CP and can
    # revoke them; founders keep revocation when the site is unavailable.
    "site.sessions",
}
SERVICE_SCOPES = {
    "agents.events",
    "agents.acks",
    "gate:read",
    "workshop.act",
    # Service-holdable so the workshop controller can report its own gate leg.
    "workshop.gate",
    # Service-holdable per-kind workshop scopes: a service may post these
    # kinds only when also provisioned for the kind (workshop.act alone never
    # authorizes a kind). The admin-only kinds (members, release.select) stay
    # out, so no service credential can ever mint them.
    *WORKSHOP_WRITE_SCOPES,
    # Site moderation kinds: every service call asserts the acting account,
    # so the actor's own grants still decide (see core.action).
    *SERVICE_MODERATION_SCOPES,
}
# Site principal only: provisioned solely on a resource="*" service credential,
# since a staff write asserts an acting account (see core.grant_change).
STAFF_SCOPES = {"staff.read", "staff.lower.manage", "staff.admin.manage"}
# Site settings principal only: the site asserts the acting admin for every
# settings write (see core.settings_change), so the actor's own grants decide
# while the token itself stays unbound (see admin.provision). Reads ride the
# same token without an actor since they need no attribution.
SITE_SETTINGS_SCOPES = {"settings.read", "settings.gameplay.write"}
# Site player sessions (coordination#29): sealed Drasl tokens live in CP, the
# site is a stateless client. Service-only like staff scopes: provisioned
# solely on a resource="*" credential, never in a human role, so no scoped
# consumer can mint sessions for another resource.
SITE_SESSIONS_SCOPES = {"site.sessions"}
# Game-producer stats ingest (coordination#29 U1): match/campaign results go
# to the CP stats schema instead of the site DB. Service-only, never in a
# human role or owner scope. Unlike the site scopes above the credential stays
# bound to its server resource (provision refuses "*"), so one server can
# never submit another server's results; the runtime requires the scope on
# the body's serverId (see core.stat_ingest).
STATS_SCOPES = {"stats.ingest"}
# Stats reads (coordination#29 U3): leaderboard, player, hit-reg and seasons
# with the site's filter/sort/rank contracts. Service-holdable on an unbound
# (resource "*") credential only — the site SSR, launcher and bot read with
# it — never in a human role; admins and owners hold it via their role (see
# ROLE_SCOPES). The public-exposure unit adds domain/rate-limit policy later.
STATS_READ_SCOPES = {"stats.read"}


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
            if self.account is None:
                return (
                    scope
                    in SERVICE_SCOPES
                    | STAFF_SCOPES
                    | SITE_SETTINGS_SCOPES
                    | SITE_SESSIONS_SCOPES
                    | STATS_SCOPES
                    | STATS_READ_SCOPES
                )
            # Service-asserted actor (staff/settings writes via the site
            # principal): the service must be provisioned for the scope, and
            # the asserted actor must hold it exactly like a direct caller.
            if (
                scope
                not in SERVICE_SCOPES
                | STAFF_SCOPES
                | SITE_SETTINGS_SCOPES
                | SITE_SESSIONS_SCOPES
                | STATS_SCOPES
                | STATS_READ_SCOPES
            ):
                return False
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
    if operation:
        operation_scope = await one(
            conn,
            "SELECT environment,backend,resource FROM operations WHERE id=%s FOR KEY SHARE",
            (operation,),
        )
        scope = tuple(
            operation_scope[key] for key in ("environment", "backend", "resource")
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
        return models.request_body(model.model_validate(body))
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


SERVICE_TTL_CAP = 30 * 86400
# The outgoing credential stays valid this long after renew unless confirmed
# sooner; a consumer that lost the response retries with it inside the window.
RENEW_GRACE = timedelta(hours=1)


def renewed_token(old_token, nonce):
    # Re-derivable from the presented old token, so a retry after a lost
    # response returns the same successor while the DB stores only a nonce.
    digest_ = hashlib.sha256(b"cp-renew\0" + nonce + old_token.encode()).digest()
    return "cp2_" + base64.urlsafe_b64encode(digest_).rstrip(b"=").decode()


def _renewal_view(token, new):
    return {
        "token": token,
        "credentialId": str(new["id"]),
        "issuedAt": new["created_at"].isoformat(),
        "expiresAt": new["expires_at"].isoformat(),
    }


async def renew_credential(conn, identity, attempt, token):
    c = identity.credential
    if c["kind"] != "service":
        raise Problem("renew_service_only", 403)
    pending = await one(
        conn,
        "SELECT r.nonce, n.* FROM credential_renewals r JOIN credentials n ON n.id=r.new_id"
        " WHERE r.old_id=%s",
        (c["id"],),
    )
    if pending:
        if pending["revoked_at"] or pending["expires_at"] <= now():
            raise Problem("renewal_revoked", 409)
        # Retry after a lost response or a crash before persisting: same successor.
        await audit(
            conn, attempt, identity, "credentials.renew", str(pending["id"]), "replayed"
        )
        return _renewal_view(renewed_token(token, pending["nonce"]), pending)
    unconfirmed = await one(
        conn,
        "SELECT 1 FROM credential_renewals r JOIN credentials o ON o.id=r.old_id"
        " WHERE r.new_id=%s AND r.confirmed_at IS NULL AND o.revoked_at IS NULL AND o.expires_at>now()",
        (c["id"],),
    )
    if unconfirmed:
        raise Problem("renewal_unconfirmed", 409)
    consumer = await one(
        conn,
        "SELECT * FROM consumers WHERE credential_id=%s OR previous_credential_id=%s FOR UPDATE",
        (c["id"], c["id"]),
    )
    if consumer:
        if consumer["credential_id"] != c["id"]:
            raise Problem("credential_superseded", 409)
        if consumer["previous_credential_id"] is not None:
            prev = await one(
                conn,
                "SELECT revoked_at, expires_at FROM credentials WHERE id=%s",
                (consumer["previous_credential_id"],),
            )
            if prev and prev["revoked_at"] is None and prev["expires_at"] > now():
                raise Problem("previous_credential_live", 409)
    lifetime = min(
        c["expires_at"] - c["created_at"], timedelta(seconds=SERVICE_TTL_CAP)
    )
    nonce, new_id = secrets.token_bytes(32), uuid4()
    new_token = renewed_token(token, nonce)
    new = await one(
        conn,
        "INSERT INTO credentials(id,verifier,client_id,ceiling,environment,backend,resource,kind,audience,expires_at)"
        " VALUES(%s,%s,%s,%s,%s,%s,%s,'service',%s,now()+%s) RETURNING *",
        (
            new_id,
            verifier(new_token),
            c["client_id"],
            c["ceiling"],
            c["environment"],
            c["backend"],
            c["resource"],
            c["audience"],
            lifetime,
        ),
    )
    # A concurrent renew of the same credential conflicts on old_id (or
    # deadlocks on the row lock) and fails; the retry takes the replay path.
    await conn.execute(
        "INSERT INTO credential_renewals(old_id,new_id,nonce) VALUES(%s,%s,%s)",
        (c["id"], new_id, nonce),
    )
    await conn.execute(
        "UPDATE credentials SET expires_at=least(expires_at, now()+%s) WHERE id=%s",
        (RENEW_GRACE, c["id"]),
    )
    if consumer:
        await conn.execute(
            "UPDATE consumers SET previous_credential_id=credential_id,credential_id=%s WHERE id=%s",
            (new_id, consumer["id"]),
        )
    await audit(
        conn,
        attempt,
        identity,
        "credentials.renew",
        str(new_id),
        "accepted",
        {"from": str(c["id"]), "consumer": consumer["id"] if consumer else None},
    )
    return _renewal_view(new_token, new)


async def confirm_renewal(conn, identity, attempt):
    c = identity.credential
    r = await one(
        conn,
        "SELECT * FROM credential_renewals WHERE new_id=%s FOR UPDATE",
        (c["id"],),
    )
    if not r:
        raise Problem("renewal_not_found", 404)
    if r["confirmed_at"] is None:
        await conn.execute(
            "UPDATE credentials SET revoked_at=now() WHERE id=%s AND revoked_at IS NULL",
            (r["old_id"],),
        )
        await conn.execute(
            "UPDATE credential_renewals SET confirmed_at=now() WHERE old_id=%s",
            (r["old_id"],),
        )
        await audit(
            conn,
            attempt,
            identity,
            "credentials.renew.confirm",
            str(r["old_id"]),
            "accepted",
        )
        await conn.execute("SELECT pg_notify('cp_events','')")
    return {"confirmed": True, "revoked": str(r["old_id"])}
