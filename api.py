"""Central control-plane API (U1): entry gate + maintenance mode.

Python stdlib only: http.server + sqlite3. Owns the shared gate state
(open/draining/maintenance) that the proxy polls and site admins toggle.
Single writer, SQLite journal on a named volume (/data).

Token model (U1 seed, U2 extends): per-client bearer tokens, sha256
verifiers stored in SQLite, scopes gate:read/gate:write. First boot with
an empty DB derives the seed tokens from CP_BOOTSTRAP_ADMIN_SECRET; U2
adds rotation UI on top of the tokens table (expires_at/revoked_at and
last_used_at columns already exist).
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SCHEMA = 1
MODES = ("open", "draining", "maintenance")
READ_SCOPE = "gate:read"
WRITE_SCOPE = "gate:write"
MAX_BODY = 16 * 1024
MAX_MESSAGE = 500
ACTOR_ROLES = ("owner", "admin")  # owner AND site admins may toggle (2026-10-30)

DDL = """
CREATE TABLE IF NOT EXISTS tokens(
  id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
  verifier_hash TEXT NOT NULL, scopes TEXT NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER,
  revoked_at INTEGER, last_used_at INTEGER);
CREATE TABLE IF NOT EXISTS gate_state(
  revision INTEGER NOT NULL, mode TEXT NOT NULL,
  message TEXT NOT NULL, since INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS gate_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL UNIQUE,
  idempotency_key TEXT NOT NULL, revision INTEGER NOT NULL,
  mode TEXT NOT NULL, message TEXT NOT NULL,
  actor_id TEXT NOT NULL, actor_role TEXT NOT NULL, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL,
  actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL);
"""


def now_ms():
    return int(time.time() * 1000)


def derive_token(secret, name):
    raw = hashlib.sha256(secret.encode() + b"\n" + name.encode()).digest()
    return "cp_" + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def verifier(token):
    return hashlib.sha256(token.encode()).hexdigest()


class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        with self.lock:
            self.db.executescript(DDL)
            if self.db.execute("SELECT COUNT(*) FROM gate_state").fetchone()[0] == 0:
                t = now_ms()
                self.db.execute(
                    "INSERT INTO gate_state VALUES (0,'open','',?,?)", (t, t)
                )
            self.db.commit()

    def bootstrap(self, secret):
        """Seed per-client tokens from the bootstrap admin secret (U1)."""
        with self.lock:
            if self.db.execute("SELECT COUNT(*) FROM tokens").fetchone()[0]:
                return {}
            seeds = {"proxy": READ_SCOPE, "site": READ_SCOPE + "," + WRITE_SCOPE}
            out, t = {}, now_ms()
            for name, scopes in seeds.items():
                token = derive_token(secret, name)
                self.db.execute(
                    "INSERT INTO tokens VALUES (?,?,?,?,?,?,?,?)",
                    (
                        secrets.token_hex(8),
                        name,
                        verifier(token),
                        scopes,
                        t,
                        None,
                        None,
                        None,
                    ),
                )
                out[name] = token
            self.db.commit()
            return out

    def check(self, token, scope):
        want = verifier(token or "")
        with self.lock:
            rows = self.db.execute(
                "SELECT name,verifier_hash,scopes FROM tokens WHERE revoked_at IS NULL"
                " AND (expires_at IS NULL OR expires_at>?)",
                (now_ms(),),
            ).fetchall()
            # compare against stored hashes without logging the bearer
            for name, stored, scopes in rows:
                if hmac.compare_digest(stored, want):
                    if scope in scopes.split(","):
                        self.db.execute(
                            "UPDATE tokens SET last_used_at=? WHERE name=?",
                            (now_ms(), name),
                        )
                        self.db.commit()
                        return name
                    return None
            return None

    def gate(self):
        with self.lock:
            rev, mode, message, since, _ = self.db.execute(
                "SELECT * FROM gate_state"
            ).fetchone()
        return {
            "schema": SCHEMA,
            "revision": rev,
            "mode": mode,
            "message": message,
            "since": since,
            "observedAt": now_ms(),
        }

    def set_gate(self, mode, message, actor_id, actor_role, expected, key, client=None):
        if not isinstance(mode, str) or mode not in MODES:
            raise Bad("mode: open, draining или maintenance.")
        if not isinstance(message, str):
            raise Bad("message must be a string.")
        message = message.strip()[:MAX_MESSAGE]
        if not isinstance(actor_id, str) or not actor_id or len(actor_id) > 128:
            raise Bad("actor.id missing.")
        if not isinstance(actor_role, str) or actor_role not in ACTOR_ROLES:
            raise Bad("actor.role: owner или admin.")
        if not isinstance(key, str) or not key or len(key) > 128:
            raise Bad("idempotencyKey missing.")
        # bool is an int subclass (True == 1): only a real int guards the revision.
        if isinstance(expected, bool) or (
            expected is not None and not isinstance(expected, int)
        ):
            raise Bad("expectedRevision must be an integer.")
        with self.lock:
            rev, cur, _, since, _ = self.db.execute(
                "SELECT * FROM gate_state"
            ).fetchone()
            dup = self.db.execute(
                "SELECT operation_id,revision FROM gate_log WHERE idempotency_key=?",
                (key,),
            ).fetchone()
            if dup:
                same = self.db.execute(
                    "SELECT operation_id FROM gate_log WHERE idempotency_key=?"
                    " AND mode=? AND message=? AND actor_id=?",
                    (key, mode, message, actor_id),
                ).fetchone()
                if not same:
                    raise Conflict({"reason": "idempotencyKey reuse with a different body."})
                return {"operationId": dup[0], "revision": dup[1]}
            if expected != rev:
                raise Conflict({"revision": rev})
            t = now_ms()
            op = secrets.token_hex(12)
            new_rev = rev + 1
            self.db.execute(
                "INSERT INTO gate_log(operation_id,idempotency_key,revision,mode,"
                "message,actor_id,actor_role,at) VALUES (?,?,?,?,?,?,?,?)",
                (op, key, new_rev, mode, message, actor_id, actor_role, t),
            )
            self.db.execute(
                "UPDATE gate_state SET revision=?,mode=?,message=?,since=?,"
                "updated_at=?",
                (new_rev, mode, message, t if mode != cur else since, t),
            )
            self.db.execute(
                "INSERT INTO audit(at,actor,action,detail) VALUES (?,?,?,?)",
                (
                    t,
                    actor_id + ":" + actor_role,
                    "gate:set",
                    # E3: the actor is a forwarded claim from the site backend;
                    # always record which authenticated token submitted it.
                    json.dumps({"revision": new_rev, "mode": mode, "client": client})[
                        :500
                    ],
                ),
            )
            self.db.commit()
            return {"operationId": op, "revision": new_rev}


class Bad(Exception):
    pass


class Conflict(Exception):
    def __init__(self, detail):
        self.detail = detail


OPENAPI = {
    "openapi": "3.0.3",
    "info": {"title": "blockfield-control-plane", "version": "1"},
    "paths": {
        "/v1/gate": {
            "get": {
                "summary": "Current entry gate state (proxy/site poll).",
                "responses": {"200": {"description": "gate state"}},
            },
            "post": {
                "summary": "Set gate mode (site admin, gate:write).",
                "responses": {
                    "202": {"description": "accepted"},
                    "409": {"description": "stale revision or key reuse"},
                },
            },
        },
        "/v1/openapi.json": {
            "get": {
                "summary": "This document.",
                "responses": {"200": {"description": "openapi"}},
            }
        },
    },
}


class Handler(BaseHTTPRequestHandler):
    server_version = "control-plane/1"

    def log_message(self, *a):
        pass  # no bearer logging, ever

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _bearer(self):
        auth = self.headers.get("Authorization", "")
        return auth[len("Bearer ") :] if auth.startswith("Bearer ") else ""

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/v1/openapi.json":
            return self._send(200, OPENAPI)
        if path != "/v1/gate":
            return self._send(404, {"error": "not found"})
        name = self.server.store.check(self._bearer(), READ_SCOPE)
        if not name:
            return self._send(401, {"error": "unauthorized"})
        # Reads never write: the proxy polls every 5 s, an audit row per poll
        # would grow the DB ~17k rows/day. Token use stays in last_used_at.
        return self._send(200, self.server.store.gate())

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path != "/v1/gate":
            return self._send(404, {"error": "not found"})
        name = self.server.store.check(self._bearer(), WRITE_SCOPE)
        if not name:
            return self._send(401, {"error": "unauthorized"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > MAX_BODY:
                raise Bad("body too large")
            body = json.loads(self.rfile.read(length) or b"{}")
            actor = body.get("actor") or {}
            out = self.server.store.set_gate(
                body.get("mode"),
                body.get("message", ""),
                actor.get("id"),
                actor.get("role"),
                body.get("expectedRevision"),
                body.get("idempotencyKey"),
                client=name,
            )
        except (Bad, ValueError) as e:
            return self._send(400, {"error": str(e) or "bad request"})
        except Conflict as e:
            return self._send(409, {"error": "conflict", **e.detail})
        return self._send(202, out)


def serve(db_path, port):
    store = Store(db_path)
    secret = os.environ.get("CP_BOOTSTRAP_ADMIN_SECRET", "")
    if secret:
        seeded = store.bootstrap(secret)
        if seeded:
            print("bootstrapped tokens for: " + ",".join(sorted(seeded)), flush=True)
    elif store.db.execute("SELECT COUNT(*) FROM tokens").fetchone()[0] == 0:
        raise SystemExit("CP_BOOTSTRAP_ADMIN_SECRET is required on first boot.")
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.store = store
    print(f"control-plane on :{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    serve(os.environ.get("CP_DB", "cp.sqlite"), int(os.environ.get("CP_PORT", "8080")))
