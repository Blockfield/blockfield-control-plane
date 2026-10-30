# blockfield-control-plane

Central API for Blockfield services (U1: entry gate + maintenance mode).
Python stdlib only (`api.py`: `http.server` + `sqlite3`), single writer,
SQLite journal on a named volume. No Redis, no new dependencies.

## API

- `GET /v1/gate` → `{schema:1, revision, mode, message, since, observedAt}`.
  Scope `gate:read` (proxy, site SSR).
- `POST /v1/gate`
  `{expectedRevision, idempotencyKey, mode, message, actor}` →
  `202 {operationId, revision}`. Scope `gate:write` (site admin backend).
  Modes: `open|draining|maintenance`. Stale `expectedRevision` → 409 with
  the current revision; same key + same body → same operation; same key +
  changed body → 409. Only `actor.role` `owner`/`admin` may toggle; every
  write is audited with the actor.
- `GET /v1/openapi.json` — schema (public).

Proxy polls `GET /v1/gate` every 5 s and fails closed when the answer is
older than its 60 s lease; site admins toggle the mode with the
«Начать/Закончить техработы» buttons.

## Tokens (U1 seed; U2 builds rotation UI on top)

On first boot with an empty DB the service derives two seed tokens from
`CP_BOOTSTRAP_ADMIN_SECRET` (never stored, only sha256 verifiers):

- `proxy`: `gate:read`
- `site`: `gate:read,gate:write`

Derivation: `token = "cp_" + base64url(sha256(secret + "\n" + name))`.
Re-derive with:

```sh
python3 -c "import hashlib,base64;print('cp_'+base64.urlsafe_b64encode(hashlib.sha256((open(0).read().rstrip(chr(10))+chr(10)+'site').encode()).digest()).decode().rstrip('='))"
```

The `tokens` table already carries `expires_at`, `revoked_at` and
`last_used_at` columns for U2 rotation; U1 never logs bearers.

## Run locally

```sh
CP_BOOTSTRAP_ADMIN_SECRET=dev-only CP_DB=/tmp/cp.sqlite CP_PORT=8080 python3 api.py
python3 -m unittest test_api -v
```

## One-time Dokploy setup (needs owner OK; NOT done by units)

1. Dokploy: new app `blockfield-control-plane`, **private network only**,
   no ingress, 1 replica, named volume `bf-control-state` mounted at
   `/data`, port 8080.
2. Environment: `CP_BOOTSTRAP_ADMIN_SECRET=<generated secret>`,
   `CP_DB=/data/cp.sqlite`.
3. Derive the `proxy`/`site` tokens (above), put them into the proxy
   (`BLOCKFIELD_CP_URL`, `BLOCKFIELD_CP_TOKEN`) and site
   (`BLOCKFIELD_CP_URL`, `BLOCKFIELD_CP_GATE_READ_TOKEN`,
   `BLOCKFIELD_CP_GATE_WRITE_TOKEN`, `BLOCKFIELD_GATE_SOURCE=cp`)
   app environments — never into the CP app itself.
4. Deploy, then `GET /v1/openapi.json` from inside the private network.
   Cut-over (removing the gate bind) is U6.
