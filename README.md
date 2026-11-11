# blockfield-control-plane

Central API for Blockfield services. V2 is the PostgreSQL authority with durable
delivery; it runs as `python -m cpv2` (also the image default).

## Control-plane v2

The PostgreSQL authority, typed asynchronous API and private SSE/ACK core run
as `python -m cpv2`. See [the v2 contract and offline bootstrap](docs/V2.md).

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
- `GET /health` -> 200 status-ok when the store answers, 503 otherwise. No auth, no gate state, no bearer logging. Reports schema 2 (requires the owner bootstrap). For deploy gates and Dokploy healthchecks; entry still fails closed on the proxy 60 s lease.
- `GET /v1/openapi.json` — schema (public).

Proxy polls `GET /v1/gate` every 5 s and fails closed when the answer is
older than its 60 s lease; site admins toggle the mode with the
«Начать/Закончить техработы» buttons.

## Credentials

Service credentials are provisioned offline via `python -m cpv2.admin provision`
(see docs/V2.md). The runtime reads only `CP_DATABASE_URL` (least-privilege login)
and `CP_PORT`; no owner UUID or bootstrap secret is read.

## Run locally

```sh
python -m cpv2.admin --help
```

See docs/V2.md for the offline database bootstrap and owner registration.

## One-time Dokploy setup (needs owner OK; NOT done by units)

1. Dokploy: app `blockfield-control-plane`, **private network only**,
   no ingress, 1 replica, port 8080.
2. Environment: `CP_DATABASE_URL=<least-privilege runtime login>`,
   `CP_PORT=8080` (see docs/V2.md for the owner bootstrap; never put the
   migration/owner credentials into the app environment).
3. Provision the proxy/site credentials offline (`python -m cpv2.admin provision`)
   and put them into the proxy (`BLOCKFIELD_CP_URL`, `BLOCKFIELD_CP_TOKEN`)
   and site (`BLOCKFIELD_CP_URL`, `BLOCKFIELD_CP_GATE_READ_TOKEN`,
   `BLOCKFIELD_CP_GATE_WRITE_TOKEN`, `BLOCKFIELD_GATE_SOURCE=cp`)
   app environments — never into the CP app itself.
4. Deploy via the `Deploy control plane` workflow (moves the release-only `:prod`
   channel to the digest, redeploys through the app webhook and verifies the
   running digest; rollback is a redeploy of the previous digest — see
   docs/DEPLOY.md; needs the one-time owner setup of the `DOKPLOY_CP_WEBHOOK`
   secret), then `GET /v1/openapi.json` from inside the private network.
