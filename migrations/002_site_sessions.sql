-- Site player sessions (coordination#29 U1): sealed Drasl tokens live in CP,
-- the site becomes a stateless client. Runtime is never a database owner.
SET search_path = control, pg_catalog, pg_temp;
CREATE TABLE site_sessions(
 id text PRIMARY KEY CHECK(id ~ '^[0-9a-f]{32}$'),
 sealed_token text NOT NULL CHECK(length(sealed_token) BETWEEN 1 AND 4096),
 player_uuid text NOT NULL CHECK(length(player_uuid) BETWEEN 1 AND 128),
 created_at timestamptz NOT NULL DEFAULT now(),
 last_seen timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX site_sessions_player ON site_sessions(player_uuid,last_seen);
GRANT SELECT,INSERT,UPDATE,DELETE ON site_sessions TO cp_runtime;
REVOKE ALL ON site_sessions FROM PUBLIC;
