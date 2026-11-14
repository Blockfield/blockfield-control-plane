-- Workshop controller state (coordination#64 rows 4/8/13): the controller
-- reports its status, catalogs and operation results here instead of the
-- shared admin directory; the site and the release CI read them back (GET or
-- the pushed SSE stream). seq orders changes for stream cursors.
SET search_path = control, pg_catalog, pg_temp;
CREATE SEQUENCE IF NOT EXISTS workshop_state_seq;
CREATE TABLE IF NOT EXISTS workshop_state(
 name text PRIMARY KEY,
 value jsonb NOT NULL,
 revision bigint NOT NULL CHECK(revision > 0),
 seq bigint NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS workshop_state_seq_idx ON workshop_state(seq);
GRANT SELECT,INSERT,UPDATE,DELETE ON workshop_state TO cp_runtime;
GRANT USAGE ON SEQUENCE workshop_state_seq TO cp_runtime;
