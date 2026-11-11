-- Async rating rebuild queue (coordination#29 U3 round 2): voiding a rated
-- campaign must return inside the 10 s request timeout, so the request only
-- commits the void row and enqueues the season; a background worker in the CP
-- process replays it. Reads expose the pending row as ratingsRebuilding.
SET search_path = control, pg_catalog, pg_temp;
CREATE TABLE stat_rating_rebuilds(
 season_id text PRIMARY KEY,
 server_id text NOT NULL, event_id text NOT NULL,
 requested_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT,INSERT,UPDATE,DELETE ON stat_rating_rebuilds TO cp_runtime;
REVOKE ALL ON stat_rating_rebuilds FROM PUBLIC;
