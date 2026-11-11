-- Async rating rebuild queue (coordination#29 U3 round 2): voiding a rated
-- campaign must return inside the 10 s request timeout, so the request only
-- commits the void row and enqueues the season; a background worker in the CP
-- process replays it. Reads expose the pending row as ratingsRebuilding.
-- Round 3: the worker replays in bounded batches, keeping its cursor in the
-- queue row (NULL = replay from the season start) and releasing the rating
-- lock between batches, so requests never wait on a long replay.
SET search_path = control, pg_catalog, pg_temp;
CREATE TABLE stat_rating_rebuilds(
 season_id text PRIMARY KEY,
 server_id text NOT NULL, event_id text NOT NULL,
 requested_at timestamptz NOT NULL DEFAULT now(),
 last_ended_at timestamptz, last_server_id text, last_event_id text
);
GRANT SELECT,INSERT,UPDATE,DELETE ON stat_rating_rebuilds TO cp_runtime;
REVOKE ALL ON stat_rating_rebuilds FROM PUBLIC;
