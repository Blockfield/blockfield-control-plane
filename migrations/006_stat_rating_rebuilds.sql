-- Async rating rebuild queue (coordination#29 U3 round 2): voiding a rated
-- campaign must return inside the 10 s request timeout, so the request only
-- commits the void row and enqueues the season; a background worker in the CP
-- process replays it. Reads expose the pending row as ratingsRebuilding.
-- Round 3: the worker replays in bounded batches, keeping its cursor in the
-- queue row (NULL = replay from the season start) and releasing the rating
-- lock between batches, so requests never wait on a long replay.
-- Round 5: every row carries a generation counter, bumped by every
-- enqueue/reset. A batch commits only with UPDATE/DELETE ... WHERE
-- generation = <read value> (compare-and-swap) in the same transaction as
-- its rating writes; a concurrent enqueue then rolls the batch back instead
-- of losing the request. Exactly one worker runs across replicas (session
-- advisory lock in the worker loop), so no second reader can commit.
SET search_path = control, pg_catalog, pg_temp;
CREATE TABLE stat_rating_rebuilds(
 season_id text PRIMARY KEY,
 server_id text NOT NULL, event_id text NOT NULL,
 requested_at timestamptz NOT NULL DEFAULT now(),
 generation integer NOT NULL DEFAULT 1,
 last_ended_at timestamptz, last_server_id text, last_event_id text
);
GRANT SELECT,INSERT,UPDATE,DELETE ON stat_rating_rebuilds TO cp_runtime;
REVOKE ALL ON stat_rating_rebuilds FROM PUBLIC;
