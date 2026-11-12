-- Game-server diagnostics pushed by the producer (coordination#29 U4). Same
-- caps as the site `server_samples`/`server_events` tables (50k samples over
-- 7 days, 5k events over 14 days with crash/error priority): the runtime
-- prunes by age and row count on every ingest, like the site saveReport.
-- No immutable trigger: pruning deletes old rows. History rows are
-- append-only from the API (inserts only, resends ignored).
SET search_path = control, pg_catalog, pg_temp;
CREATE TABLE stat_samples(
 server_id text NOT NULL, at timestamptz NOT NULL,
 tps double precision NOT NULL, mspt_avg double precision NOT NULL,
 mspt_p95 double precision, mspt_max double precision NOT NULL,
 players bigint, heap_used_mb bigint, heap_max_mb bigint, gc_pause_ms bigint,
 started_at timestamptz,
 PRIMARY KEY(server_id,at)
);
CREATE TABLE stat_events(
 server_id text NOT NULL, event_id text NOT NULL, at timestamptz NOT NULL,
 kind text NOT NULL, duration_ms bigint, source text, message text NOT NULL,
 repeats integer NOT NULL,
 PRIMARY KEY(server_id,event_id)
);
CREATE INDEX stat_samples_at ON stat_samples(at);
CREATE INDEX stat_events_at ON stat_events(at);
GRANT SELECT,INSERT,DELETE ON stat_samples,stat_events TO cp_runtime;
REVOKE ALL ON stat_samples,stat_events FROM PUBLIC;
