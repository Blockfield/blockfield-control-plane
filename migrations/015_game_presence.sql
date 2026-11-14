-- Game presence (coordination#64 rows 10-11): the game agent pushes its live
-- room/status report; the site reads rooms + gate from CP instead of direct
-- status TCP, status.json or the gate file. Latest-only per consumer
-- (upsert, no history): readers poll the CP read API, agents never poll CP.
SET search_path = control, pg_catalog, pg_temp;
CREATE TABLE IF NOT EXISTS game_presence(
  consumer_id TEXT PRIMARY KEY,
  reported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  environment TEXT NOT NULL,
  backend TEXT NOT NULL,
  resource TEXT NOT NULL DEFAULT '*',
  value JSONB NOT NULL
);
GRANT SELECT,INSERT,UPDATE ON game_presence TO cp_runtime;
