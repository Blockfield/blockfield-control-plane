-- Match/campaign results ingested from the game producer (coordination#29 U1).
-- CP stats start with the new season: no history import, no rating compute yet
-- (reads land in a later unit and replay the stored payloads). Runtime inserts
-- only; history rows are append-only like audit evidence. Profiles are the
-- display-name cache and upsert by uuid.
SET search_path = control, pg_catalog, pg_temp;
CREATE TABLE stat_results(
 server_id text NOT NULL, event_id text NOT NULL, kind text NOT NULL, mode text NOT NULL,
 campaign_id text, ended_at timestamptz NOT NULL, reason text NOT NULL, winner text NOT NULL,
 digest text NOT NULL, payload jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(server_id,event_id)
);
CREATE INDEX stat_results_mode_time ON stat_results(mode,ended_at);
CREATE TABLE stat_profiles(
 uuid text PRIMARY KEY, name text NOT NULL CHECK(length(name) BETWEEN 1 AND 64),
 last_seen timestamptz NOT NULL
);
CREATE TABLE stat_participants(
 server_id text NOT NULL, event_id text NOT NULL, uuid text NOT NULL, team text NOT NULL,
 score double precision NOT NULL, kills bigint NOT NULL, deaths bigint NOT NULL,
 captures bigint NOT NULL, neutralizations bigint NOT NULL,
 point_seconds bigint NOT NULL, play_seconds bigint NOT NULL,
 suicides bigint NOT NULL, team_kills bigint NOT NULL, max_streak bigint NOT NULL,
 PRIMARY KEY(server_id,event_id,uuid),
 FOREIGN KEY(server_id,event_id) REFERENCES stat_results(server_id,event_id)
);
CREATE INDEX stat_participants_uuid ON stat_participants(uuid);
CREATE TABLE stat_classes(
 server_id text NOT NULL, event_id text NOT NULL, uuid text NOT NULL,
 class_id text NOT NULL, variant_id text NOT NULL,
 time_seconds bigint NOT NULL, kills bigint NOT NULL, deaths bigint NOT NULL,
 point_seconds bigint NOT NULL,
 PRIMARY KEY(server_id,event_id,uuid,class_id,variant_id),
 FOREIGN KEY(server_id,event_id,uuid) REFERENCES stat_participants(server_id,event_id,uuid)
);
GRANT SELECT,INSERT ON stat_results,stat_participants,stat_classes TO cp_runtime;
GRANT SELECT,INSERT,UPDATE ON stat_profiles TO cp_runtime;
REVOKE ALL ON stat_results,stat_participants,stat_classes,stat_profiles FROM PUBLIC;
CREATE TRIGGER stat_results_immutable BEFORE UPDATE OR DELETE ON stat_results FOR EACH ROW EXECUTE FUNCTION immutable_row();
CREATE TRIGGER stat_participants_immutable BEFORE UPDATE OR DELETE ON stat_participants FOR EACH ROW EXECUTE FUNCTION immutable_row();
CREATE TRIGGER stat_classes_immutable BEFORE UPDATE OR DELETE ON stat_classes FOR EACH ROW EXECUTE FUNCTION immutable_row();
