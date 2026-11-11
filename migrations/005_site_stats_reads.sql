-- Stats reads + MMR (coordination#29 U3). Ratings are computed CP-side with
-- the site's Glicko-2 and per-season replay rule, replaying the stored
-- payloads like the site rebuildRatings. Voids live in their own table so
-- stat_results stays append-only under its immutable trigger.
SET search_path = control, pg_catalog, pg_temp;
CREATE TABLE stat_ratings(
 season_id text NOT NULL, uuid text NOT NULL, rating double precision NOT NULL,
 rd double precision NOT NULL, volatility double precision NOT NULL,
 rated_campaigns bigint NOT NULL, last_rated_at timestamptz NOT NULL,
 PRIMARY KEY(season_id,uuid)
);
CREATE TABLE stat_rating_changes(
 server_id text NOT NULL, event_id text NOT NULL, uuid text NOT NULL,
 rules_version text NOT NULL, team text NOT NULL, score double precision NOT NULL,
 opp_rating double precision NOT NULL, opp_rd double precision NOT NULL,
 before_rating double precision NOT NULL, before_rd double precision NOT NULL,
 before_volatility double precision NOT NULL,
 after_rating double precision NOT NULL, after_rd double precision NOT NULL,
 after_volatility double precision NOT NULL,
 rated_at timestamptz NOT NULL, season_id text NOT NULL,
 PRIMARY KEY(server_id,event_id,uuid),
 FOREIGN KEY(server_id,event_id) REFERENCES stat_results(server_id,event_id)
);
CREATE INDEX stat_rating_changes_uuid ON stat_rating_changes(uuid,rated_at);
CREATE TABLE stat_result_voids(
 server_id text NOT NULL, event_id text NOT NULL,
 voided_at timestamptz NOT NULL DEFAULT now(), voided_by text NOT NULL,
 PRIMARY KEY(server_id,event_id),
 FOREIGN KEY(server_id,event_id) REFERENCES stat_results(server_id,event_id)
);
GRANT SELECT,INSERT,UPDATE,DELETE ON stat_ratings,stat_rating_changes,stat_result_voids TO cp_runtime;
REVOKE ALL ON stat_ratings,stat_rating_changes,stat_result_voids FROM PUBLIC;
