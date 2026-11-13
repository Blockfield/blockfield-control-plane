-- Console log cursor independent of retained rows (review round: retention
-- deleting every row restarted the sequence at 1 and polling sites missed
-- new logs until the sequence passed their cursor). The counter only moves
-- forward on ingest, under a row lock, so concurrent batches serialize.
SET search_path = control, pg_catalog, pg_temp;
CREATE TABLE IF NOT EXISTS console_log_seq(
 consumer_id text PRIMARY KEY REFERENCES consumers ON DELETE CASCADE,
 next_seq bigint NOT NULL DEFAULT 0
);
INSERT INTO console_log_seq(consumer_id, next_seq)
 SELECT consumer_id, COALESCE(MAX(seq),0) FROM console_log GROUP BY consumer_id
 ON CONFLICT DO NOTHING;
