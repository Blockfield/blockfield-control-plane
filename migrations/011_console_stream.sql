-- Console streaming + completion (coordination#35 follow-up, site#135):
-- the game pushes its log ring to CP and answers completion frames here.
-- Existing game consumers gain console.suggest next to the round-1 kinds.
SET search_path = control, pg_catalog, pg_temp;
CREATE TABLE console_log(
 consumer_id text NOT NULL REFERENCES consumers ON DELETE CASCADE,
 seq bigint NOT NULL,
 at timestamptz NOT NULL DEFAULT now(),
 level text NOT NULL,
 logger text NOT NULL,
 message text NOT NULL,
 PRIMARY KEY(consumer_id,seq)
);
CREATE INDEX console_log_consumer_seq ON console_log(consumer_id,seq);
UPDATE consumers
SET capabilities = array_append(capabilities, 'console.suggest')
WHERE 'console.run' = ANY(capabilities)
AND NOT 'console.suggest' = ANY(capabilities);
