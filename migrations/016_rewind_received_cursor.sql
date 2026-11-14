-- Rewind received_cursor to the largest contiguous terminal ACK prefix (#69).
-- Earlier CP releases advanced consumers.received_cursor on non-terminal
-- `received` receipts, so an unsettled operation below the persisted cursor
-- would be skipped on snapshot/reconnect after deploying terminal-only cursors.
-- Recompute each consumer's cursor as the largest contiguous prefix of outbox
-- sequences covered by terminal receipts ('effective', 'rejected', 'unknown')
-- using the same definition as cpv2/delivery.py:acknowledge, and never move a
-- cursor forward. Idempotent and transactional. After deploy, consumers
-- reconnect from the rewound cursor and receive unsettled operations again.
--
-- Lock order (matches cpv2/delivery.py:acknowledge to avoid deadlocks):
--   1. consumers (EXCLUSIVE; conflicts with SELECT ... FOR UPDATE's ROW SHARE and
--      UPDATE's ROW EXCLUSIVE, matching the ack path's first lock on consumers)
--   2. consumer_acks (EXCLUSIVE; ack path inserts into consumer_acks after)
-- Acquiring both locks before the target CTE ensures a fresh READ COMMITTED
-- snapshot that observes any ACK serialized ahead of the migration and blocks
-- concurrent ACK writes until the rewind commits.
SET search_path = control, pg_catalog, pg_temp;
LOCK TABLE consumers IN EXCLUSIVE MODE;
LOCK TABLE consumer_acks IN EXCLUSIVE MODE;
WITH target AS (
  SELECT
    c.id,
    LEAST(
      c.received_cursor,
      GREATEST(
        0,
        COALESCE(
          (
            SELECT min(o.sequence) - 1
            FROM outbox o
            WHERE o.consumer_id = c.id
              AND NOT EXISTS (
                SELECT 1
                FROM consumer_acks a
                WHERE a.consumer_id = o.consumer_id
                  AND a.sequence = o.sequence
                  AND a.state IN ('effective', 'rejected', 'unknown')
              )
          ),
          c.next_sequence - 1
        )
      )
    ) AS cursor
  FROM consumers c
)
UPDATE consumers c
SET received_cursor = target.cursor
FROM target
WHERE c.id = target.id
  AND c.received_cursor > target.cursor;
