-- Workshop game consumer capabilities (coordination#64): the Workshop game
-- server runs its own CP agent alongside the main game server, receives
-- workshop.game lifecycle operations (save-on/off/flush, stop, export-limbo),
-- and pushes game-ready/game-activity state documents instead of RCON or files.
-- Existing Workshop game consumers (console.run without moderation.say, i.e.
-- never the main game or the Workshop controller) gain workshop.game and
-- workshop.ready idempotently. Tables operations/outbox/consumer_acks and
-- workshop_state already hold cp_runtime grants from 001/013.
SET search_path = control, pg_catalog, pg_temp;
UPDATE consumers
SET capabilities = capabilities || ARRAY(
  SELECT k FROM unnest(ARRAY['workshop.game','workshop.ready']::text[]) k
  WHERE NOT k = ANY(capabilities)
)
WHERE 'console.run' = ANY(capabilities)
  AND NOT 'moderation.say' = ANY(capabilities);
