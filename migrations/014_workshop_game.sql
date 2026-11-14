-- Workshop game consumer capabilities (coordination#64): the Workshop game
-- server runs its own CP agent alongside the main game server, receives
-- workshop.game lifecycle operations (save-on/off/flush, stop, export-limbo),
-- and pushes game-ready/game-activity state documents instead of RCON or files.
-- Existing prod/game/workshop consumers with console.run and without
-- moderation.say gain workshop.game and
-- workshop.ready idempotently. Tables operations/outbox/consumer_acks and
-- workshop_state already hold cp_runtime grants from 001/013.
SET search_path = control, pg_catalog, pg_temp;
UPDATE consumers
SET capabilities = capabilities || ARRAY(
  SELECT k FROM unnest(ARRAY['workshop.game','workshop.ready']::text[]) k
  WHERE NOT k = ANY(capabilities)
)
WHERE environment = 'prod' AND backend = 'game' AND resource = 'workshop'
  AND 'console.run' = ANY(capabilities)
  AND NOT 'moderation.say' = ANY(capabilities);
