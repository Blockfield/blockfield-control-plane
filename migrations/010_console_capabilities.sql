-- Site RCON cutover (coordination#35): every consumer that already executes the
-- site moderation kinds (the game servers) also receives the kinds that replace
-- the remaining RCON paths. A game build without them rejects the frames as an
-- unknown action; authority still comes from the caller's scopes.
SET search_path = control, pg_catalog, pg_temp;
UPDATE consumers
SET capabilities = capabilities || ARRAY(
  SELECT k FROM unnest(ARRAY['moderation.maintenance','moderation.announce','console.run']::text[]) k
  WHERE NOT k = ANY(capabilities)
)
WHERE 'moderation.say' = ANY(capabilities);
