-- Consumer credential rotation without a delivery gap (control-plane#57).
-- Re-provisioning a consumer id keeps the row (generation, epoch, cursors,
-- outbox) and stashes the outgoing credential here, so both tokens pull
-- delivery until the old one is revoked. Revocation is enforced in
-- authenticate(), before consumer_for() ever runs.
SET search_path = control, pg_catalog, pg_temp;
ALTER TABLE consumers ADD COLUMN IF NOT EXISTS previous_credential_id uuid NULL REFERENCES credentials;
