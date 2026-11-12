-- Self-renewing service credentials (coordination#33). A renewal row links the
-- outgoing credential to its successor until the caller confirms; only a nonce
-- is stored, the new token is re-derived from the presented old token.
SET search_path = control, pg_catalog, pg_temp;
CREATE TABLE IF NOT EXISTS credential_renewals(
 old_id uuid PRIMARY KEY REFERENCES credentials, new_id uuid NOT NULL UNIQUE REFERENCES credentials,
 nonce bytea NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), confirmed_at timestamptz
);
GRANT SELECT,INSERT,UPDATE ON credential_renewals TO cp_runtime;
REVOKE ALL ON credential_renewals FROM PUBLIC;
