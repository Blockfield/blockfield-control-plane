-- Run once as the dedicated database owner. Runtime is never a database owner.
DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='cp_runtime') THEN
 CREATE ROLE cp_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
END IF; END $$;
CREATE SCHEMA control;
REVOKE ALL ON SCHEMA control FROM PUBLIC;
GRANT USAGE ON SCHEMA control TO cp_runtime;
SET search_path = control, pg_catalog, pg_temp;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
DO $$ BEGIN EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC',current_database()); END $$;
CREATE TABLE schema_migrations(version integer PRIMARY KEY, checksum text NOT NULL);
CREATE TABLE accounts(
 id uuid PRIMARY KEY, status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled','tombstoned')),
 display_name text NOT NULL CHECK(length(display_name) BETWEEN 1 AND 128),
 is_test boolean NOT NULL DEFAULT false, test_reason text, test_expires_at timestamptz,
 authorization_epoch bigint NOT NULL DEFAULT 1 CHECK(authorization_epoch > 0),
 created_at timestamptz NOT NULL DEFAULT now(), tombstoned_at timestamptz,
 CHECK(NOT is_test OR test_reason IS NOT NULL)
);
CREATE TABLE account_identities(
 account_id uuid NOT NULL REFERENCES accounts, issuer text NOT NULL, subject uuid NOT NULL,
 player_id uuid NOT NULL, current_name text NOT NULL, generation bigint NOT NULL CHECK(generation > 0),
 PRIMARY KEY(issuer,subject), UNIQUE(issuer,player_id)
);
CREATE TABLE clients(
 id text PRIMARY KEY, via text NOT NULL CHECK(via IN ('ui','mcp','cli','discord','game','release','recovery')),
 ceiling text[] NOT NULL, audience text NOT NULL DEFAULT 'blockfield-control-v2',
 human boolean NOT NULL DEFAULT false
);
CREATE TABLE owner_memberships(account_id uuid PRIMARY KEY REFERENCES accounts, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE owner_credentials(
 id text PRIMARY KEY, account_id uuid NOT NULL REFERENCES owner_memberships,
 public_key bytea NOT NULL, sign_count bigint NOT NULL DEFAULT 0,
 rp_id text NOT NULL, origin text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE role_grants(
 id uuid PRIMARY KEY, account_id uuid NOT NULL REFERENCES accounts,
 role text NOT NULL CHECK(role IN ('builder','moderator','admin')),
 environment text NOT NULL, backend text NOT NULL, resource text NOT NULL,
 grantor uuid NOT NULL REFERENCES accounts, revision bigint NOT NULL CHECK(revision > 0),
 expires_at timestamptz, revoked_at timestamptz,
 CHECK(account_id <> grantor)
);
CREATE TABLE credentials(
 id uuid PRIMARY KEY, verifier text NOT NULL UNIQUE, account_id uuid REFERENCES accounts,
 client_id text NOT NULL REFERENCES clients, ceiling text[] NOT NULL,
 environment text NOT NULL, backend text NOT NULL, resource text NOT NULL,
 kind text NOT NULL CHECK(kind IN ('session','delegation','service')),
 audience text NOT NULL DEFAULT 'blockfield-control-v2', authorization_epoch bigint,
 parent_id uuid REFERENCES credentials, expires_at timestamptz NOT NULL,
 revoked_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(),
 CHECK((kind = 'service') = (account_id IS NULL))
);
CREATE TABLE owner_challenges(
 id uuid PRIMARY KEY, account_id uuid NOT NULL REFERENCES owner_memberships,
 credential_id uuid NOT NULL REFERENCES credentials, action_hash text NOT NULL,
 challenge bytea NOT NULL, expires_at timestamptz NOT NULL, used_at timestamptz
);
-- WebAuthn replay counters live outside protected credential public keys.
CREATE TABLE owner_assertions(
 credential_id text PRIMARY KEY REFERENCES owner_credentials, sign_count bigint NOT NULL CHECK(sign_count >= 0)
);
CREATE TABLE setting_definitions(
 namespace text PRIMARY KEY, schema_version integer NOT NULL, json_schema jsonb NOT NULL,
 default_value jsonb NOT NULL, read_scope text NOT NULL, write_scope text NOT NULL,
 owner_paths text[] NOT NULL, timing text NOT NULL,
 sensitivity text NOT NULL CHECK(sensitivity IN ('ordinary','protected'))
);
CREATE TABLE operations(
 id uuid PRIMARY KEY, account_id uuid REFERENCES accounts, credential_id uuid NOT NULL REFERENCES credentials,
 client_id text NOT NULL REFERENCES clients, via text NOT NULL, kind text NOT NULL,
 target text NOT NULL, resource text NOT NULL, environment text NOT NULL, backend text NOT NULL,
 request_hash text NOT NULL, idempotency_key text NOT NULL, authorization_epoch bigint,
 required_scope text NOT NULL, expected_revision bigint, revision bigint,
 generation uuid, deadline timestamptz NOT NULL, status text NOT NULL CHECK(status IN
 ('accepted','received','validated','applied','effective','rejected','expired','unknown','partial')),
 result jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(credential_id,idempotency_key)
);
CREATE TABLE settings_revisions(
 namespace text NOT NULL REFERENCES setting_definitions, environment text NOT NULL, backend text NOT NULL,
 target text NOT NULL, revision bigint NOT NULL CHECK(revision > 0), base_revision bigint NOT NULL,
 value jsonb NOT NULL, diff jsonb NOT NULL, value_hash text NOT NULL,
 operation_id uuid NOT NULL UNIQUE REFERENCES operations, actor uuid NOT NULL REFERENCES accounts,
 rollback_of bigint, state_since timestamptz NOT NULL DEFAULT now(), created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(namespace,environment,backend,target,revision)
);
CREATE TABLE settings_heads(
 namespace text NOT NULL REFERENCES setting_definitions, environment text NOT NULL, backend text NOT NULL,
 target text NOT NULL, revision bigint NOT NULL DEFAULT 0 CHECK(revision >= 0),
 PRIMARY KEY(namespace,environment,backend,target)
);
CREATE TABLE audit_events(
 sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 attempt_id uuid NOT NULL, operation_id uuid REFERENCES operations, parent_id uuid,
 actor uuid REFERENCES accounts, credential_id uuid REFERENCES credentials,
 client_id text REFERENCES clients, via text NOT NULL, request_id uuid NOT NULL,
 action text NOT NULL, target text NOT NULL,
 environment text NOT NULL DEFAULT '*', backend text NOT NULL DEFAULT '*', resource text NOT NULL DEFAULT '*',
 outcome text NOT NULL,
 policy_version integer NOT NULL DEFAULT 2, detail jsonb NOT NULL DEFAULT '{}',
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(), recorded_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_attempt ON audit_events(attempt_id,sequence);
CREATE TABLE operation_events(
 sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, operation_id uuid NOT NULL REFERENCES operations,
 status text NOT NULL, detail jsonb NOT NULL DEFAULT '{}', at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE consumers(
 id text PRIMARY KEY, credential_id uuid NOT NULL UNIQUE REFERENCES credentials,
 environment text NOT NULL, backend text NOT NULL, resource text NOT NULL,
 generation uuid NOT NULL, epoch uuid NOT NULL, capabilities text[] NOT NULL,
 next_sequence bigint NOT NULL DEFAULT 1, received_cursor bigint NOT NULL DEFAULT 0,
 last_heartbeat timestamptz, CHECK(next_sequence > received_cursor)
);
CREATE TABLE outbox(
 consumer_id text NOT NULL REFERENCES consumers, sequence bigint NOT NULL,
 epoch uuid NOT NULL, operation_id uuid NOT NULL REFERENCES operations,
 generation uuid NOT NULL, revision bigint, payload jsonb NOT NULL, payload_hash text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(consumer_id,sequence),
 UNIQUE(consumer_id,operation_id)
);
CREATE INDEX outbox_operation ON outbox(operation_id);
CREATE TABLE consumer_acks(
 consumer_id text NOT NULL, sequence bigint NOT NULL, state text NOT NULL
 CHECK(state IN ('received','validated','applied','effective','rejected','unknown')),
 receipt_hash text NOT NULL, result jsonb NOT NULL, actual_at timestamptz NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(consumer_id,sequence,state),
 FOREIGN KEY(consumer_id,sequence) REFERENCES outbox
);
CREATE TABLE legacy_imports(source_hash text PRIMARY KEY, manifest jsonb NOT NULL, imported_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE legacy_records(source_hash text NOT NULL REFERENCES legacy_imports, kind text NOT NULL,
 legacy_id text NOT NULL, body jsonb NOT NULL, PRIMARY KEY(source_hash,kind,legacy_id));
CREATE TABLE legacy_gate(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), value jsonb NOT NULL);
CREATE TABLE legacy_read_tokens(verifier text PRIMARY KEY, name text NOT NULL, expires_at timestamptz, revoked_at timestamptz);

CREATE FUNCTION immutable_row() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'append-only record'; END $$;
CREATE TRIGGER audit_immutable BEFORE UPDATE OR DELETE ON audit_events FOR EACH ROW EXECUTE FUNCTION immutable_row();
CREATE TRIGGER revision_immutable BEFORE UPDATE OR DELETE ON settings_revisions FOR EACH ROW EXECUTE FUNCTION immutable_row();
CREATE TRIGGER event_immutable BEFORE UPDATE OR DELETE ON operation_events FOR EACH ROW EXECUTE FUNCTION immutable_row();
CREATE TRIGGER outbox_immutable BEFORE UPDATE OR DELETE ON outbox FOR EACH ROW EXECUTE FUNCTION immutable_row();
CREATE TRIGGER ack_immutable BEFORE UPDATE OR DELETE ON consumer_acks FOR EACH ROW EXECUTE FUNCTION immutable_row();
CREATE FUNCTION protect_account() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.is_test AND NOT NEW.is_test THEN RAISE EXCEPTION 'test privacy classification is permanent'; END IF;
 IF NEW.is_test AND EXISTS(SELECT 1 FROM control.owner_memberships WHERE account_id=NEW.id) THEN
 RAISE EXCEPTION 'owner cannot be a test account'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER account_protected BEFORE UPDATE ON accounts FOR EACH ROW EXECUTE FUNCTION protect_account();
CREATE FUNCTION protect_owner() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM control.accounts WHERE id=NEW.account_id AND (is_test OR status <> 'active')) THEN
 RAISE EXCEPTION 'owner must be an active ordinary account'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER owner_protected BEFORE INSERT OR UPDATE ON owner_memberships FOR EACH ROW EXECUTE FUNCTION protect_owner();
GRANT SELECT ON ALL TABLES IN SCHEMA control TO cp_runtime;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA control TO cp_runtime;
GRANT INSERT ON audit_events,operation_events,settings_revisions,outbox,consumer_acks TO cp_runtime;
GRANT INSERT,UPDATE ON role_grants,credentials,owner_challenges,owner_assertions,operations,settings_heads TO cp_runtime;
GRANT UPDATE ON accounts,consumers TO cp_runtime;
REVOKE ALL ON schema_migrations,legacy_records,legacy_imports FROM cp_runtime;
