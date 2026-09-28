-- Reference DDL for the embedded Dex's Ent storage.
--
-- NOT APPLIED BY THIS PACKAGE, and Dex's own migrator is disabled. Same rule as
-- pgstore/schema.sql: the host owns schema. Armornet applies these through
-- internal/schema/migrations; another host executes Schema() or folds it into
-- whatever it already uses.
--
-- org_id is an ARMORNET FORK column the fork's Ent code reads and writes, so it
-- is part of the contract. The seal CHECK constraints armornet adds on top
-- (ANS1: prefixes on claims, connector config, device codes) are NOT: they
-- enforce armornet's sealer, and a host running without one would have every
-- write refused.
--
-- Keys are inline rather than ALTER TABLE ADD CONSTRAINT so every statement is
-- idempotent.

CREATE TABLE IF NOT EXISTS auth_codes (
    id text PRIMARY KEY,
    client_id text NOT NULL,
    scopes jsonb,
    nonce text NOT NULL,
    redirect_uri text NOT NULL,
    claims_user_id text NOT NULL,
    claims_username text NOT NULL,
    claims_groups jsonb,
    claims_preferred_username text DEFAULT ''::text NOT NULL,
    connector_id text NOT NULL,
    connector_data bytea,
    expiry timestamp with time zone NOT NULL,
    code_challenge text DEFAULT ''::text NOT NULL,
    code_challenge_method text DEFAULT ''::text NOT NULL,
    org_id text DEFAULT ''::text NOT NULL,
    claims_email text DEFAULT ''::text NOT NULL,
    claims_email_verified boolean DEFAULT false NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_requests (
    id text PRIMARY KEY,
    client_id text NOT NULL,
    scopes jsonb,
    response_types jsonb,
    redirect_uri text NOT NULL,
    nonce text NOT NULL,
    state text NOT NULL,
    force_approval_prompt boolean NOT NULL,
    logged_in boolean NOT NULL,
    claims_user_id text NOT NULL,
    claims_username text NOT NULL,
    claims_groups jsonb,
    claims_preferred_username text DEFAULT ''::text NOT NULL,
    connector_id text NOT NULL,
    connector_data bytea,
    expiry timestamp with time zone NOT NULL,
    code_challenge text DEFAULT ''::text NOT NULL,
    code_challenge_method text DEFAULT ''::text NOT NULL,
    hmac_key bytea NOT NULL,
    org_id text DEFAULT ''::text NOT NULL,
    claims_email text DEFAULT ''::text NOT NULL,
    claims_email_verified boolean DEFAULT false NOT NULL
);

CREATE TABLE IF NOT EXISTS connectors (
    id text PRIMARY KEY,
    type text NOT NULL,
    name text NOT NULL,
    resource_version text NOT NULL,
    config bytea NOT NULL,
    org_id text DEFAULT ''::text NOT NULL
);

CREATE TABLE IF NOT EXISTS device_requests (
    id BIGSERIAL PRIMARY KEY,
    user_code text NOT NULL UNIQUE,
    device_code text NOT NULL,
    client_id text NOT NULL,
    client_secret text NOT NULL,
    scopes jsonb,
    expiry timestamp with time zone NOT NULL,
    org_id text DEFAULT ''::text NOT NULL
);

CREATE TABLE IF NOT EXISTS device_tokens (
    id BIGSERIAL PRIMARY KEY,
    device_code text NOT NULL UNIQUE,
    status text NOT NULL,
    token bytea,
    expiry timestamp with time zone NOT NULL,
    last_request timestamp with time zone NOT NULL,
    poll_interval integer NOT NULL,
    code_challenge text DEFAULT ''::text NOT NULL,
    code_challenge_method text DEFAULT ''::text NOT NULL,
    org_id text DEFAULT ''::text NOT NULL
);

CREATE TABLE IF NOT EXISTS keys (
    id text PRIMARY KEY,
    verification_keys jsonb NOT NULL,
    signing_key jsonb NOT NULL,
    signing_key_pub jsonb NOT NULL,
    next_rotation timestamp with time zone NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth2clients (
    id text PRIMARY KEY,
    secret text NOT NULL,
    redirect_uris jsonb,
    trusted_peers jsonb,
    public boolean NOT NULL,
    name text NOT NULL,
    logo_url text NOT NULL,
    org_id text DEFAULT ''::text NOT NULL
);

CREATE TABLE IF NOT EXISTS offline_sessions (
    id text PRIMARY KEY,
    user_id text NOT NULL,
    conn_id text NOT NULL,
    refresh bytea NOT NULL,
    connector_data bytea,
    org_id text DEFAULT ''::text NOT NULL
);

CREATE TABLE IF NOT EXISTS passwords (
    id BIGSERIAL PRIMARY KEY,
    hash bytea NOT NULL,
    username text NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    preferred_username text DEFAULT ''::text NOT NULL,
    user_id text NOT NULL,
    groups jsonb,
    org_id text DEFAULT ''::text NOT NULL,
    email text DEFAULT ''::text NOT NULL,
    email_verified boolean
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id text PRIMARY KEY,
    client_id text NOT NULL,
    scopes jsonb,
    nonce text NOT NULL,
    claims_user_id text NOT NULL,
    claims_username text NOT NULL,
    claims_groups jsonb,
    claims_preferred_username text DEFAULT ''::text NOT NULL,
    connector_id text NOT NULL,
    connector_data bytea,
    token text DEFAULT ''::text NOT NULL,
    obsolete_token text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_used timestamp with time zone NOT NULL,
    org_id text DEFAULT ''::text NOT NULL,
    claims_email text DEFAULT ''::text NOT NULL,
    claims_email_verified boolean DEFAULT false NOT NULL
);

CREATE INDEX IF NOT EXISTS auth_codes_org_id_idx ON auth_codes USING btree (org_id);
CREATE INDEX IF NOT EXISTS auth_requests_org_id_idx ON auth_requests USING btree (org_id);
CREATE INDEX IF NOT EXISTS connectors_org_id_idx ON connectors USING btree (org_id);
CREATE INDEX IF NOT EXISTS device_requests_org_id_idx ON device_requests USING btree (org_id);
CREATE INDEX IF NOT EXISTS device_tokens_org_id_idx ON device_tokens USING btree (org_id);
CREATE INDEX IF NOT EXISTS oauth2clients_org_id_idx ON oauth2clients USING btree (org_id);
CREATE INDEX IF NOT EXISTS offline_sessions_org_id_idx ON offline_sessions USING btree (org_id);
CREATE UNIQUE INDEX IF NOT EXISTS passwords_email_key ON passwords USING btree (email);
CREATE INDEX IF NOT EXISTS passwords_org_id_idx ON passwords USING btree (org_id);
CREATE INDEX IF NOT EXISTS refresh_tokens_org_id_idx ON refresh_tokens USING btree (org_id);
