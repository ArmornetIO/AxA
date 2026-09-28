-- Reference DDL for the embedded OpenFGA's Postgres datastore.
--
-- NOT APPLIED BY THIS PACKAGE, and OpenFGA's own migrator is disabled. Same rule
-- as pgstore/schema.sql: the host owns schema. Armornet applies these through
-- internal/schema/migrations; another host executes Schema() or folds it into
-- whatever it already uses.
--
-- This is upstream's postgres migrations 001–006 collapsed to their end state.
-- Keys are inline rather than ALTER TABLE ADD CONSTRAINT so every statement is
-- idempotent.

CREATE TABLE IF NOT EXISTS store (
    id text PRIMARY KEY,
    name text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone
);

CREATE TABLE IF NOT EXISTS authorization_model (
    store text NOT NULL,
    authorization_model_id text NOT NULL,
    type text NOT NULL,
    type_definition bytea,
    schema_version text DEFAULT '1.0'::text NOT NULL,
    serialized_protobuf bytea,
    PRIMARY KEY (store, authorization_model_id, type)
);

CREATE TABLE IF NOT EXISTS tuple (
    store text NOT NULL,
    object_type text NOT NULL,
    object_id text NOT NULL,
    relation text NOT NULL,
    _user text NOT NULL,
    user_type text NOT NULL,
    ulid text NOT NULL,
    inserted_at timestamp with time zone NOT NULL,
    condition_name text,
    condition_context bytea,
    PRIMARY KEY (store, object_type, object_id, relation, _user)
);

CREATE TABLE IF NOT EXISTS changelog (
    store text NOT NULL,
    object_type text NOT NULL,
    object_id text NOT NULL,
    relation text NOT NULL,
    _user text NOT NULL,
    operation integer NOT NULL,
    ulid text NOT NULL,
    inserted_at timestamp with time zone NOT NULL,
    condition_name text,
    condition_context bytea,
    PRIMARY KEY (store, ulid, object_type)
);

CREATE TABLE IF NOT EXISTS assertion (
    store text NOT NULL,
    authorization_model_id text NOT NULL,
    assertions bytea,
    PRIMARY KEY (store, authorization_model_id)
);

CREATE INDEX IF NOT EXISTS idx_tuple_partial_user ON tuple USING btree (store, object_type, object_id, relation, _user) WHERE (user_type = 'user'::text);
CREATE INDEX IF NOT EXISTS idx_tuple_partial_userset ON tuple USING btree (store, object_type, object_id, relation, _user) WHERE (user_type = 'userset'::text);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tuple_ulid ON tuple USING btree (ulid);
CREATE INDEX IF NOT EXISTS idx_user_lookup ON tuple USING btree (store, _user, relation, object_type, object_id COLLATE "C");
