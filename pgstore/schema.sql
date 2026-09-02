-- Reference DDL for the tables identity owns.
--
-- NOT APPLIED BY THIS PACKAGE. pgstore takes an opened *sql.DB and runs
-- queries; it never migrates. Creating and versioning these tables is the
-- host's job, deliberately: a library that silently reshapes a database it was
-- handed is a library that fights whatever the host already uses to manage
-- schema. The embedded Dex and OpenFGA ship migrators that run disabled for
-- exactly this reason; a host applies their tables through its own migrations.
--
-- A host should apply these however it already manages schema; this file is the
-- contract of what pgstore expects to find, and Schema() returns it verbatim so
-- a consumer can execute or diff it programmatically. Every statement is
-- idempotent, so re-running it is safe — but it will not upgrade a table that
-- already exists in an older shape.
--
-- Columns marked HOST are ones identity reads and writes but does not define the
-- meaning of. org_id is the clearest case: identity treats it as an opaque
-- scoping string, while a host may point a foreign key at its own tenant table
-- (armornet does). Nothing here requires that.

-- organizations: a tenant's identity, and nothing a host hangs off it.
--
-- parent_id supports grouping tenants under an enterprise. Self-referential and
-- nullable: identity records the shape and does not interpret it — what a parent
-- implies about billing, policy inheritance or visibility is the host's.
CREATE TABLE IF NOT EXISTS organizations (
    id         text NOT NULL PRIMARY KEY,
    name       text NOT NULL,
    slug       text NOT NULL,
    parent_id  text REFERENCES organizations (id),
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    updated_at timestamp with time zone NOT NULL DEFAULT now()
);

-- users: the mapping from an IDP subject to a stable internal id.
--
-- subject is the identity, and the reason this table exists at all: it is the
-- only stable handle across logins. Email is stored but never keyed on — an
-- address changes hands, and a user row that followed it would hand one person
-- another's history.
CREATE TABLE IF NOT EXISTS users (
    id           uuid NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    subject      text NOT NULL DEFAULT '',
    email        text NOT NULL DEFAULT '',
    display_name text NOT NULL DEFAULT '',
    created_at   timestamp with time zone NOT NULL DEFAULT now(),
    updated_at   timestamp with time zone NOT NULL DEFAULT now()
);

-- Partial, because the default '' is not an identity: rows predating a subject
-- must not collide with each other while still being unique once one arrives.
CREATE UNIQUE INDEX IF NOT EXISTS users_subject_key ON users (subject) WHERE subject <> '';

-- organization_users: membership, and the authority every scope decision rests
-- on. A credential may claim an org only if a row here says so.
CREATE TABLE IF NOT EXISTS organization_users (
    org_id     text NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- HOST: an opaque label to identity. The vocabulary and what each role
    -- permits are the host's policy, enforced above this layer.
    role       text NOT NULL DEFAULT 'member',
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id)
);

-- sessions: one row per signed-in browser.
--
-- token_hash, not the token. The value the browser sends is never written down;
-- only its SHA-256 digest is, so a database read or a backup yields no usable
-- credential. id is the primary key and what a provider-issued `sid` is matched
-- against on back-channel logout — it is not a secret and must never reach a
-- browser.
--
-- org_id is nullable because a session can legitimately exist before its owner
-- belongs to anything.
--
-- No upstream token is kept: the ID token is verified once at the callback and
-- nothing after sign-in presents or sends one. connector_id names the
-- identity provider configuration, so a signed-in person can re-authorize
-- without a picker.
CREATE TABLE IF NOT EXISTS sessions (
    id            uuid        DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    subject       text        NOT NULL,
    org_id        text,                                  -- HOST: opaque to identity
    token_hash    text,
    connector_id  text        NOT NULL DEFAULT '',
    expires_at    timestamp with time zone NOT NULL,
    created_at    timestamp with time zone NOT NULL DEFAULT now(),
    last_seen_at  timestamp with time zone NOT NULL DEFAULT now()
);

-- The lookup every authenticated request makes. UNIQUE because two sessions
-- sharing a digest would make authentication ambiguous.
CREATE UNIQUE INDEX IF NOT EXISTS sessions_token_hash_key ON sessions (token_hash);

-- magic_link: short-lived scoped access issued by e-mail.
--
-- Only the hash is stored, same rule as sessions. prefix is an unhashed lookup
-- key that narrows candidates to a handful so the expensive verify runs a few
-- times rather than across the table.
CREATE TABLE IF NOT EXISTS magic_link (
    id          text NOT NULL PRIMARY KEY,
    prefix      text NOT NULL,
    token_hash  text NOT NULL,
    subject     text NOT NULL,
    org_id      text NOT NULL,                            -- HOST: opaque to identity
    object_type text NOT NULL,                            -- HOST: authz object being granted
    object_id   text NOT NULL,                            -- HOST
    relation    text NOT NULL,                            -- HOST
    expires_at  timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_at  timestamp with time zone NOT NULL DEFAULT now()
);

-- Partial: only live links are ever looked up, so consumed ones stay out of the
-- index entirely.
CREATE INDEX IF NOT EXISTS idx_magic_link_prefix ON magic_link (prefix) WHERE consumed_at IS NULL;

-- personal_access_tokens: credentials a user issues for a CLI or an agent.
--
-- Only the argon2id hash is stored. `prefix` is the unhashed first characters of
-- the token, kept so a lookup narrows to a handful of candidates before the
-- deliberately expensive verify — without it, authenticating would mean running
-- argon2 against every row.
--
-- user_id is the ISSUER, and authentication joins through it to users.subject
-- so a token resolves to exactly the membership its owner's session would. The
-- three nullable timestamps are three distinct absences: never expires, never
-- used, not revoked.
CREATE TABLE IF NOT EXISTS personal_access_tokens (
    id           text NOT NULL PRIMARY KEY,
    user_id      text NOT NULL,
    org_id       text NOT NULL,                          -- HOST: opaque to identity
    name         text NOT NULL,
    prefix       text NOT NULL,
    token_hash   text NOT NULL,
    -- HOST: identity carries scopes through and never interprets them.
    scopes       text[] NOT NULL DEFAULT '{}'::text[],
    created_at   timestamp with time zone NOT NULL,
    expires_at   timestamp with time zone,
    last_used_at timestamp with time zone,
    revoked_at   timestamp with time zone
);

CREATE INDEX IF NOT EXISTS idx_pat_prefix ON personal_access_tokens (prefix);
CREATE INDEX IF NOT EXISTS idx_pat_user ON personal_access_tokens (user_id);
-- Partial: the only listing that matters operationally is of tokens still live.
CREATE INDEX IF NOT EXISTS idx_pat_active ON personal_access_tokens (org_id) WHERE revoked_at IS NULL;

-- mfa_challenges: a login held open between the upstream callback and the
-- second factor still owed.
--
-- subject rather than a user id: no session exists yet, so there is nothing
-- resolved to hang this off. token_expiry is the UPSTREAM tokens' deadline,
-- carried so the session minted afterwards cannot outlive the credentials
-- behind it; expires_at is how long the person has to answer.
--
-- attempt_count is a column and not an in-memory counter because the rate limit
-- it feeds has to survive a restart and hold across replicas.
CREATE TABLE IF NOT EXISTS mfa_challenges (
    id            uuid NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    subject       text NOT NULL,
    org_id        text NOT NULL,                         -- HOST: opaque to identity
    token_expiry  timestamp with time zone NOT NULL,
    attempt_count integer NOT NULL DEFAULT 0,
    expires_at    timestamp with time zone NOT NULL,
    created_at    timestamp with time zone NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS mfa_challenges_expires_at ON mfa_challenges (expires_at);

-- user_totp_credentials: one authenticator-app secret per subject.
--
-- The secret is bytea because a host may seal it (authn.Encrypter). Unlike a
-- session token it cannot be hashed: verifying a code means recomputing it, so
-- the value has to come back out.
--
-- `enrolled` separates a secret that has been SHOWN to someone from one they
-- have proved they can compute codes from. Until the first code verifies, the
-- credential must not gate a login — otherwise a mistyped enrollment locks the
-- account out.
CREATE TABLE IF NOT EXISTS user_totp_credentials (
    id           uuid NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    subject      text NOT NULL UNIQUE,
    secret       bytea NOT NULL,
    enrolled     boolean NOT NULL DEFAULT false,
    created_at   timestamp with time zone NOT NULL DEFAULT now(),
    last_used_at timestamp with time zone
);

-- webauthn_credentials: registered passkeys and security keys.
--
-- id is the authenticator's OWN credential id — raw bytes, not minted here,
-- which is why it is a bytea primary key rather than a uuid.
--
-- sign_count is bigint only because Postgres has no unsigned type; the value is
-- a uint32. With clone_warning it is the clone-detection pair: a counter that
-- fails to advance means the authenticator was duplicated, or is one of the many
-- that never count — which is why it is recorded rather than fatal.
--
-- attestation_object is nullable and kept so a credential can be re-checked
-- against metadata published after it was registered.
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id                   bytea NOT NULL PRIMARY KEY,
    subject              text NOT NULL,
    public_key           bytea NOT NULL,
    attestation_type     text NOT NULL,
    transport            text[] NOT NULL DEFAULT '{}'::text[],
    aaguid               bytea NOT NULL,
    sign_count           bigint NOT NULL DEFAULT 0,
    clone_warning        boolean NOT NULL DEFAULT false,
    flag_user_present    boolean NOT NULL DEFAULT false,
    flag_user_verified   boolean NOT NULL DEFAULT false,
    -- Fixed at registration. No assertion updates it: letting one relabel a
    -- device-bound key as syncable would erase the distinction.
    flag_backup_eligible boolean NOT NULL DEFAULT false,
    flag_backup_state    boolean NOT NULL DEFAULT false,
    attestation_object   bytea,
    created_at           timestamp with time zone NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS webauthn_credentials_subject ON webauthn_credentials (subject);

-- webauthn_sessions: the challenge state held between Begin and Finish.
--
-- UNIQUE on subject, so a second Begin replaces the first: a challenge issued
-- and abandoned must not remain completable alongside a fresh one. session_data
-- is an opaque JSON document — identity keeps the blob alive for the seconds
-- between the two calls and models none of the ceremony, so the WebAuthn library
-- stays the host's choice.
CREATE TABLE IF NOT EXISTS webauthn_sessions (
    id           uuid NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    subject      text NOT NULL UNIQUE,
    session_data jsonb NOT NULL,
    challenge    text NOT NULL UNIQUE,
    expires_at   timestamp with time zone NOT NULL,
    created_at   timestamp with time zone NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS webauthn_sessions_expires_at ON webauthn_sessions (expires_at);

-- invite_kinds: the vocabulary an invite may be issued under ('user',
-- 'domain'). A table and a foreign key rather than a CHECK because the two
-- kinds mean different things at redemption — one binds to a person, the other
-- to an email suffix — and a typo must fail the write, not create a third kind.
CREATE TABLE IF NOT EXISTS invite_kinds (
    id text NOT NULL PRIMARY KEY
);

INSERT INTO invite_kinds (id) VALUES ('user'), ('domain') ON CONFLICT DO NOTHING;

-- org_invites: a pending grant of membership.
--
-- token is stored as-is rather than hashed, which is weaker than sessions and
-- PATs and is worth naming: the lookup is by exact value and could hash, but the
-- token is also this row's unique key and the shape predates that convention.
-- A host tightening it should hash and keep a prefix, as magic_link does.
--
-- binding is what the invite is FOR and its meaning follows kind_id alone: an
-- address for a user invite, a domain suffix for a domain invite.
CREATE TABLE IF NOT EXISTS org_invites (
    id         uuid NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     text NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    kind_id    text NOT NULL REFERENCES invite_kinds (id),
    binding    text NOT NULL,
    -- HOST: opaque here, as everywhere. Identity records which role an invite
    -- confers and never decides what it permits.
    role       text NOT NULL,
    token      text NOT NULL UNIQUE,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL DEFAULT now()
);

-- org_invite_parties: the people attached to an invite — issuer, target,
-- acceptor.
--
-- Split from org_invites because the invite is written before anyone has
-- accepted, and this is where that later fact lands. UNIQUE on invite_id keeps
-- it one-to-one, so every read joins the two and no caller sees half.
--
-- The two CHECKs encode what an acceptance IS: a who and a when together, never
-- one without the other, and never an acceptor who is not the person the invite
-- named.
CREATE TABLE IF NOT EXISTS org_invite_parties (
    id             uuid NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    invite_id      uuid NOT NULL UNIQUE REFERENCES org_invites (id) ON DELETE CASCADE,
    invited_by     uuid NOT NULL REFERENCES users (id),
    target_user_id uuid REFERENCES users (id),
    accepted_by    uuid REFERENCES users (id),
    accepted_at    timestamp with time zone,
    created_at     timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT party_accepted_consistency CHECK (
        (accepted_by IS NULL AND accepted_at IS NULL) OR
        (accepted_by IS NOT NULL AND accepted_at IS NOT NULL)
    ),
    CONSTRAINT party_target_matches_accepter CHECK (
        target_user_id IS NULL OR accepted_by IS NULL OR accepted_by = target_user_id
    )
);

-- preauth_sessions: the server-side half of an in-flight OIDC authorization.
--
-- The reason this table exists is that state, nonce and code_verifier must NOT
-- travel to the browser: each defends a different attack (a forged callback, a
-- replayed ID token, a stolen authorization code) and all three are worthless if
-- the client can read or choose them. The row is the proof this server started
-- this flow.
--
-- org_id is nullable because a signup has no org yet — it is created on the
-- callback. invite_id ties the flow to the invitation that began it, so
-- acceptance is decided from what the server recorded before the redirect rather
-- than from whatever comes back with the callback. It is declared after
-- org_invites for that foreign key's sake. intent ('' or 'intake') is recorded
-- here for the same reason.
CREATE TABLE IF NOT EXISTS preauth_sessions (
    id            uuid NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        text,                                  -- HOST: opaque to identity
    connector_id  text NOT NULL,
    state         text NOT NULL,
    nonce         text NOT NULL,
    code_verifier text NOT NULL,
    expires_at    timestamp with time zone NOT NULL,
    created_at    timestamp with time zone NOT NULL DEFAULT now(),
    is_signup     boolean NOT NULL DEFAULT false,
    invite_id     uuid REFERENCES org_invites (id),
    intent        text NOT NULL DEFAULT '',
    -- The path the identity-aware proxy stopped, held for the round trip.
    return_to     text NOT NULL DEFAULT ''
);

-- org_domain_allowlist: anyone with a verified address at `domain` may join
-- `org_id` with `role`.
--
-- This is the one place membership is granted from something other than an
-- explicit invitation, so the domain fed to it must be one the IdP verified. An
-- address a user typed is a claim, not a fact, and treating it as one turns this
-- table into self-service membership of any org that lists a common provider.
--
-- UNIQUE (org_id, domain) because two rules for one domain would silently pick
-- a role by row order.
CREATE TABLE IF NOT EXISTS org_domain_allowlist (
    id         uuid NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     text NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    domain     text NOT NULL,
    role       text NOT NULL,                            -- HOST: opaque to identity
    -- Nullable so a rule outlives the account that added it; the FK is not
    -- cascading for the same reason.
    created_by uuid REFERENCES users (id),
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    UNIQUE (org_id, domain)
);

-- org_disabled_connectors: a global connector one org has taken off its login
-- page. An opt-out so a new global reaches every org; a row for a global since
-- removed is inert, hence no foreign key to connectors.
CREATE TABLE IF NOT EXISTS org_disabled_connectors (
    org_id       text NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    connector_id text NOT NULL,
    disabled_at  timestamp with time zone NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, connector_id)
);

-- The legal family: published terms, the immutable versions they are cut into,
-- and who agreed to which.
--
-- NOTHING HERE IS ORG-SCOPED and nothing should become so. These are the
-- OPERATOR's own documents: the same words for every tenant, so there is no
-- org_id to filter on. The row-level guard that replaces it is user_id, which a
-- caller must take from the authenticated principal.
--
-- Identity owns the mechanism, not the content. Where the prose comes from — a
-- vendor API, a generator, a file in a binary — is the host's entirely.

-- legal_document_kinds: the vocabulary a login gate may key on.
--
-- Seeded with the schema and not written at runtime, on purpose: a kind that can
-- be invented by a running process is a gate whose meaning can drift under it.
-- A host adds a kind by adding a migration, alongside the document and first
-- version it is introducing.
CREATE TABLE IF NOT EXISTS legal_document_kinds (
    id text NOT NULL PRIMARY KEY
);

-- legal_documents: a document's stable identity across all its versions.
-- kind is UNIQUE, so there is exactly one document per kind and a gate never has
-- to choose between two.
CREATE TABLE IF NOT EXISTS legal_documents (
    id         text NOT NULL PRIMARY KEY,
    kind       text NOT NULL UNIQUE REFERENCES legal_document_kinds (id),
    title      text NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now()
);

-- legal_document_versions: one immutable published cut.
--
-- body is plaintext, alone among the things this schema stores. There is no
-- linkage to protect — these are published terms, identical for everyone and
-- handed to anyone who asks.
--
-- effective_at is what makes future-dating work: a version is invisible to the
-- gate until its date arrives, so nobody is asked to accept text that governs
-- nothing yet.
--
-- Two uniques, doing different jobs. content_hash makes re-publishing unchanged
-- text a no-op. version (the LABEL) is separate so that two DIFFERENT texts
-- minted under one label raise instead of being swallowed as already-done.
CREATE TABLE IF NOT EXISTS legal_document_versions (
    id           text NOT NULL PRIMARY KEY,
    document_id  text NOT NULL REFERENCES legal_documents (id) ON DELETE CASCADE,
    version      text NOT NULL,
    body         text NOT NULL,
    content_hash text NOT NULL,
    effective_at timestamp with time zone NOT NULL,
    created_at   timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT legal_document_versions_hash_key UNIQUE (document_id, content_hash),
    CONSTRAINT legal_document_versions_label_key UNIQUE (document_id, version)
);

CREATE INDEX IF NOT EXISTS idx_legal_document_versions_effective
    ON legal_document_versions (document_id, effective_at DESC);

-- legal_acceptance: the recorded fact that one person agreed to one version.
--
-- Both foreign keys are ON DELETE RESTRICT, unlike most of this schema: an
-- attestation that vanishes when its subject or its text is deleted is not an
-- attestation. Removing either means dealing with the acceptances first.
--
-- context/nonce hold the sealed circumstances of the act (where from, on what,
-- through which surface) — the correlatable half — and are opaque here. One
-- blob rather than a column per field, so capturing another later needs no
-- migration.
CREATE TABLE IF NOT EXISTS legal_acceptance (
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    version_id  text NOT NULL REFERENCES legal_document_versions (id) ON DELETE RESTRICT,
    accepted_at timestamp with time zone NOT NULL DEFAULT now(),
    context     bytea,
    nonce       bytea,
    PRIMARY KEY (user_id, version_id)
);

CREATE INDEX IF NOT EXISTS idx_legal_acceptance_version
    ON legal_acceptance (version_id, accepted_at DESC);

-- access_decisions: one row per authorization decision, permitted or refused,
-- authenticated or not. The audit trail.
--
-- The split between plaintext and sealed is the whole design, and it is a
-- compromise stated honestly rather than a claim of secrecy.
--
-- PLAINTEXT are only the columns a question is asked BY: which subject, which
-- resource, which outcome, when. They are the lookup keys, so encrypting them
-- would mean scanning and decrypting every row to answer anything. This is the
-- documented ceiling — the existence of a row still reveals that a decision
-- occurred for some subject at some time, and encryption protects the
-- ATTRIBUTES, not the fact of the row.
--
-- SEALED is everything else: the reason, the predicate verdicts, the action.
-- One blob rather than a column per field, so recording another attribute later
-- needs no migration. The host supplies the cipher; this layer stores opaque
-- bytes and never sees plaintext or a key.
--
-- correlation_key is stored in the clear ON PURPOSE. It is already a peppered
-- one-way index over the request origin — non-reversible by construction — and
-- grouping repeated attempts is exactly what it is for. Recovering the origin
-- is sealed_origin's job, and requires a recorded unsealing.
--
-- org_id and subject_id are HOST-defined: identity stores them and joins on
-- them but does not define what they mean.
CREATE TABLE IF NOT EXISTS access_decisions (
    id              text NOT NULL PRIMARY KEY,
    -- HOST: the organization the decision was scoped to. NULL for a caller
    -- acting in none, which is a real state rather than missing data.
    org_id          text,
    -- HOST: the internal subject id. NULL for an unauthenticated refusal —
    -- there is no caller to name, and a placeholder would read as one.
    subject_id      text,
    subject_kind    text,
    resource_type   text,
    resource_id     text,
    outcome         text NOT NULL,
    decided_at      timestamp with time zone NOT NULL DEFAULT now(),
    correlation_key text,
    -- The sealed record: reason, ordered predicate verdicts, action.
    content         bytea,
    nonce           bytea,
    -- The sealed request origin, opened only by a recorded break-glass.
    sealed_origin   bytea
);

-- "Why was this subject refused, and when" — the first two standing questions.
CREATE INDEX IF NOT EXISTS idx_access_decisions_subject
    ON access_decisions (subject_id, decided_at DESC);

-- "Who could have reached this resource last month" — the third.
CREATE INDEX IF NOT EXISTS idx_access_decisions_resource
    ON access_decisions (resource_type, resource_id, decided_at DESC);

-- The retention sweep and the correlation rollup both walk this.
CREATE INDEX IF NOT EXISTS idx_access_decisions_at
    ON access_decisions (decided_at);

CREATE INDEX IF NOT EXISTS idx_access_decisions_correlation
    ON access_decisions (correlation_key, decided_at DESC)
    WHERE correlation_key IS NOT NULL;
