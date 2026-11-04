# identity

A self-hostable identity broker for Go services: an embedded Dex that brokers
upstream OIDC, SAML and LDAP sign-in, OpenFGA for relationship-based
authorization, and the credentials a service issues itself (personal access
tokens, agent tokens, single-use magic links, TOTP and WebAuthn MFA). It is what
[Armornet](https://armornet.io) runs, as a library: **issue** identity, **relate**
principals to resources, **enforce** access.

Module `github.com/ArmornetIO/identity`. The host application imports it; it
never imports the host. Persistence, delivery and domain decisions are
interfaces the host implements.

## Status

Alpha, versioned `0.0.x`: no compatibility promise between releases, so pin an
exact version. What holds regardless is what the tests enforce: `authn` and
`authz` import nothing else from this module (`TestLayering`), a recognised but
invalid credential never falls through to a weaker one, and stored client
secrets are argon2id hashes.

The embedded Dex is a fork of Dex v2.45.1 in `internal/dex`: it adds token
revocation, RP-initiated and back-channel logout, the `client_credentials`
grant, hashed client secrets and sealed claims at rest. Each change is marked
`ARMORNET FORK`.

## Design rule

**The module defines seams; the host implements them.** Persistence, delivery,
and domain decisions are reached only through the interfaces defined in each
package (e.g. `PATLookup`, `MagicLinkStore`, `Notifier`, `Resolver`). Domain
logic that names a host's own concepts stays in the host.

## Layout

| Path | What it owns |
|------|--------------|
| `broker.go`, `clients.go`, `connectors.go` | Root contracts: `Broker`, `ClientStore`, `ConnectorStore`/`Connector` (upstream IdP CRUD, backend-agnostic). |
| `authn/` | Request authentication: `Claims`, `Provider`, and `Service`, the ordered provider chain (below). Credentials the host itself issues & verifies — **not** federated OIDC: `AgentTokenProvider`, `PATProvider`, `MagicLinkProvider`. `token.go` (`GenerateToken`, prefixes), `scopes.go`. |
| `authz/` | Authorization: `Service` (the `access` decision pipeline assembled from host ports), `Grapher` (Checker → graph axis), `Checker`, `Tuple`, mapper, `FGAClientIface`. Tenant-agnostic (tenancy is a host boundary). |
| `access/` | Composes `authn` and `authz` into one decision per request, plus short-lived signed assertions for a proxy to check. |
| `dex/` | The embedded Dex broker, configured by a `Config` struct (DB URL, connectors, hasher injected — no env reads except the secrets seam). |
| `fga/` | OpenFGA server/client wiring. |
| `ginauthz/` | Gin middleware adapter for the checker. |
| `authn/secrethash/` | argon2id token hashing (`HashToken`/`VerifyToken`) + params. |
| `pgstore/` | Postgres implementations of identity-owned persistence seams (see below). Uses a **host-injected** `*sql.DB`; imports no driver. |
| `service/` | Assembly/health entry points. |
| `web/` | The browser sign-in flow: `/api/auth/*` (authorize, callback, session, logout, back-channel logout, MFA) over the `authn` stores. Plain `net/http`: `Handler()` for a mux, `Routes()` for a router that registers per pattern. `ts/` is its browser client. |
| `examples/` | [`gin-basic`](examples/gin-basic) — a Gin API behind this sign-in, runnable against one Postgres. [`custom-login`](examples/custom-login) — a designed login UI over `ts/`. |
| `internal/dex/` | The Dex fork. Upstream code except where marked `ARMORNET FORK`. |

## Credential providers (`authn/`)

Every provider implements `Provider` — `Validate(ctx, r) → Claims` — and a host
lists them, most privileged first, in an `authn.Service`. A provider returns
`ErrNoCredential` for a request it does not recognize, and the chain tries the
next. Once it recognizes its credential, any rejection is final: a bad token
never falls through to a weaker credential on the same request. Persistence is a
seam the host fills.

### PAT — `authn/pat.go`
Personal access tokens (`anet_user_` / `anet_agent_` prefixes), argon2id-hashed,
prefix-narrowed lookup via the host's `PATLookup`.

### Magic link — `authn/magiclink.go`
Short-lived, **single-use, scoped** access links for a third party (e.g. a vendor
filling out an assessment) who can't do federated login. **Not** a general
passwordless fallback — it grants scoped access to one object, enforced by FGA.

- **`MagicLinkProvider`** — `Request(ctx, email)` (resolve → mint token → persist
  hash → deliver; **enumeration-safe**: unknown emails send nothing) and
  `Redeem(ctx, token)` (verify → atomic single-use consume → return `Grant`).
  Token prefix `anet_magic_`; default TTL 15m.
- **`Grant{Subject, OrgID, ObjectType, ObjectID, Relation}`** — opaque to the
  module. The host interprets it: write an FGA tuple `Relation` on
  `ObjectType:ObjectID` for `Subject`, then mint a scoped session. `Subject` is a
  host-minted principal id, **never** an email.
- **Seams the host implements:**
  - `Notifier` — delivery. The module builds the token + link; the host chooses
    the channel.
  - `Resolver` — domain. Given an email, does it map to a scoped `Grant`? The
    module has no concept of assessments or assignees — the host answers.
  - `MagicLinkStore` — persistence (`Create` / `ByPrefix` / atomic `Consume`).
- **`pgstore.MagicLinkStore`** — the Postgres implementation of `MagicLinkStore`
  over the identity-owned `magic_link` table (host injects `*sql.DB`).

## Schema: identity owns the code, the host owns the tables

`pgstore` takes an opened `*sql.DB` and runs queries. It never migrates, and
there is no migrator in this module. Creating and versioning the tables below is
the host's job.

That split is deliberate rather than unfinished. A library that reshapes a
database it was handed fights whatever the host already uses to manage schema —
which is why the embedded Dex and OpenFGA run with their own migrators
disabled, and a host applies their tables through its own migrations instead.
Identity follows the same rule for its own tables.

| Table | Used by |
|---|---|
| `users` | `pgstore.UserStore` → `authn.UserStore` |
| `organizations` | `pgstore.OrgStore` → `authn.OrgStore` |
| `organization_users` | `pgstore.UserStore` → `authn.UserStore` |
| `sessions` | `pgstore.SessionStore` → `authn.SessionStore` |
| `magic_link` | `pgstore.MagicLinkStore` → `authn.MagicLinkStore` |
| `personal_access_tokens` | `pgstore.PATStore` → `authn.PATStore` (and `authn.PATLookup`) |
| `preauth_sessions` | `pgstore.PreAuthStore` → `authn.PreAuthStore` |
| `mfa_challenges` | `pgstore.MFAChallengeStore` → `authn.MFAChallengeStore` |
| `user_totp_credentials` | `pgstore.TOTPStore` → `authn.TOTPStore` |
| `webauthn_credentials` | `pgstore.WebAuthnCredentialStore` → `authn.WebAuthnCredentialStore` |
| `webauthn_sessions` | `pgstore.WebAuthnSessionStore` → `authn.WebAuthnSessionStore` |
| `invite_kinds`, `org_invites`, `org_invite_parties` | `pgstore.InviteStore` → `authn.InviteStore` |
| `org_domain_allowlist` | `pgstore.DomainAllowlistStore` → `authn.DomainAllowlistStore` |
| `legal_document_kinds`, `legal_documents`, `legal_document_versions`, `legal_acceptance` | `pgstore.LegalStore` → `authn.LegalStore` |

A host's own tables may carry foreign keys into `users` and `organizations`.
That is expected: identity owns the definition, the
host applies it into the host's database, and the tables sit alongside each
other. What identity must not acquire is the reverse — a reference from these
tables out into anything a host defines.

`pgstore.Schema()` returns the reference DDL ([`pgstore/schema.sql`](pgstore/schema.sql))
so a host can execute it, diff against it, or fold it into its own migrations.
`dex.Schema()` and `fga.Schema()` do the same for the embedded Dex and OpenFGA
tables, whose own migrators are disabled — without them a fresh database has
nowhere for either engine to write.
Every statement is `IF NOT EXISTS`, so running it is safe — but it will not
upgrade a table that already exists in an older shape.

Two things a host should know before wiring these up:

- **`org_id` is opaque here.** Identity treats it as a scoping string and
  nothing more. A host may point a foreign key at its own tenant table.
  Nothing in this module requires that, and `sessions.org_id` is nullable
  because a session can legitimately exist before its owner belongs to anything.
- **Encryption is yours.** The upstream tokens on a session are `bytea` and are
  sealed by an `authn.Encrypter` the host supplies, because the key is the
  host's. Supply none and they are stored as-is.

## Develop

`authn`, `authz` and `ginauthz` are modules of their own, so `./...` from the
root does not reach them:

```sh
for m in . authn authz ginauthz; do (cd $m && go vet ./... && go test ./...); done
```

The LDAP connector's tests need an LDAP server and skip without one.

## Security

Report a vulnerability privately: see [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
