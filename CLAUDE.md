# CLAUDE.md

AxA (Agent x Anything Authentication): a self-hostable identity broker for Go
services. README.md explains the design; these are the rules that cause real
bugs when broken.

## Rules

- **`authn/` and `authz/` are leaves**, each its own module, composed only by
  `access/`. `TestLayering` enforces it; a leaf importing up stops it shipping
  on its own.
- **The host implements the seams.** No package reads a host's environment or
  imports host code; persistence, delivery and domain decisions are interfaces.
- **`internal/dex` is a fork of upstream Dex.** Every change from upstream is
  marked `ARMORNET FORK` with the reason, so a later upstream merge can find it.
  Leave unmarked upstream code as upstream wrote it.
- **The schema is the host's to apply.** `pgstore`, `dex` and `fga` each
  return their DDL from `Schema()` and never migrate.
- **Credentials never fall through.** A provider that recognises its credential
  and rejects it ends the chain; it must not fall back to a weaker provider.

Constructors: a config struct and `New` when there is something to build or
validate; a plain literal when the zero value fails closed
(`authn.Service{Authenticators: …}`); options only for optional knobs; no
package globals.

## Testing

- `.`, `authn`, `authz`, `ginauthz` and `examples/gin-basic` each have their
  own `go.mod`: test each separately. A new nested module needs a `replace` in
  this `go.mod` and `examples/gin-basic`'s, and a line in CI, or its tests
  silently stop running.
- The LDAP connector tests need `DEX_LDAP_HOST` and skip without it.
- Dex's test certificates under `internal/dex/**/testdata` are upstream's public
  fixtures, not secrets.

## Style

Comments say why, never what.
