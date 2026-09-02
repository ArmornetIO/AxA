package authn

import (
	"context"
	"errors"
	"time"
)

// ErrNoAllowlistEntry is returned when no rule covers the (org, domain) asked
// about. It is the ordinary answer on the join path, not a failure: most people
// signing in are not covered by one.
var ErrNoAllowlistEntry = errors.New("authn: no domain allowlist entry")

// DomainAllowlistEntry is one rule saying that anyone with a verified address at
// Domain may join OrgID with Role.
//
// This is the one place identity grants membership from something other than an
// explicit invitation, so the input has to be a domain the IdP verified — an
// address a user typed is a claim, not a fact, and treating it as one turns this
// table into self-service membership of any org that lists a common provider.
type DomainAllowlistEntry struct {
	ID     string
	OrgID  string
	Domain string
	Role   string
	// CreatedBy is the internal id of whoever added the rule. Empty when the
	// rule outlived the account that made it.
	CreatedBy string
	CreatedAt time.Time
}

// DomainAllowlistStore persists email-domain auto-join rules.
type DomainAllowlistStore interface {
	Add(ctx context.Context, entry DomainAllowlistEntry) (DomainAllowlistEntry, error)
	ListByOrg(ctx context.Context, orgID string) ([]DomainAllowlistEntry, error)
	// Remove is scoped by org so one tenant cannot delete another's rule.
	Remove(ctx context.Context, id, orgID string) error
	// Match answers whether one org admits one domain, returning
	// ErrNoAllowlistEntry when it does not. Exact match only — no suffix logic
	// lives here, because "ends with example.com" also ends with
	// notexample.com, and that is a decision the caller must make explicitly.
	Match(ctx context.Context, orgID, domain string) (DomainAllowlistEntry, error)
}
