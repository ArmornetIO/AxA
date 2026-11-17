package authn

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ArmornetIO/axa/authn/secrethash"
)

// ErrUnauthorized is returned when a PAT is absent, malformed, unknown, or
// fails verification. Hosts wrap this in their own auth error as needed.
var ErrUnauthorized = errors.New("authn: unauthorized")

// PATClaims is the validated identity carried by a personal access token.
// Its method set is a superset of Claims (Subject/OrgID/Groups)
// and of the scope interface (Scopes), so a host adapter can return it directly
// through those interfaces via structural typing.
//
// Subject is the issuing user's IDP subject — the SAME identifier the user's
// session carries — so downstream org-scope resolution maps a PAT to exactly the
// issuing user's org membership and FGA groups (never more). OrgID is the org
// the token was bound to at creation, honoured downstream only if the user is
// still a member (fail-closed).
type PATClaims struct {
	subject string
	orgID   string
	scopes  []string
}

func (c PATClaims) Subject() string  { return c.subject }
func (c PATClaims) OrgID() string    { return c.orgID }
func (c PATClaims) Groups() []string { return nil }
func (c PATClaims) Scopes() []string { return c.scopes }

// PATRecord is the minimal stored token data the provider needs to verify a
// bearer and construct claims. The host maps its persistence rows to this,
// resolving UserID → Subject (the issuing user's IDP subject) at lookup time.
// Expiry and revocation are enforced by the lookup: ByPrefix MUST NOT return
// expired or revoked tokens.
type PATRecord struct {
	ID        string // opaque token id, echoed back to Touch
	Subject   string // issuing user's IDP subject → PATClaims.Subject()
	OrgID     string // token's bound org → PATClaims.OrgID()
	TokenHash string // argon2id PHC-encoded hash of the raw token
	Scopes    []string
}

// PATLookup is the persistence seam between the identity provider and the host
// datastore. The identity module never imports the store; the host implements
// this interface over it.
type PATLookup interface {
	// ByPrefix returns the (small) candidate set of non-expired, non-revoked
	// tokens whose stored prefix matches. The provider runs a constant-time
	// argon2 verify against each candidate.
	ByPrefix(ctx context.Context, prefix string) ([]PATRecord, error)
	// Touch records that the token with the given id was just used. It is
	// fire-and-forget from the provider's perspective: implementations should
	// not block request handling on it.
	Touch(id string)
}

// ErrNoPAT is returned when a token id names nothing the caller may act on.
// Revoking an already-revoked token yields it too: there is nothing left to do,
// and reporting success would imply an action that did not happen.
var ErrNoPAT = errors.New("authn: no such personal access token")

// PATToken is a whole stored token — what a management screen lists, as opposed
// to PATRecord, which is the projection the authentication path needs.
//
// UserID is the ISSUER's internal id, not their IDP subject. The distinction
// matters and is why the two types exist: this table is keyed on the internal
// id, while authentication must resolve through to the subject so a PAT lands
// on exactly the org membership and groups the issuing user's own session would.
//
// The three nullable times are pointers because their absence is meaningful and
// distinct — never expires, never used, not revoked — and a zero time.Time
// would collapse all three into a date in year 1.
type PATToken struct {
	ID         string
	UserID     string
	OrgID      string
	Name       string
	Prefix     string
	TokenHash  string
	Scopes     []string
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// PATStore is the full lifecycle behind the provider's read-only seam: what a
// host needs to issue and withdraw tokens, not merely to verify them.
type PATStore interface {
	PATLookup

	// Create persists an already-hashed token. The raw secret never crosses this
	// boundary — the caller mints it, shows it once, and stores only the hash.
	Create(ctx context.Context, tok PATToken) (PATToken, error)
	// ListByUser returns a user's tokens, newest first. includeRevoked exists
	// because a revoked token is still an audit fact worth showing.
	ListByUser(ctx context.Context, userID string, includeRevoked bool) ([]PATToken, error)
	// Revoke withdraws one token, scoped by its owner so one user cannot revoke
	// another's. Returns ErrNoPAT when nothing live matched.
	Revoke(ctx context.Context, userID, id string) error
}

// PATProvider validates requests bearing an Armornet personal access token
// (prefix anet_user_ or anet_agent_). Lookups are pre-filtered by prefix so
// argon2id verification only runs against a tiny candidate set.
type PATProvider struct {
	lookup PATLookup
}

// NewPATProvider constructs a PAT provider backed by lookup.
func NewPATProvider(lookup PATLookup) *PATProvider {
	return &PATProvider{lookup: lookup}
}

// Authenticate extracts the bearer token, narrows candidates by prefix, and returns
// PATClaims on the first argon2id match. On any failure it returns a zero
// PATClaims and an error wrapping ErrUnauthorized.
func (p *PATProvider) Authenticate(ctx context.Context, r *http.Request) (PATClaims, error) {
	raw := bearerToken(r)
	if raw == "" || (!strings.HasPrefix(raw, TokenPrefixUser) && !strings.HasPrefix(raw, TokenPrefixAgent)) {
		return PATClaims{}, ErrUnauthorized
	}

	candidates, err := p.lookup.ByPrefix(ctx, TokenPrefix(raw))
	if err != nil {
		return PATClaims{}, fmt.Errorf("%w: lookup: %v", ErrUnauthorized, err)
	}

	for _, tok := range candidates {
		ok, err := secrethash.VerifyToken(raw, tok.TokenHash)
		if err != nil || !ok {
			continue
		}
		p.lookup.Touch(tok.ID)
		return PATClaims{subject: tok.Subject, orgID: tok.OrgID, scopes: tok.Scopes}, nil
	}

	return PATClaims{}, ErrUnauthorized
}

// bearerToken extracts the token value from an Authorization: Bearer header.
// Returns "" when the header is absent or not a Bearer token.
func bearerToken(r *http.Request) string {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return ""
	}
	return token
}
