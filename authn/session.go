package authn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"
)

// SessionClaims shares PATClaims' method set; OrgID is honoured downstream only
// while the user is still a member.
type SessionClaims struct {
	subject string
	orgID   string
}

func (c SessionClaims) Subject() string  { return c.subject }
func (c SessionClaims) OrgID() string    { return c.orgID }
func (c SessionClaims) Groups() []string { return nil }

// SessionRecord keeps no upstream token, nor its hash: nothing after the callback
// needs one, and a leak would.
type SessionRecord struct {
	ID          string // opaque session id; NOT the cookie value
	Subject     string
	OrgID       string
	ConnectorID string // lets a signed-in person re-authorize without a picker
	ExpiresAt   time.Time
}

// SessionLookup is read-only, so an authenticating caller cannot delete.
type SessionLookup interface {
	// ByTokenHash takes the digest, so no implementation can log the raw token.
	ByTokenHash(ctx context.Context, tokenHash string) (SessionRecord, error)
}

// SessionStore is the full lifecycle: what a host needs to sign someone in and
// out, not merely to validate.
type SessionStore interface {
	SessionLookup

	// Create persists a session. rec.Token is the raw secret handed to the
	// browser; implementations MUST store only its digest.
	Create(ctx context.Context, rec SessionRecord, token string) error
	// Delete ends the session a raw token names.
	Delete(ctx context.Context, token string) error
	// Purge removes expired sessions.
	Purge(ctx context.Context) error

	// DeleteBySubject ends every session for an IDP subject — the back-channel
	// logout path when no sid is present.
	DeleteBySubject(ctx context.Context, subject string) error
	// DeleteBySubjectAndSID returns rows removed, so a miss can fall back.
	DeleteBySubjectAndSID(ctx context.Context, subject, sid string) (int64, error)
	// SeatOrg puts the org-less session a raw token names into orgID, for the
	// org its holder just created. A session already in an org is left alone.
	SeatOrg(ctx context.Context, token, orgID string) error
}

// Encrypter seals readable secrets (TOTP seeds) with the host's key. Nil stores
// them as-is, deliberately: better than no working login.
type Encrypter interface {
	Wrap(plaintext []byte) ([]byte, error)
	Unwrap(ciphertext []byte) ([]byte, error)
}

// SessionProvider stores only the token's SHA-256: no usable credential in the
// DB, and a deterministic digest is one indexed lookup.
type SessionProvider struct {
	lookup     SessionLookup
	cookieName string
	now        func() time.Time
}

// NewSessionProvider takes cookieName: its prefix and mirrors are host policy.
func NewSessionProvider(lookup SessionLookup, cookieName string) *SessionProvider {
	return &SessionProvider{lookup: lookup, cookieName: cookieName, now: time.Now}
}

// HashSessionToken is SHA-256, not argon2: a random token has nothing to slow
// down, and argon2 per request only buys latency.
func HashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Authenticate reads the cookie; hosts with their own carry use ValidateToken.
func (p *SessionProvider) Authenticate(ctx context.Context, r *http.Request) (SessionClaims, error) {
	cookie, err := r.Cookie(p.cookieName)
	if err != nil || cookie.Value == "" {
		return SessionClaims{}, fmt.Errorf("%w: no session cookie", ErrUnauthorized)
	}
	return p.ValidateToken(ctx, cookie.Value)
}

// ValidateToken resolves a raw session token to claims. Every failure wraps
// ErrUnauthorized and says nothing a caller could enumerate with.
func (p *SessionProvider) ValidateToken(ctx context.Context, token string) (SessionClaims, error) {
	if token == "" {
		return SessionClaims{}, fmt.Errorf("%w: no session token", ErrUnauthorized)
	}

	rec, err := p.lookup.ByTokenHash(ctx, HashSessionToken(token))
	if err != nil {
		return SessionClaims{}, fmt.Errorf("%w: session not found", ErrUnauthorized)
	}

	// Checked here and not left to the query so that expiry is enforced even by
	// a lookup implementation that forgot to filter on it.
	if p.now().After(rec.ExpiresAt) {
		return SessionClaims{}, fmt.Errorf("%w: session expired", ErrUnauthorized)
	}

	return SessionClaims{subject: rec.Subject, orgID: rec.OrgID}, nil
}
