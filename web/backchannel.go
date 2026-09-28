package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// BackchannelLogoutEventURI is the event type required in a logout_token's events claim.
// Per OIDC Back-Channel Logout 1.0 §4.1.
const BackchannelLogoutEventURI = "http://schemas.openid.net/event/backchannel-logout"

// LogoutTokenClaims holds the validated claims extracted from a Dex back-channel logout_token.
type LogoutTokenClaims struct {
	Subject string
	JTI     string
	SID     string    // empty means subject-wide logout; non-empty enables per-session targeting
	Expiry  time.Time // bounds the JTI replay window
}

// LogoutTokenVerifier validates incoming back-channel logout_token JWTs issued by Dex.
type LogoutTokenVerifier interface {
	ValidateLogoutToken(ctx context.Context, raw string) (*LogoutTokenClaims, error)
}

// JTIStore tracks logout_token JTI nonces to prevent replay attacks.
// Implementations must be safe for concurrent use.
type JTIStore interface {
	// HasSeen returns true if jti was already presented.
	HasSeen(ctx context.Context, jti string) (bool, error)
	// Record marks jti as seen. expiry is when the record may be discarded.
	Record(ctx context.Context, jti string, expiry time.Time) error
}

// oidcLogoutTokenVerifier validates logout_token JWTs using a pre-configured OIDC verifier.
type oidcLogoutTokenVerifier struct {
	v *oidc.IDTokenVerifier
}

// NewLogoutTokenVerifierFromProvider requires clientID: without it go-oidc skips
// the audience check and accepts any JWT.
func NewLogoutTokenVerifierFromProvider(provider *oidc.Provider, clientID string) (LogoutTokenVerifier, error) {
	if clientID == "" {
		return nil, errors.New("NewLogoutTokenVerifierFromProvider: clientID must not be empty")
	}
	return &oidcLogoutTokenVerifier{
		v: provider.Verifier(&oidc.Config{ClientID: clientID}),
	}, nil
}

func (lv *oidcLogoutTokenVerifier) ValidateLogoutToken(ctx context.Context, raw string) (*LogoutTokenClaims, error) {
	return ValidateLogoutToken(ctx, lv.v, raw)
}

// ValidateLogoutToken is the shared validation logic used by both oidcLogoutTokenVerifier
// and OIDCDexClient.ValidateLogoutToken. Exported so the Dex client can delegate here.
func ValidateLogoutToken(ctx context.Context, verifier *oidc.IDTokenVerifier, raw string) (*LogoutTokenClaims, error) {
	// go-oidc enforces: valid signature, matching issuer, matching audience (ClientID set), not expired.
	tok, err := verifier.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("logout_token: JWT verification failed: %w", err)
	}

	var allClaims map[string]json.RawMessage
	if err := tok.Claims(&allClaims); err != nil {
		return nil, fmt.Errorf("logout_token: failed to unmarshal claims: %w", err)
	}

	// Trap 2: spec §4.1 explicitly forbids nonce in a logout_token.
	if _, ok := allClaims["nonce"]; ok {
		return nil, errors.New("logout_token: nonce claim is forbidden in logout tokens")
	}

	// Trap 3: events must be a JSON object containing the exact event URI as a key.
	// A non-object value (string, array) or wrong URI key must be rejected.
	eventsRaw, ok := allClaims["events"]
	if !ok {
		return nil, errors.New("logout_token: missing events claim")
	}
	var events map[string]json.RawMessage
	if err := json.Unmarshal(eventsRaw, &events); err != nil {
		return nil, fmt.Errorf("logout_token: events must be a JSON object: %w", err)
	}
	if _, ok := events[BackchannelLogoutEventURI]; !ok {
		return nil, fmt.Errorf("logout_token: events must contain key %q", BackchannelLogoutEventURI)
	}

	var extras struct {
		JTI string `json:"jti"`
		SID string `json:"sid"`
	}
	_ = tok.Claims(&extras)
	if extras.JTI == "" {
		return nil, errors.New("logout_token: missing jti claim")
	}

	return &LogoutTokenClaims{
		Subject: tok.Subject,
		JTI:     extras.JTI,
		SID:     extras.SID,
		Expiry:  tok.Expiry,
	}, nil
}

// MemJTIStore is a thread-safe in-memory JTI nonce store for single-instance deployments.
// Multi-instance deployments should use a Postgres-backed store with a used_jtis table.
type MemJTIStore struct {
	mu      sync.Mutex
	entries map[string]time.Time // jti → expiry
}

// NewMemJTIStore returns an empty MemJTIStore.
func NewMemJTIStore() *MemJTIStore {
	return &MemJTIStore{entries: make(map[string]time.Time)}
}

func (s *MemJTIStore) HasSeen(_ context.Context, jti string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.entries[jti]
	if !ok {
		return false, nil
	}
	if time.Now().After(exp) {
		delete(s.entries, jti)
		return false, nil
	}
	return true, nil
}

func (s *MemJTIStore) Record(_ context.Context, jti string, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[jti] = expiry
	return nil
}
