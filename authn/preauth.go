package authn

import (
	"context"
	"errors"
	"time"
)

// ErrNoPreAuthSession is returned when a pre-auth id names nothing live.
// Unknown and expired are one error: a callback arriving against either is a
// flow that cannot be completed, and telling them apart would let someone probe
// which authorization requests were ever started.
var ErrNoPreAuthSession = errors.New("authn: no such pre-auth session")

// PreAuthSession is the server-side half of an OIDC authorization request,
// held for the seconds between the redirect out and the callback back.
//
// It exists so State, Nonce and CodeVerifier never travel to the browser. Each
// defends a different attack — state a forged callback, nonce a replayed ID
// token, the verifier a stolen authorization code — and all three are worthless
// if the client can read or choose them. The row IS the proof that this server
// started this flow.
type PreAuthSession struct {
	ID           string
	OrgID        string // empty on signup: the org does not exist until the callback
	ConnectorID  string
	State        string
	Nonce        string
	CodeVerifier string
	IsSignup     bool
	// InviteID ties the flow to the invite that started it, so acceptance is
	// decided from what the server recorded before the redirect rather than from
	// whatever comes back with the callback.
	InviteID string
	// Intent is what the person asked to do on returning ('' or "intake"),
	// recorded here for the same reason as InviteID.
	Intent string
	// ReturnTo is the path the identity-aware proxy stopped, kept here rather
	// than in the callback URL so the browser cannot choose where it lands.
	ReturnTo  string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// PreAuthStore persists pre-authorization sessions.
//
// There is no Consume: unlike a magic link, the callback that reads one is
// already bound to it by the state parameter, and the flow deletes it once the
// exchange succeeds.
type PreAuthStore interface {
	Create(ctx context.Context, p PreAuthSession) error
	// Get returns the live session, or ErrNoPreAuthSession.
	Get(ctx context.Context, id string) (PreAuthSession, error)
	Delete(ctx context.Context, id string) error
	Purge(ctx context.Context) error
}
