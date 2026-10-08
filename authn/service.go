package authn

import (
	"context"
	"errors"
	"net/http"
)

// ErrNoCredential is an authenticator's answer to a request that carries
// nothing it recognizes. It is the only error that lets Service try the next.
var ErrNoCredential = errors.New("authn: no credential for this authenticator")

// Service authenticates a request against an ordered list of authenticators.
//
// Order is authority-descending: a service agent's token is checked before a
// PAT or a session, so a request that could satisfy two is treated as the more
// privileged thing it actually is.
//
// An authenticator that recognizes its credential and rejects it ENDS the chain. A
// forged agent token or a revoked PAT must never fall through to a session
// cookie riding on the same request — that would let the weaker credential
// launder a request the stronger one refused. Only ErrNoCredential continues.
//
// The zero value authenticates nobody.
type Service struct {
	Authenticators []Authenticator
}

func (s *Service) Authenticate(ctx context.Context, r *http.Request) (Claims, error) {
	for _, p := range s.Authenticators {
		if p == nil {
			continue
		}
		claims, err := p.Authenticate(ctx, r)
		if errors.Is(err, ErrNoCredential) {
			continue
		}
		return claims, err
	}
	return nil, ErrUnauthorized
}
