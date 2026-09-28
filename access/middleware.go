package access

import (
	"context"
	"net/http"
	"time"
)

type ctxKey struct{}

// WithClaims returns ctx carrying verified assertion claims.
func WithClaims(ctx context.Context, c Claims) context.Context {
	return context.WithValue(ctx, ctxKey{}, c)
}

// ClaimsFrom returns the claims Middleware verified, if any.
func ClaimsFrom(ctx context.Context) (Claims, bool) {
	c, ok := ctx.Value(ctxKey{}).(Claims)
	return c, ok
}

// Middleware never redirects to login: no assertion means it bypassed the
// access path. exempt paths match exactly, for kubelet probes only.
func Middleware(keys *KeySet, aud string, exempt ...string) func(http.Handler) http.Handler {
	skip := make(map[string]bool, len(exempt))
	for _, p := range exempt {
		skip[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if skip[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}
			c, err := keys.Verify(r.Header.Get(Header), aud, time.Now())
			if err != nil {
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), c)))
		})
	}
}
