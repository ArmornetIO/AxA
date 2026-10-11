package authn

import (
	"context"
	"net/http"
	"strings"
)

// Claims carries the validated identity from a successful auth check.
type Claims interface {
	Subject() string
	// OrgID returns the organization identifier for multi-tenant scoping.
	// Returns empty string for providers that do not carry org context.
	OrgID() string
	// Groups returns the IDP group memberships embedded in the token.
	// Returns nil or empty when the token carries no group claim.
	Groups() []string
}

// Authenticator validates an incoming HTTP request and returns Claims on success.
// Implementations should return ErrUnauthorized (or wrap it) on failure so
// callers can distinguish auth failures from internal errors.
type Authenticator interface {
	Authenticate(ctx context.Context, r *http.Request) (Claims, error)
}

// AuthenticatorFunc adapts a function to the Authenticator interface.
type AuthenticatorFunc func(ctx context.Context, r *http.Request) (Claims, error)

func (f AuthenticatorFunc) Authenticate(ctx context.Context, r *http.Request) (Claims, error) {
	return f(ctx, r)
}

type contextKey struct{}

// Middleware validates each request with p, attaches Claims to the context on
// success, and responds 401 on any failure. Downstream handlers can retrieve
// Claims via FromContext.
func Middleware(p Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := p.Authenticate(r.Context(), r)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), contextKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// FromContext retrieves Claims attached by Middleware. Returns false if the
// request was not processed by an auth middleware.
func FromContext(ctx context.Context) (Claims, bool) {
	c, ok := ctx.Value(contextKey{}).(Claims)
	return c, ok
}

// BearerToken extracts the token value from an Authorization: Bearer header.
// Returns an empty string when the header is absent or not a Bearer token.
func BearerToken(r *http.Request) string {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return ""
	}
	return token
}
