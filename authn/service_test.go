package authn

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

type stubClaims string

func (c stubClaims) Subject() string  { return string(c) }
func (c stubClaims) OrgID() string    { return "" }
func (c stubClaims) Groups() []string { return nil }

// stub answers with a fixed result and counts how often it was asked.
type stub struct {
	claims Claims
	err    error
	calls  int
}

func (s *stub) Authenticate(context.Context, *http.Request) (Claims, error) {
	s.calls++
	return s.claims, s.err
}

func TestServiceDispatch(t *testing.T) {
	rejected := fmt.Errorf("%w: bad signature", ErrUnauthorized)

	tests := []struct {
		name      string
		providers func(a, b *stub) []Authenticator
		a, b      stub
		wantSub   string
		wantErr   error
		wantBCall int
	}{
		{
			name:      "recognized and rejected ends the chain",
			a:         stub{err: rejected},
			b:         stub{claims: stubClaims("cookie-user")},
			wantErr:   ErrUnauthorized,
			wantBCall: 0,
		},
		{
			name:      "no credential falls through to the next provider",
			a:         stub{err: ErrNoCredential},
			b:         stub{claims: stubClaims("cookie-user")},
			wantSub:   "cookie-user",
			wantBCall: 1,
		},
		{
			name:      "wrapped no credential still falls through",
			a:         stub{err: fmt.Errorf("agent: %w", ErrNoCredential)},
			b:         stub{claims: stubClaims("cookie-user")},
			wantSub:   "cookie-user",
			wantBCall: 1,
		},
		{
			name:      "nothing recognized is unauthorized",
			a:         stub{err: ErrNoCredential},
			b:         stub{err: ErrNoCredential},
			wantErr:   ErrUnauthorized,
			wantBCall: 1,
		},
		{
			name: "nil entries are skipped",
			providers: func(a, b *stub) []Authenticator {
				return []Authenticator{nil, a, nil, b}
			},
			a:         stub{err: ErrNoCredential},
			b:         stub{claims: stubClaims("cookie-user")},
			wantSub:   "cookie-user",
			wantBCall: 1,
		},
		{
			name:      "first success wins without asking later providers",
			a:         stub{claims: stubClaims("agent")},
			b:         stub{claims: stubClaims("cookie-user")},
			wantSub:   "agent",
			wantBCall: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, b := tc.a, tc.b
			providers := []Authenticator{&a, &b}
			if tc.providers != nil {
				providers = tc.providers(&a, &b)
			}
			svc := &Service{Authenticators: providers}

			claims, err := svc.Authenticate(context.Background(), httptest.NewRequest(http.MethodGet, "/", nil))

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				if claims != nil {
					t.Fatalf("claims = %v on error", claims)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				if claims.Subject() != tc.wantSub {
					t.Fatalf("subject = %q, want %q", claims.Subject(), tc.wantSub)
				}
			}
			if b.calls != tc.wantBCall {
				t.Fatalf("second provider called %d times, want %d", b.calls, tc.wantBCall)
			}
		})
	}
}

func TestServiceZeroValueAuthenticatesNobody(t *testing.T) {
	var svc Service
	if _, err := svc.Authenticate(context.Background(), httptest.NewRequest(http.MethodGet, "/", nil)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}
