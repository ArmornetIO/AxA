package authn_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ArmornetIO/identity/authn"
)

type stubSessionLookup struct {
	rec authn.SessionRecord
	err error
	// got records the digest the provider asked for.
	got *string
}

func (s stubSessionLookup) ByTokenHash(_ context.Context, hash string) (authn.SessionRecord, error) {
	if s.got != nil {
		*s.got = hash
	}
	return s.rec, s.err
}

const testToken = "0f9a1c3e-1111-2222-3333-444455556666"

func liveRecord() authn.SessionRecord {
	return authn.SessionRecord{
		ID:        "sess-1",
		Subject:   "dex|alice",
		OrgID:     "org-1",
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

func TestValidateToken_Success(t *testing.T) {
	p := authn.NewSessionProvider(stubSessionLookup{rec: liveRecord()}, "__Host-x")
	claims, err := p.ValidateToken(context.Background(), testToken)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.Subject() != "dex|alice" || claims.OrgID() != "org-1" {
		t.Errorf("claims = %q/%q", claims.Subject(), claims.OrgID())
	}
}

// The raw token must not cross the persistence seam — an implementation that
// received it could log or store it, which is the whole thing hashing prevents.
func TestValidateToken_LookupSeesOnlyTheDigest(t *testing.T) {
	var got string
	p := authn.NewSessionProvider(stubSessionLookup{rec: liveRecord(), got: &got}, "__Host-x")
	if _, err := p.ValidateToken(context.Background(), testToken); err != nil {
		t.Fatal(err)
	}
	if got == testToken {
		t.Fatal("lookup received the raw token")
	}
	if got != authn.HashSessionToken(testToken) {
		t.Errorf("lookup got %q, want the token's digest", got)
	}
}

// Expiry is re-checked in the provider so a lookup that forgot to filter on it
// still cannot return a live session.
func TestValidateToken_ExpiredIsRejected(t *testing.T) {
	rec := liveRecord()
	rec.ExpiresAt = time.Now().Add(-time.Minute)
	p := authn.NewSessionProvider(stubSessionLookup{rec: rec}, "__Host-x")
	if _, err := p.ValidateToken(context.Background(), testToken); !errors.Is(err, authn.ErrUnauthorized) {
		t.Fatalf("got %v, want ErrUnauthorized", err)
	}
}

func TestValidateToken_Rejects(t *testing.T) {
	cases := map[string]struct {
		lookup stubSessionLookup
		token  string
	}{
		"empty token":     {stubSessionLookup{rec: liveRecord()}, ""},
		"no such session": {stubSessionLookup{err: errors.New("no rows")}, testToken},
	}
	for name, tc := range cases {
		p := authn.NewSessionProvider(tc.lookup, "__Host-x")
		if _, err := p.ValidateToken(context.Background(), tc.token); !errors.Is(err, authn.ErrUnauthorized) {
			t.Errorf("%s: got %v, want ErrUnauthorized", name, err)
		}
	}
}

func TestValidate_ReadsTheNamedCookie(t *testing.T) {
	p := authn.NewSessionProvider(stubSessionLookup{rec: liveRecord()}, "__Host-x")

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := p.Authenticate(context.Background(), r); !errors.Is(err, authn.ErrUnauthorized) {
		t.Errorf("no cookie: got %v, want ErrUnauthorized", err)
	}

	r.AddCookie(&http.Cookie{Name: "__Host-x", Value: testToken})
	claims, err := p.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Subject() != "dex|alice" {
		t.Errorf("subject = %q", claims.Subject())
	}
}
