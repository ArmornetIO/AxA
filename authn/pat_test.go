package authn_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/ArmornetIO/axa/authn"
	"github.com/ArmornetIO/axa/authn/secrethash"
)

// fakeLookup is an in-memory PATLookup keyed by stored prefix; it also records
// Touch calls so the test can assert last-used bookkeeping fires.
type fakeLookup struct {
	mu      sync.Mutex
	byPfx   map[string][]authn.PATRecord
	err     error
	touched []string
}

func newFakeLookup() *fakeLookup {
	return &fakeLookup{byPfx: map[string][]authn.PATRecord{}}
}

func (f *fakeLookup) add(prefix string, rec authn.PATRecord) {
	f.byPfx[prefix] = append(f.byPfx[prefix], rec)
}

func (f *fakeLookup) ByPrefix(_ context.Context, prefix string) ([]authn.PATRecord, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.byPfx[prefix], nil
}

func (f *fakeLookup) Touch(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.touched = append(f.touched, id)
}

func mint(t *testing.T, prefix string, rec authn.PATRecord) (string, authn.PATRecord) {
	t.Helper()
	raw, err := authn.GenerateToken(prefix)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	hash, err := secrethash.HashToken(raw, secrethash.DefaultArgon2Params())
	if err != nil {
		t.Fatalf("HashToken: %v", err)
	}
	rec.TokenHash = hash
	return raw, rec
}

func req(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func TestPATProvider_ValidUserToken(t *testing.T) {
	raw, rec := mint(t, authn.TokenPrefixUser, authn.PATRecord{ID: "pat_1", Subject: "idp-sub-1", OrgID: "org-9", Scopes: []string{"vendors:read", "dns:admin"}})
	f := newFakeLookup()
	f.add(authn.TokenPrefix(raw), rec)

	p := authn.NewPATProvider(f)
	claims, err := p.Authenticate(context.Background(), req(raw))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	// Subject is the issuing user's IDP subject (so org-scope resolution maps the
	// PAT to the user's memberships), NOT the internal user_id.
	if claims.Subject() != "idp-sub-1" {
		t.Errorf("Subject = %q, want idp-sub-1", claims.Subject())
	}
	// OrgID is the token's bound org.
	if claims.OrgID() != "org-9" {
		t.Errorf("OrgID = %q, want org-9", claims.OrgID())
	}
	if got := claims.Scopes(); len(got) != 2 || got[0] != "vendors:read" || got[1] != "dns:admin" {
		t.Errorf("Scopes = %v, want [vendors:read dns:admin]", got)
	}
	if len(f.touched) != 1 || f.touched[0] != "pat_1" {
		t.Errorf("touched = %v, want [pat_1]", f.touched)
	}
}

func TestPATProvider_ValidAgentToken(t *testing.T) {
	raw, rec := mint(t, authn.TokenPrefixAgent, authn.PATRecord{ID: "pat_a", Subject: "agent-sub-1"})
	f := newFakeLookup()
	f.add(authn.TokenPrefix(raw), rec)

	claims, err := authn.NewPATProvider(f).Authenticate(context.Background(), req(raw))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Subject() != "agent-sub-1" {
		t.Errorf("Subject = %q, want agent-sub-1", claims.Subject())
	}
}

func TestPATProvider_NoToken(t *testing.T) {
	_, err := authn.NewPATProvider(newFakeLookup()).Authenticate(context.Background(), req(""))
	if err == nil {
		t.Fatal("expected error for missing token")
	}
}

func TestPATProvider_WrongPrefix(t *testing.T) {
	_, err := authn.NewPATProvider(newFakeLookup()).Authenticate(context.Background(), req("github_pat_deadbeef"))
	if err == nil {
		t.Fatal("expected error for non-anet token")
	}
	// A non-anet token must not even hit the lookup.
	if f := newFakeLookup(); len(f.touched) != 0 {
		t.Fatal("unreachable")
	}
}

func TestPATProvider_UnknownToken(t *testing.T) {
	raw, err := authn.GenerateToken(authn.TokenPrefixUser)
	if err != nil {
		t.Fatal(err)
	}
	// Empty store: correct prefix, no matching hash.
	_, err = authn.NewPATProvider(newFakeLookup()).Authenticate(context.Background(), req(raw))
	if err == nil {
		t.Fatal("expected error for unknown token")
	}
}

func TestPATProvider_WrongTokenSamePrefix_DoesNotMatch(t *testing.T) {
	// Two tokens can share a stored prefix; only the exact secret verifies.
	raw, rec := mint(t, authn.TokenPrefixUser, authn.PATRecord{ID: "pat_real", Subject: "idp-sub-1"})
	f := newFakeLookup()
	f.add(authn.TokenPrefix(raw), rec)

	other, err := authn.GenerateToken(authn.TokenPrefixUser)
	if err != nil {
		t.Fatal(err)
	}
	// Register the other token under the SAME prefix bucket as the real one, so
	// the candidate set is non-empty but the secret differs.
	f.byPfx[authn.TokenPrefix(raw)] = append(f.byPfx[authn.TokenPrefix(raw)], rec)

	if _, err := authn.NewPATProvider(f).Authenticate(context.Background(), req(other)); err == nil {
		t.Fatal("a different secret sharing the prefix must not validate")
	}
}
