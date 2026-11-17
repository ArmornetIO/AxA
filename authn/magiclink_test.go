package authn_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArmornetIO/axa/authn"
)

type memMagicStore struct {
	mu   sync.Mutex
	recs map[string]authn.MagicLinkRecord
	used map[string]bool
}

func newMemMagicStore() *memMagicStore {
	return &memMagicStore{recs: map[string]authn.MagicLinkRecord{}, used: map[string]bool{}}
}

func (s *memMagicStore) Create(_ context.Context, rec authn.MagicLinkRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recs[rec.ID] = rec
	return nil
}

func (s *memMagicStore) ByPrefix(_ context.Context, prefix string) ([]authn.MagicLinkRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []authn.MagicLinkRecord
	for _, r := range s.recs {
		if r.Prefix == prefix {
			out = append(out, r)
		}
	}
	return out, nil
}

func (s *memMagicStore) Consume(_ context.Context, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used[id] {
		return false, nil
	}
	s.used[id] = true
	return true, nil
}

type staticResolver struct {
	grant authn.Grant
	ok    bool
	err   error
}

func (r staticResolver) Resolve(_ context.Context, _ string) (authn.Grant, bool, error) {
	return r.grant, r.ok, r.err
}

type captureNotifier struct {
	mu   sync.Mutex
	sent []authn.Notification
}

func (n *captureNotifier) Notify(_ context.Context, note authn.Notification) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sent = append(n.sent, note)
	return nil
}

func (n *captureNotifier) last() (authn.Notification, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.sent) == 0 {
		return authn.Notification{}, false
	}
	return n.sent[len(n.sent)-1], true
}

func testGrant() authn.Grant {
	return authn.Grant{
		Subject:    "respondent:abc",
		OrgID:      "org-1",
		ObjectType: "assessment",
		ObjectID:   "assess-1",
		Relation:   "respondent",
	}
}

func TestMagicLink_RequestSendsLink_ThenRedeemOnce(t *testing.T) {
	store := newMemMagicStore()
	notif := &captureNotifier{}
	p := authn.NewMagicLinkProvider(store, staticResolver{grant: testGrant(), ok: true}, notif,
		func(tok string) string { return "https://host/verify?token=" + tok })

	if err := p.Request(context.Background(), "Vendor@Example.com"); err != nil {
		t.Fatalf("Request: %v", err)
	}
	note, ok := notif.last()
	if !ok {
		t.Fatal("no notification delivered for a resolvable email")
	}
	if note.Email != "vendor@example.com" {
		t.Errorf("email not normalized: %q", note.Email)
	}
	if !strings.Contains(note.URL, note.Token) || note.Token == "" {
		t.Fatalf("link URL %q must embed the token %q", note.URL, note.Token)
	}
	if !strings.HasPrefix(note.Token, authn.TokenPrefixMagic) {
		t.Errorf("token missing magic prefix: %q", note.Token)
	}

	grant, err := p.Redeem(context.Background(), note.Token)
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if grant != testGrant() {
		t.Errorf("grant mismatch: %+v", grant)
	}

	// Single-use: a second redeem of the same token fails identically to a bogus one.
	if _, err := p.Redeem(context.Background(), note.Token); !errors.Is(err, authn.ErrMagicLinkInvalid) {
		t.Errorf("second redeem should be invalid, got %v", err)
	}
}

func TestMagicLink_UnknownEmailIsSilent(t *testing.T) {
	store := newMemMagicStore()
	notif := &captureNotifier{}
	p := authn.NewMagicLinkProvider(store, staticResolver{ok: false}, notif,
		func(tok string) string { return tok })

	if err := p.Request(context.Background(), "stranger@example.com"); err != nil {
		t.Fatalf("Request should be nil for unknown email (enumeration-safe): %v", err)
	}
	if _, ok := notif.last(); ok {
		t.Fatal("no link must be sent for an unresolved email")
	}
}

func TestMagicLink_ExpiredTokenRejected(t *testing.T) {
	store := newMemMagicStore()
	notif := &captureNotifier{}
	p := authn.NewMagicLinkProvider(store, staticResolver{grant: testGrant(), ok: true}, notif,
		func(tok string) string { return tok },
		authn.WithMagicLinkTTL(1*time.Millisecond)) // lapses almost immediately

	if err := p.Request(context.Background(), "vendor@example.com"); err != nil {
		t.Fatalf("Request: %v", err)
	}
	note, _ := notif.last()
	time.Sleep(15 * time.Millisecond) // let the link lapse
	if _, err := p.Redeem(context.Background(), note.Token); !errors.Is(err, authn.ErrMagicLinkInvalid) {
		t.Errorf("expired token should be invalid, got %v", err)
	}
}

func TestMagicLink_MalformedAndWrongTokenRejected(t *testing.T) {
	store := newMemMagicStore()
	p := authn.NewMagicLinkProvider(store, staticResolver{grant: testGrant(), ok: true}, &captureNotifier{},
		func(tok string) string { return tok })

	for _, tok := range []string{"", "not-a-token", "anet_user_deadbeef", authn.TokenPrefixMagic + "unknownbody"} {
		if _, err := p.Redeem(context.Background(), tok); !errors.Is(err, authn.ErrMagicLinkInvalid) {
			t.Errorf("token %q should be invalid, got %v", tok, err)
		}
	}
}
