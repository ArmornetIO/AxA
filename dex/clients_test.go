package dex

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/ArmornetIO/axa"
	dexstorage "github.com/ArmornetIO/axa/internal/dex/storage"
)

// fakeStorage fakes the client half; the embedded nil interface panics on the
// rest rather than returning zero values.
type fakeStorage struct {
	dexstorage.Storage
	clients map[string]dexstorage.Client
}

func newFakeStorage() *fakeStorage {
	return &fakeStorage{clients: map[string]dexstorage.Client{}}
}

func (f *fakeStorage) CreateClient(_ context.Context, c dexstorage.Client) error {
	if _, ok := f.clients[c.ID]; ok {
		return dexstorage.ErrAlreadyExists
	}
	f.clients[c.ID] = c
	return nil
}

func (f *fakeStorage) GetClient(_ context.Context, id string) (dexstorage.Client, error) {
	c, ok := f.clients[id]
	if !ok {
		return dexstorage.Client{}, dexstorage.ErrNotFound
	}
	return c, nil
}

func (f *fakeStorage) UpdateClient(_ context.Context, id string, updater func(dexstorage.Client) (dexstorage.Client, error)) error {
	old, ok := f.clients[id]
	if !ok {
		return dexstorage.ErrNotFound
	}
	updated, err := updater(old)
	if err != nil {
		return err
	}
	f.clients[id] = updated
	return nil
}

func (f *fakeStorage) DeleteClient(_ context.Context, id string) error {
	if _, ok := f.clients[id]; !ok {
		return dexstorage.ErrNotFound
	}
	delete(f.clients, id)
	return nil
}

// newTestStore returns a clientStore over empty fake storage, plus the storage
// itself so tests can assert on what was actually persisted.
func newTestStore() (*clientStore, *fakeStorage) {
	fs := newFakeStorage()
	return &clientStore{storage: fs}, fs
}

func TestCreate_ReturnsSecretAndPersistsIt(t *testing.T) {
	s, fs := newTestStore()
	secret, err := s.Create(context.Background(), axa.Client{ID: "agent:org1:abc", Name: "probe"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if secret == "" {
		t.Fatal("Create returned an empty secret")
	}
	if got := fs.clients["agent:org1:abc"].Secret; got != secret {
		t.Errorf("persisted secret = %q, want the returned %q", got, secret)
	}
}

func TestCreate_DuplicateIsErrClientExists(t *testing.T) {
	s, _ := newTestStore()
	c := axa.Client{ID: "agent:org1:abc"}
	if _, err := s.Create(context.Background(), c); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	_, err := s.Create(context.Background(), c)
	if !errors.Is(err, axa.ErrClientExists) {
		t.Errorf("second Create err = %v, want ErrClientExists", err)
	}
}

func TestGet_NeverReturnsTheSecret(t *testing.T) {
	s, _ := newTestStore()
	if _, err := s.Create(context.Background(), axa.Client{ID: "agent:org1:abc", Name: "probe"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := s.Get(context.Background(), "agent:org1:abc")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "probe" {
		t.Errorf("Name = %q, want %q", got.Name, "probe")
	}
	// axa.Client has no Secret field at all — the write-once guarantee is
	// structural. This asserts the rest of the record still round-trips.
	if got.ID != "agent:org1:abc" {
		t.Errorf("ID = %q, want %q", got.ID, "agent:org1:abc")
	}
}

func TestGet_UnknownIsErrClientNotFound(t *testing.T) {
	s, _ := newTestStore()
	_, err := s.Get(context.Background(), "agent:org1:nope")
	if !errors.Is(err, axa.ErrClientNotFound) {
		t.Errorf("Get err = %v, want ErrClientNotFound", err)
	}
}

func TestUpdate_LeavesSecretIntact(t *testing.T) {
	s, fs := newTestStore()
	secret, err := s.Create(context.Background(), axa.Client{ID: "agent:org1:abc", Name: "before"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	err = s.Update(context.Background(), axa.Client{
		ID:           "agent:org1:abc",
		Name:         "after",
		RedirectURIs: []string{"https://app.example/cb"},
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	stored := fs.clients["agent:org1:abc"]
	if stored.Name != "after" {
		t.Errorf("Name = %q, want %q", stored.Name, "after")
	}
	if stored.Secret != secret {
		t.Error("Update changed the client secret; it must only touch mutable metadata")
	}
}

func TestUpdate_UnknownIsErrClientNotFound(t *testing.T) {
	s, _ := newTestStore()
	err := s.Update(context.Background(), axa.Client{ID: "agent:org1:nope"})
	if !errors.Is(err, axa.ErrClientNotFound) {
		t.Errorf("Update err = %v, want ErrClientNotFound", err)
	}
}

func TestRotateSecret_ReplacesSecretAndKeepsIdentity(t *testing.T) {
	s, fs := newTestStore()
	original, err := s.Create(context.Background(), axa.Client{
		ID:           "agent:org1:abc",
		Name:         "probe",
		RedirectURIs: []string{"https://app.example/cb"},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	rotated, err := s.RotateSecret(context.Background(), "agent:org1:abc")
	if err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}
	if rotated == original {
		t.Fatal("RotateSecret returned the original secret")
	}

	stored := fs.clients["agent:org1:abc"]
	if stored.Secret != rotated {
		t.Errorf("persisted secret = %q, want the returned %q", stored.Secret, rotated)
	}
	// The whole point of rotation over delete+recreate: the client keeps its ID
	// and configuration, so nothing downstream has to be re-pointed.
	if stored.ID != "agent:org1:abc" || stored.Name != "probe" {
		t.Errorf("rotation altered identity: got ID=%q Name=%q", stored.ID, stored.Name)
	}
	if len(stored.RedirectURIs) != 1 || stored.RedirectURIs[0] != "https://app.example/cb" {
		t.Errorf("rotation altered RedirectURIs: got %v", stored.RedirectURIs)
	}
}

func TestRotateSecret_UnknownIsErrClientNotFound(t *testing.T) {
	s, _ := newTestStore()
	_, err := s.RotateSecret(context.Background(), "agent:org1:nope")
	if !errors.Is(err, axa.ErrClientNotFound) {
		t.Errorf("RotateSecret err = %v, want ErrClientNotFound", err)
	}
}

func TestDelete_UnknownIsErrClientNotFound(t *testing.T) {
	s, _ := newTestStore()
	err := s.Delete(context.Background(), "agent:org1:nope")
	if !errors.Is(err, axa.ErrClientNotFound) {
		t.Errorf("Delete err = %v, want ErrClientNotFound", err)
	}
}

func TestGenerateSecret_Length(t *testing.T) {
	s, err := generateSecret()
	if err != nil {
		t.Fatalf("generateSecret: %v", err)
	}
	// 32 raw bytes → 43 base64url chars (no padding)
	if len(s) != 43 {
		t.Errorf("secret length = %d, want 43", len(s))
	}
}

func TestGenerateSecret_ValidBase64URL(t *testing.T) {
	s, err := generateSecret()
	if err != nil {
		t.Fatalf("generateSecret: %v", err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(s); err != nil {
		t.Errorf("secret is not valid base64url: %v", err)
	}
}

func TestGenerateSecret_Unique(t *testing.T) {
	seen := make(map[string]bool, 20)
	for range 20 {
		s, err := generateSecret()
		if err != nil {
			t.Fatalf("generateSecret: %v", err)
		}
		if seen[s] {
			t.Fatalf("generateSecret returned duplicate: %q", s)
		}
		seen[s] = true
	}
}
