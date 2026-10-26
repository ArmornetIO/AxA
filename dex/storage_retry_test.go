package dex

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/lib/pq"
	pkgerrors "github.com/pkg/errors"

	"github.com/ArmornetIO/identity/authn/secrethash"
	dexstorage "github.com/ArmornetIO/identity/internal/dex/storage"
)

// The Ent client hands back the pq error under both of its wrappings — %w from
// convertDBError, then pkg/errors when the rollback itself fails — and the
// retry must see through each.
func TestIsSerializationFailureThroughEntWrapping(t *testing.T) {
	serial := &pq.Error{Code: "40001"}
	for name, err := range map[string]error{
		"bare":     serial,
		"uploaded": fmt.Errorf("update auth request uploading: %w", serial),
		"rollback": pkgerrors.Wrapf(fmt.Errorf("update auth request commit: %w", serial), "rolling back transaction: %v", errors.New("tx done")),
		"deadlock": fmt.Errorf("x: %w", &pq.Error{Code: "40P01"}),
	} {
		if !isSerializationFailure(err) {
			t.Errorf("%s: not recognised as a serialization failure", name)
		}
	}
	for name, err := range map[string]error{
		"nil":       nil,
		"not found": dexstorage.ErrNotFound,
		"unique":    fmt.Errorf("x: %w", &pq.Error{Code: "23505"}),
	} {
		if isSerializationFailure(err) {
			t.Errorf("%s: retried an error that is not a serialization failure", name)
		}
	}
}

// Each storage wrapper hides the backend's argon2id check unless it passes it
// on; one that does not refuses every confidential client with invalid_client.
// Opening is lazy, so this needs no database.
func TestStorageStillVerifiesHashedClientSecrets(t *testing.T) {
	s, err := newStorage("postgres://unused@127.0.0.1:1/x?sslmode=disable", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := s.(interface {
		VerifyClientSecret(stored, plaintext string) bool
	})
	if !ok {
		t.Fatal("storage does not expose VerifyClientSecret")
	}
	hash, err := secrethash.HashToken("bff-secret", secrethash.DefaultArgon2Params())
	if err != nil {
		t.Fatal(err)
	}
	if !v.VerifyClientSecret(hash, "bff-secret") || v.VerifyClientSecret(hash, "wrong") {
		t.Fatal("hashed client secret not verified through the storage wrappers")
	}
}

func TestRetrySerialization(t *testing.T) {
	serial := fmt.Errorf("commit: %w", &pq.Error{Code: "40001"})

	calls := 0
	err := retrySerialization(context.Background(), func() error {
		if calls++; calls < 3 {
			return serial
		}
		return nil
	})
	if err != nil || calls != 3 {
		t.Errorf("recovering update: err=%v after %d calls, want nil after 3", err, calls)
	}

	calls = 0
	_ = retrySerialization(context.Background(), func() error { calls++; return dexstorage.ErrNotFound })
	if calls != 1 {
		t.Errorf("a non-serialization error ran %d times, want 1", calls)
	}

	calls = 0
	if err := retrySerialization(context.Background(), func() error { calls++; return serial }); !errors.Is(err, serial) || calls != maxTxAttempts {
		t.Errorf("endless conflict: err=%v after %d calls, want the conflict after %d", err, calls, maxTxAttempts)
	}
}
