package dex

import (
	"context"
	"strings"
	"testing"

	"github.com/ArmornetIO/axa/authn"
	dexstorage "github.com/ArmornetIO/axa/internal/dex/storage"
	entclient "github.com/ArmornetIO/axa/internal/dex/storage/ent/client"
)

// fakeDeviceStorage records what reaches the columns: that, not the round trip,
// is under test.
type fakeDeviceStorage struct {
	dexstorage.Storage
	requests map[string]dexstorage.DeviceRequest // by user code
	tokens   map[string]dexstorage.DeviceToken   // by whatever key it was given
}

func newFakeDeviceStorage() *fakeDeviceStorage {
	return &fakeDeviceStorage{
		requests: map[string]dexstorage.DeviceRequest{},
		tokens:   map[string]dexstorage.DeviceToken{},
	}
}

func (f *fakeDeviceStorage) CreateDeviceRequest(_ context.Context, r dexstorage.DeviceRequest) error {
	f.requests[r.UserCode] = r
	return nil
}

func (f *fakeDeviceStorage) GetDeviceRequest(_ context.Context, userCode string) (dexstorage.DeviceRequest, error) {
	r, ok := f.requests[userCode]
	if !ok {
		return dexstorage.DeviceRequest{}, dexstorage.ErrNotFound
	}
	return r, nil
}

func (f *fakeDeviceStorage) CreateDeviceToken(_ context.Context, t dexstorage.DeviceToken) error {
	f.tokens[t.DeviceCode] = t
	return nil
}

func (f *fakeDeviceStorage) GetDeviceToken(_ context.Context, deviceCode string) (dexstorage.DeviceToken, error) {
	t, ok := f.tokens[deviceCode]
	if !ok {
		return dexstorage.DeviceToken{}, dexstorage.ErrNotFound
	}
	return t, nil
}

func (f *fakeDeviceStorage) UpdateDeviceToken(_ context.Context, deviceCode string, updater func(dexstorage.DeviceToken) (dexstorage.DeviceToken, error)) error {
	old, ok := f.tokens[deviceCode]
	if !ok {
		return dexstorage.ErrNotFound
	}
	next, err := updater(old)
	if err != nil {
		return err
	}
	f.tokens[deviceCode] = next
	return nil
}

// reversibleSealer stands in for the KEK cipher. It is not encryption — the
// tests only need Open(Seal(x)) == x and a value that is not x.
type reversibleSealer struct{}

func (reversibleSealer) Seal(plaintext []byte) ([]byte, error) {
	return append([]byte("sealed:"), plaintext...), nil
}

func (reversibleSealer) Open(sealed []byte) ([]byte, error) {
	return []byte(strings.TrimPrefix(string(sealed), "sealed:")), nil
}

const testDeviceCode = "cnv2xn4jwqz6k3mzvtqk7t5qgq7n5wvd"

func newTestDeviceStore() (deviceCodeStore, *fakeDeviceStorage) {
	inner := newFakeDeviceStorage()
	return deviceCodeStore{Storage: inner, sealer: reversibleSealer{}}, inner
}

func TestDeviceRequestStoresSealedCode(t *testing.T) {
	store, inner := newTestDeviceStore()
	ctx := context.Background()

	if err := store.CreateDeviceRequest(ctx, dexstorage.DeviceRequest{
		UserCode:   "ABCD-EFGH",
		DeviceCode: testDeviceCode,
	}); err != nil {
		t.Fatalf("CreateDeviceRequest: %v", err)
	}

	stored := inner.requests["ABCD-EFGH"].DeviceCode
	if strings.Contains(stored, testDeviceCode) {
		t.Errorf("device code reached storage in cleartext: %q", stored)
	}
	if !strings.HasPrefix(stored, entclient.SealedStringPrefix) {
		// Migration 39's CHECK tests for this marker, so a value without it
		// fails at the database rather than here.
		t.Errorf("stored device code = %q, want the %q marker", stored, entclient.SealedStringPrefix)
	}

	got, err := store.GetDeviceRequest(ctx, "ABCD-EFGH")
	if err != nil {
		t.Fatalf("GetDeviceRequest: %v", err)
	}
	if got.DeviceCode != testDeviceCode {
		// The callback hands this value to GetDeviceToken, so a seal that does
		// not round-trip breaks every sign-in rather than failing loudly.
		t.Errorf("round-tripped device code = %q, want %q", got.DeviceCode, testDeviceCode)
	}
}

func TestDeviceRequestRefusesUnsealedCode(t *testing.T) {
	store, inner := newTestDeviceStore()
	inner.requests["ABCD-EFGH"] = dexstorage.DeviceRequest{
		UserCode:   "ABCD-EFGH",
		DeviceCode: testDeviceCode, // written around the wrapper
	}

	if _, err := store.GetDeviceRequest(context.Background(), "ABCD-EFGH"); err == nil {
		t.Error("read an unsealed device code without error; a cleartext row must not be usable")
	}
}

func TestDeviceTokenKeyedByDigest(t *testing.T) {
	store, inner := newTestDeviceStore()
	ctx := context.Background()
	digest := authn.HashSessionToken(testDeviceCode)

	if err := store.CreateDeviceToken(ctx, dexstorage.DeviceToken{
		DeviceCode: testDeviceCode,
		Status:     "pending",
	}); err != nil {
		t.Fatalf("CreateDeviceToken: %v", err)
	}

	if _, ok := inner.tokens[testDeviceCode]; ok {
		t.Error("device token stored under the cleartext code")
	}
	if _, ok := inner.tokens[digest]; !ok {
		t.Fatalf("device token not stored under its digest; keys = %v", keysOf(inner.tokens))
	}

	// The polling client presents the cleartext code and must still find it.
	got, err := store.GetDeviceToken(ctx, testDeviceCode)
	if err != nil {
		t.Fatalf("GetDeviceToken: %v", err)
	}
	if got.Status != "pending" {
		t.Errorf("status = %q, want pending", got.Status)
	}
}

func TestDeviceTokenUpdateKeepsDigestKey(t *testing.T) {
	store, inner := newTestDeviceStore()
	ctx := context.Background()
	digest := authn.HashSessionToken(testDeviceCode)

	if err := store.CreateDeviceToken(ctx, dexstorage.DeviceToken{DeviceCode: testDeviceCode}); err != nil {
		t.Fatalf("CreateDeviceToken: %v", err)
	}

	// An updater that writes the field back — the shape that would hash a hash,
	// or restore cleartext, if the wrapper did not pin the key.
	err := store.UpdateDeviceToken(ctx, testDeviceCode, func(old dexstorage.DeviceToken) (dexstorage.DeviceToken, error) {
		old.DeviceCode = testDeviceCode
		old.Status = "complete"
		return old, nil
	})
	if err != nil {
		t.Fatalf("UpdateDeviceToken: %v", err)
	}

	if len(inner.tokens) != 1 {
		t.Errorf("update wrote a second row: keys = %v", keysOf(inner.tokens))
	}
	stored, ok := inner.tokens[digest]
	if !ok {
		t.Fatalf("row no longer keyed by digest; keys = %v", keysOf(inner.tokens))
	}
	if stored.DeviceCode != digest {
		t.Errorf("stored device code = %q, want the digest", stored.DeviceCode)
	}
	if stored.Status != "complete" {
		t.Errorf("status = %q, want complete", stored.Status)
	}
}

func TestDeviceCodesUnsealedWithoutCipher(t *testing.T) {
	// No KEK: the code passes through unsealed, but hashing still applies.
	store := deviceCodeStore{Storage: newFakeDeviceStorage()}
	ctx := context.Background()

	if err := store.CreateDeviceRequest(ctx, dexstorage.DeviceRequest{
		UserCode:   "ABCD-EFGH",
		DeviceCode: testDeviceCode,
	}); err != nil {
		t.Fatalf("CreateDeviceRequest: %v", err)
	}
	got, err := store.GetDeviceRequest(ctx, "ABCD-EFGH")
	if err != nil {
		t.Fatalf("GetDeviceRequest: %v", err)
	}
	if got.DeviceCode != testDeviceCode {
		t.Errorf("device code = %q, want %q", got.DeviceCode, testDeviceCode)
	}
}

func keysOf(m map[string]dexstorage.DeviceToken) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// verifyingStorage stands in for *entclient.Database, whose argon2id check is
// not on the interface.
type verifyingStorage struct {
	dexstorage.Storage
	called bool
}

func (v *verifyingStorage) VerifyClientSecret(stored, plaintext string) bool {
	v.called = true
	return stored == "hash-of:"+plaintext
}

// A wrapper embedding the INTERFACE hides the type-asserted argon2id check, and
// every confidential client gets invalid_client.
func TestDeviceCodeStorePassesThroughClientSecretVerification(t *testing.T) {
	inner := &verifyingStorage{Storage: newFakeDeviceStorage()}
	var wrapped dexstorage.Storage = deviceCodeStore{Storage: inner}

	v, ok := wrapped.(interface {
		VerifyClientSecret(stored, plaintext string) bool
	})
	if !ok {
		t.Fatal("deviceCodeStore does not expose VerifyClientSecret — the server will fall back to comparing plaintext against a hash")
	}
	if !v.VerifyClientSecret("hash-of:s3cret", "s3cret") {
		t.Error("matching secret rejected")
	}
	if !inner.called {
		t.Error("verification did not reach the backend")
	}
	if v.VerifyClientSecret("hash-of:s3cret", "wrong") {
		t.Error("wrong secret accepted")
	}
}
