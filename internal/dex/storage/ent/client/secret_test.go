// ARMORNET FORK: this whole file is armornet's, with no upstream counterpart.
// It covers client-secret hashing on update (secretForUpdate in main.go), which
// upstream does not have because upstream stores secrets in cleartext.
// Keep it on an upstream Dex pull — see the Dex migration notes.
package client

import (
	"strings"
	"testing"
)

// The real hasher is argon2id from identity/secrethash, which this module
// cannot import — the fork is a separate Go module and is deliberately kept
// free of armornet dependencies (the hasher arrives via WithSecretHasher).
//
// These stubs stand in for it and preserve the one property the code under test
// depends on: hashing is NOT idempotent, so a double-hash is observable. That is
// exactly the bug being guarded.
func stubDB() *Database {
	return &Database{
		secretHasher: func(plaintext string) (string, error) {
			return "H(" + plaintext + ")", nil
		},
		secretVerifier: func(plaintext, hash string) (bool, error) {
			if !strings.HasPrefix(hash, "H(") {
				return false, errNotAHash
			}
			return hash == "H("+plaintext+")", nil
		},
	}
}

var errNotAHash = &notAHashError{}

type notAHashError struct{}

func (*notAHashError) Error() string { return "stored value is not in hash format" }

// The regression this guards: UpdateClient's updater receives the client as
// STORED, so its secret is already a hash. Every metadata-only edit — a rename,
// a redirect-URI change — hands that hash straight back. Re-hashing it persists
// H(H(secret)), the presented plaintext stops verifying forever, and the real
// hash is gone. A cosmetic rename would permanently brick the credential.
func TestSecretForUpdate_UnchangedSecretIsNotRehashed(t *testing.T) {
	d := stubDB()

	stored, err := d.hashSecret("s3cret")
	if err != nil {
		t.Fatalf("hashSecret: %v", err)
	}

	// A rename: the updater returns the stored (hashed) secret untouched.
	got, err := d.secretForUpdate(stored, stored)
	if err != nil {
		t.Fatalf("secretForUpdate: %v", err)
	}
	if got != stored {
		t.Fatalf("secretForUpdate re-hashed an unchanged secret: got %q, want %q", got, stored)
	}
	if !d.VerifyClientSecret(got, "s3cret") {
		t.Error("original plaintext no longer verifies after a metadata-only update")
	}
}

// Rotation must still hash: a genuinely new plaintext cannot be stored as-is.
func TestSecretForUpdate_ChangedSecretIsHashed(t *testing.T) {
	d := stubDB()

	stored, err := d.hashSecret("old-secret")
	if err != nil {
		t.Fatalf("hashSecret: %v", err)
	}

	got, err := d.secretForUpdate(stored, "new-secret")
	if err != nil {
		t.Fatalf("secretForUpdate: %v", err)
	}
	if got == "new-secret" {
		t.Fatal("secretForUpdate stored the new secret as plaintext")
	}
	if !d.VerifyClientSecret(got, "new-secret") {
		t.Error("the new plaintext does not verify against the stored hash")
	}
	if d.VerifyClientSecret(got, "old-secret") {
		t.Error("the previous secret still verifies after rotation")
	}
}

// With no hasher configured the fork must behave exactly like upstream Dex, so
// an un-hashed deployment is not silently altered.
func TestSecretForUpdate_NoHasherPassesThrough(t *testing.T) {
	var d Database

	got, err := d.secretForUpdate("old", "new")
	if err != nil {
		t.Fatalf("secretForUpdate: %v", err)
	}
	if got != "new" {
		t.Errorf("got %q, want %q", got, "new")
	}
}

// A client with no secret (public/PKCE) must not acquire one.
func TestSecretForUpdate_EmptySecretStaysEmpty(t *testing.T) {
	d := stubDB()

	got, err := d.secretForUpdate("", "")
	if err != nil {
		t.Fatalf("secretForUpdate: %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want an empty secret", got)
	}
}

// The documented migration window: rows written before hashing landed are
// plaintext, and must keep working until they are rotated.
func TestVerifyClientSecret_FallsBackToPlaintext(t *testing.T) {
	d := stubDB()

	if !d.VerifyClientSecret("legacy-plaintext", "legacy-plaintext") {
		t.Error("a legacy plaintext row no longer verifies")
	}
	if d.VerifyClientSecret("legacy-plaintext", "wrong") {
		t.Error("a wrong secret verified against a legacy plaintext row")
	}
}
