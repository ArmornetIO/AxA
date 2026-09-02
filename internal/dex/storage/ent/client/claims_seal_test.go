// ARMORNET FORK: this whole file is armornet's, with no upstream counterpart.
// It covers the at-rest sealing of claims.Email (sealClaims/openClaims in
// claims.go). Keep it on an upstream Dex pull — see the Dex migration notes.
package client

import (
	"strings"
	"testing"

	"github.com/ArmornetIO/identity/internal/dex/storage"
)

func TestSealClaims_RoundTrips(t *testing.T) {
	d := sealingDB()
	in := storage.Claims{UserID: "67766491", Email: "user@example.com", Username: "A User"}

	sealed, err := d.sealClaims(in)
	if err != nil {
		t.Fatalf("sealClaims: %v", err)
	}
	if strings.Contains(sealed.Email, "user@example.com") {
		t.Fatalf("sealed email still contains the address: %q", sealed.Email)
	}
	if !strings.HasPrefix(sealed.Email, SealedStringPrefix) {
		t.Errorf("sealed email missing %q marker: %q", SealedStringPrefix, sealed.Email)
	}

	opened, err := d.openClaims(sealed)
	if err != nil {
		t.Fatalf("openClaims: %v", err)
	}
	if opened.Email != in.Email {
		t.Errorf("round trip returned %q, want %q", opened.Email, in.Email)
	}
}

// UserID is the join key Dex and armornet find rows by, so sealing it would
// silently break those lookups. Every other identifying claim must be sealed —
// leaving the real name or the upstream login readable would make the address
// recoverable anyway.
func TestSealClaims_SealsIdentityButNotTheJoinKey(t *testing.T) {
	d := sealingDB()
	in := storage.Claims{
		UserID:            "67766491",
		Email:             "user@example.com",
		Username:          "A User",
		PreferredUsername: "auser",
		Groups:            []string{"eng"},
	}

	sealed, err := d.sealClaims(in)
	if err != nil {
		t.Fatalf("sealClaims: %v", err)
	}
	if sealed.UserID != in.UserID {
		t.Errorf("UserID was sealed; it is a lookup key and must stay readable: %q", sealed.UserID)
	}
	for name, got := range map[string]string{
		"Username":          sealed.Username,
		"PreferredUsername": sealed.PreferredUsername,
	} {
		if !strings.HasPrefix(got, SealedStringPrefix) {
			t.Errorf("%s was left in cleartext: %q", name, got)
		}
	}

	opened, err := d.openClaims(sealed)
	if err != nil {
		t.Fatalf("openClaims: %v", err)
	}
	if opened.Username != in.Username || opened.PreferredUsername != in.PreferredUsername {
		t.Errorf("round trip returned %q / %q, want %q / %q",
			opened.Username, opened.PreferredUsername, in.Username, in.PreferredUsername)
	}
}

// A connector that yields no address stores an empty string, which 0138's CHECK
// exempts it. Sealing it would both violate nothing and leak the empty case as
// a distinguishable ciphertext, so it must pass through untouched.
func TestSealClaims_EmptyEmailStaysEmpty(t *testing.T) {
	d := sealingDB()

	sealed, err := d.sealClaims(storage.Claims{UserID: "1"})
	if err != nil {
		t.Fatalf("sealClaims: %v", err)
	}
	if sealed.Email != "" {
		t.Errorf("empty email became %q", sealed.Email)
	}
	opened, err := d.openClaims(sealed)
	if err != nil {
		t.Fatalf("openClaims on empty: %v", err)
	}
	if opened.Email != "" {
		t.Errorf("empty email round-tripped to %q", opened.Email)
	}
}

// With a sealer configured an unmarked value is a hard error, not a cleartext
// fallback: 0138 deletes the rows written before sealing and its CHECK blocks
// new ones, so an unmarked value means something wrote around the constraint.
func TestOpenClaims_RejectsUnsealedEmail(t *testing.T) {
	d := sealingDB()

	if _, err := d.openClaims(storage.Claims{Email: "user@example.com"}); err == nil {
		t.Fatal("openClaims accepted an unsealed address")
	}
}

// The refresh path rewrites Claims.Email from the upstream identity, so the
// updater must be handed OPENED claims and its result sealed once. Sealing
// before the updater yields Seal(Seal(email)) and the address decrypts to
// garbage — the same trap TestConnectorUpdateOrdering guards for configs.
func TestClaimsUpdateOrdering_OpenBeforeUpdaterSealAfter(t *testing.T) {
	d := sealingDB()
	const original = "old@example.com"
	const rotated = "new@example.com"

	stored, err := d.sealClaims(storage.Claims{Email: original})
	if err != nil {
		t.Fatalf("sealClaims: %v", err)
	}

	opened, err := d.openClaims(stored)
	if err != nil {
		t.Fatalf("openClaims: %v", err)
	}
	if opened.Email != original {
		t.Fatalf("updater would have seen %q, want %q", opened.Email, original)
	}
	opened.Email = rotated

	resealed, err := d.sealClaims(opened)
	if err != nil {
		t.Fatalf("re-sealClaims: %v", err)
	}
	final, err := d.openClaims(resealed)
	if err != nil {
		t.Fatalf("final openClaims: %v", err)
	}
	if final.Email != rotated {
		t.Errorf("after update the stored address opens to %q, want %q", final.Email, rotated)
	}
}

// With no sealer configured — a deployment that never sealed anything — both
// directions must be pass-through, or upstream Dex behaviour changes.
func TestClaims_NoSealerIsPassThrough(t *testing.T) {
	var d Database
	in := storage.Claims{Email: "user@example.com"}

	sealed, err := d.sealClaims(in)
	if err != nil || sealed.Email != in.Email {
		t.Fatalf("sealClaims without a sealer: %q, %v", sealed.Email, err)
	}
	opened, err := d.openClaims(in)
	if err != nil || opened.Email != in.Email {
		t.Fatalf("openClaims without an opener: %q, %v", opened.Email, err)
	}
}
