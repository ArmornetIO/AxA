// ARMORNET FORK: this whole file is armornet's, with no upstream counterpart.
// It covers the at-rest sealing of connector configs and the device flow's
// stored client secret (WithFieldSealer / WithFieldOpener in main.go).
// Keep it on an upstream Dex pull — see the Dex migration notes.
package client

import (
	"bytes"
	"strings"
	"testing"
)

// A stand-in for the host's real cipher. This module cannot import it (separate
// Go module, deliberately dependency-free), so the stub preserves the property
// the code under test relies on: sealing is observable and not idempotent, so a
// double-seal shows up.
func sealingDB() *Database {
	const marker = "SEALED:"
	return &Database{
		fieldSealer: func(plaintext []byte) ([]byte, error) {
			return append([]byte(marker), plaintext...), nil
		},
		fieldOpener: func(sealed []byte) ([]byte, error) {
			return bytes.TrimPrefix(sealed, []byte(marker)), nil
		},
	}
}

func TestSealConfig_RoundTrips(t *testing.T) {
	d := sealingDB()
	const cfg = `{"clientSecret":"upstream-secret"}`

	sealed, err := d.sealField([]byte(cfg))
	if err != nil {
		t.Fatalf("sealConfig: %v", err)
	}
	if bytes.Equal(sealed, []byte(cfg)) {
		t.Fatal("sealConfig returned the plaintext unchanged")
	}

	opened, err := d.openField(sealed)
	if err != nil {
		t.Fatalf("openConfig: %v", err)
	}
	if string(opened) != cfg {
		t.Errorf("round trip returned %q, want %q", opened, cfg)
	}
}

// The UpdateConnector ordering contract, which is the same trap that bricked
// client secrets: the updater must be handed OPENED config and its result
// sealed once. Opening after the updater, or sealing before it, yields
// Seal(Seal(config)) — the connector then decrypts to garbage and the upstream
// IdP credentials inside it are unrecoverable.
func TestConnectorUpdateOrdering_OpenBeforeUpdaterSealAfter(t *testing.T) {
	d := sealingDB()
	const original = `{"clientSecret":"upstream-secret"}`
	const renamed = `{"clientSecret":"upstream-secret","name":"renamed"}`

	stored, err := d.sealField([]byte(original))
	if err != nil {
		t.Fatalf("sealConfig: %v", err)
	}

	// What UpdateConnector does: open, hand to the updater, seal the result.
	opened, err := d.openField(stored)
	if err != nil {
		t.Fatalf("openConfig: %v", err)
	}
	if string(opened) != original {
		t.Fatalf("updater would have seen %q, want the plaintext %q", opened, original)
	}

	resealed, err := d.sealField([]byte(renamed))
	if err != nil {
		t.Fatalf("sealConfig: %v", err)
	}

	// One layer, not two: opening once must yield usable JSON.
	final, err := d.openField(resealed)
	if err != nil {
		t.Fatalf("openConfig: %v", err)
	}
	if string(final) != renamed {
		t.Errorf("after update the config opens to %q, want %q — double-sealed?", final, renamed)
	}
}

// Unconfigured, the fork must behave exactly like upstream Dex.
func TestSealConfig_NoSealerPassesThrough(t *testing.T) {
	var d Database
	const cfg = `{"a":1}`

	sealed, err := d.sealField([]byte(cfg))
	if err != nil {
		t.Fatalf("sealConfig: %v", err)
	}
	if string(sealed) != cfg {
		t.Errorf("got %q, want %q", sealed, cfg)
	}

	opened, err := d.openField([]byte(cfg))
	if err != nil {
		t.Fatalf("openConfig: %v", err)
	}
	if string(opened) != cfg {
		t.Errorf("got %q, want %q", opened, cfg)
	}
}

func TestSealConfig_EmptyIsLeftAlone(t *testing.T) {
	d := sealingDB()

	sealed, err := d.sealField(nil)
	if err != nil {
		t.Fatalf("sealField: %v", err)
	}
	if len(sealed) != 0 {
		t.Errorf("empty config sealed to %q, want empty", sealed)
	}
}

// device_requests.client_secret is a text column, so the sealed bytes are
// base64-encoded to survive it. This is the path a CONFIDENTIAL client's real
// secret takes for the lifetime of a device-authorization request.
func TestSealFieldString_RoundTrips(t *testing.T) {
	d := sealingDB()
	const secret = "confidential-client-secret"

	stored, err := d.sealFieldString(secret)
	if err != nil {
		t.Fatalf("sealFieldString: %v", err)
	}
	if stored == secret {
		t.Fatal("sealFieldString returned the plaintext unchanged")
	}

	opened, err := d.openFieldString(stored)
	if err != nil {
		t.Fatalf("openFieldString: %v", err)
	}
	if opened != secret {
		t.Errorf("round trip returned %q, want %q", opened, secret)
	}
}

// With sealing on, an unmarked value must be refused, not read. Migration 0094
// deletes the unsealed device_requests rows and constrains the column, so an
// unmarked value can only mean something wrote around the constraint.
//
// The base64-shaped entries are the reason detection is an explicit marker
// rather than a decode attempt: client secrets usually ARE base64, so inferring
// "decodes cleanly ⇒ sealed" would misread a legacy secret as ciphertext.
func TestOpenFieldString_RejectsUnsealedValues(t *testing.T) {
	d := sealingDB()

	unsealed := []string{
		"-",
		"some-plaintext-secret!",
		"YWJjZGVmZ2hpamtsbW5vcA==", // valid base64, but not sealed
		"abcd",                     // decodes cleanly as base64 too
	}
	for _, v := range unsealed {
		if got, err := d.openFieldString(v); err == nil {
			t.Errorf("openFieldString(%q) returned %q, want an error", v, got)
		}
	}
}

// A deployment that never sealed anything has nothing to decrypt, and must keep
// reading its values unchanged.
func TestOpenFieldString_NoOpenerPassesThrough(t *testing.T) {
	var d Database

	for _, v := range []string{"-", "some-plaintext-secret!"} {
		opened, err := d.openFieldString(v)
		if err != nil {
			t.Fatalf("openFieldString(%q): %v", v, err)
		}
		if opened != v {
			t.Errorf("value %q opened to %q", v, opened)
		}
	}
}

// The migration's CHECK constraint matches on this literal prefix, so the Go
// constant and the SQL must not drift apart.
func TestSealFieldString_UsesTheDocumentedMarker(t *testing.T) {
	d := sealingDB()

	stored, err := d.sealFieldString("confidential-client-secret")
	if err != nil {
		t.Fatalf("sealFieldString: %v", err)
	}
	if !strings.HasPrefix(stored, "ANS1:") {
		t.Errorf("sealed value %q does not carry the ANS1: marker asserted by migration 0094", stored)
	}
	if SealedStringPrefix != "ANS1:" {
		t.Errorf("SealedStringPrefix = %q; migration 0094 checks for %q", SealedStringPrefix, "ANS1:")
	}
}

func TestSealFieldString_NoSealerPassesThrough(t *testing.T) {
	var d Database

	stored, err := d.sealFieldString("secret")
	if err != nil {
		t.Fatalf("sealFieldString: %v", err)
	}
	if stored != "secret" {
		t.Errorf("got %q, want %q", stored, "secret")
	}
}

func TestSealFieldString_EmptyStaysEmpty(t *testing.T) {
	d := sealingDB()

	stored, err := d.sealFieldString("")
	if err != nil {
		t.Fatalf("sealFieldString: %v", err)
	}
	if stored != "" {
		t.Errorf("empty secret sealed to %q, want empty", stored)
	}
}
