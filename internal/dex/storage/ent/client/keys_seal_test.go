// ARMORNET FORK: this whole file is armornet's, with no upstream counterpart.
// It covers the at-rest sealing of the ID-token signing key (SealedSigningKeyID
// in keys.go). Keep it on an upstream Dex pull — see the Dex migration notes.
package client

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func testSigningKey(t *testing.T) jose.JSONWebKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return jose.JSONWebKey{Key: priv, KeyID: "real-kid", Algorithm: "RS256", Use: "sig"}
}

func TestSealSigningKey_RoundTrips(t *testing.T) {
	d := sealingDB()
	key := testSigningKey(t)

	sealed, err := d.sealSigningKey(key)
	if err != nil {
		t.Fatalf("sealSigningKey: %v", err)
	}
	if sealed.KeyID != SealedSigningKeyID {
		t.Fatalf("kid = %q, want the sealed marker — nothing else can tell the row apart in SQL", sealed.KeyID)
	}

	// The private key must not survive into what gets stored. Marshalling is
	// what the column holds, so that is what has to be checked: a JWK still
	// carrying the RSA private key would serialise its "d" parameter.
	stored, err := sealed.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), `"d"`) {
		t.Fatal("the stored JWK still carries private key material")
	}

	open, err := d.openSigningKey(sealed)
	if err != nil {
		t.Fatalf("openSigningKey: %v", err)
	}
	if open.KeyID != key.KeyID || open.Algorithm != key.Algorithm {
		t.Fatalf("opened key = %+v, want the original back", open)
	}
	if _, ok := open.Key.(*rsa.PrivateKey); !ok {
		t.Fatalf("opened key holds %T, want the RSA private key", open.Key)
	}
}

// A row written before sealing was enabled has no marker, and Dex rewrites this
// row on its own rotation schedule — so tolerating it is what lets the seal land
// without a backfill. Refusing it would lock everyone out until the next rotation.
func TestOpenSigningKey_PassesThroughAnUnsealedRow(t *testing.T) {
	d := sealingDB()
	key := testSigningKey(t)

	open, err := d.openSigningKey(key)
	if err != nil {
		t.Fatalf("openSigningKey on a legacy row: %v", err)
	}
	if open.KeyID != key.KeyID {
		t.Fatalf("opened key = %+v, want the row unchanged", open)
	}
}

// With no sealer configured the key is stored as it always was, so a deployment
// without a KEK keeps working rather than failing closed at login.
func TestSealSigningKey_NoSealerIsAPassThrough(t *testing.T) {
	d := &Database{}
	key := testSigningKey(t)

	sealed, err := d.sealSigningKey(key)
	if err != nil {
		t.Fatalf("sealSigningKey: %v", err)
	}
	if sealed.KeyID != key.KeyID {
		t.Fatalf("kid = %q, want the key untouched with no sealer", sealed.KeyID)
	}
}
