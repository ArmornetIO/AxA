package secrethash

import "testing"

// TestArgon2RoundTrip pins the hash/verify round trip and rejection of a wrong
// secret.
func TestArgon2RoundTrip(t *testing.T) {
	const secret = "anet_user_a8b3c1d2e3f4g5h6i7j8k9l0m1n2o3p4"
	hash, err := HashToken(secret, DefaultArgon2Params())
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	ok, err := VerifyToken(secret, hash)
	if err != nil || !ok {
		t.Fatalf("verify mismatch: ok=%v err=%v", ok, err)
	}
	bad, err := VerifyToken("anet_user_wrongwrongwrongwrongwrongwrong", hash)
	if err != nil {
		t.Fatalf("verify wrong: %v", err)
	}
	if bad {
		t.Fatalf("verify accepted wrong token")
	}
}

func TestEmptyTokenRejected(t *testing.T) {
	if _, err := HashToken("", DefaultArgon2Params()); err == nil {
		t.Fatal("expected error hashing empty token")
	}
}
