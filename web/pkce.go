package web

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// RandBase64URL returns a cryptographically random base64url-encoded string of n bytes.
func RandBase64URL(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// S256Challenge derives a PKCE S256 code_challenge from a plain verifier.
func S256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
