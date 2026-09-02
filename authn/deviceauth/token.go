package deviceauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// SubjectFromToken reads the `sub` claim out of a JWT WITHOUT verifying it.
//
// This is for display only — answering "who does this machine think it is
// signed in as?" while offline. It is NOT an authorization decision and must
// never be used as one: the claims are unverified, so a caller that trusted
// them would be trusting whatever the token's holder chose to write.
//
// Every authorization decision happens server-side against a verified token.
func SubjectFromToken(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("not a JWT")
	}
	// JWT uses base64url with no padding.
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode claims: %w", err)
	}
	var claims struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("parse claims: %w", err)
	}
	// Prefer a human-readable label, but never invent one: fall back to the
	// subject, which is the identifier the platform actually keys on.
	switch {
	case claims.Name != "":
		return fmt.Sprintf("%s (%s)", claims.Name, claims.Sub), nil
	case claims.Email != "":
		return fmt.Sprintf("%s (%s)", claims.Email, claims.Sub), nil
	case claims.Sub != "":
		return claims.Sub, nil
	}
	return "", fmt.Errorf("token carries no subject")
}
