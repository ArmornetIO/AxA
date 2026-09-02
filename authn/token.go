// Package authn holds identity's locally-validated bearer-credential
// providers — credentials the platform itself issues and verifies (as opposed
// to federated OIDC tokens verified against an upstream IdP). The first member
// is the personal access token (PAT) provider.
//
// authn is part of the open-sourceable identity module and therefore never
// imports the host application (no store, no server/*). Persistence is reached
// only through the narrow interfaces defined here (see PATLookup), which the
// host implements over its own datastore.
//
// It is a leaf and its own module: it imports neither authz nor access nor the
// rest of identity, and access composes it with authz. Constructors follow the rule in package identity's
// documentation.
package authn

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
)

// Token prefixes. The visible prefix is also stored on the row so a UI can show
// a recognizable stub ("anet_user_a8b3…") without revealing the secret.
const (
	TokenPrefixUser  = "anet_user_"
	TokenPrefixAgent = "anet_agent_"
	// TokenPrefixMagic marks a short-lived, single-use magic-link token issued to
	// a third party (e.g. a vendor) who cannot use federated login.
	TokenPrefixMagic = "anet_magic_"
	// TokenPrefixInvite marks a single-use invite a host hands out by link,
	// such as an admission invite.
	TokenPrefixInvite = "anet_invite_"
	tokenBodyLen      = 32 // base32 chars after the prefix
)

var tokenPrefixes = []string{TokenPrefixUser, TokenPrefixAgent, TokenPrefixMagic, TokenPrefixInvite}

// GenerateToken returns a freshly minted token of the given prefix plus 32
// crockford-style base32 characters of entropy (160 bits). The returned value
// is shown to the caller exactly once — only its argon2id hash is persisted.
func GenerateToken(prefix string) (string, error) {
	if !slices.Contains(tokenPrefixes, prefix) {
		return "", errors.New("authn: unsupported token prefix")
	}
	// 20 bytes → 32 chars when encoded with std base32 without padding.
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	body := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
	return prefix + body[:tokenBodyLen], nil
}

// TokenPrefix returns the kind marker plus the first eight characters of the
// body. Used for UI display ("anet_user_a8b3…") and to narrow the lookup before
// the constant-time argon2 verify.
func TokenPrefix(token string) string {
	if len(token) < len(TokenPrefixUser)+8 {
		return token
	}
	for _, p := range tokenPrefixes {
		if strings.HasPrefix(token, p) && len(token) >= len(p)+8 {
			return token[:len(p)+8]
		}
	}
	return token[:8]
}

// RandomToken returns 256 bits of randomness, base64url-encoded without
// padding — the shape every one-shot secret in this module uses: OIDC state and
// nonce, the PKCE verifier, a session token.
//
// An error is never ignorable. A failed read from the system's random source
// means the value would be predictable, and a predictable state parameter is a
// forged callback waiting to be accepted, so every caller must refuse rather
// than continue with whatever it got.
func RandomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
