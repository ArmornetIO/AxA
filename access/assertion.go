package access

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Issuer is the iss of every assertion. Verification requires it exactly.
const Issuer = "armornet-access"

// Header is where the destination reads the assertion.
const Header = "X-Armornet-Access-Assertion"

// MaxTTL is how long a revoked subject keeps access: revocation is just no new
// assertion.
const MaxTTL = 5 * time.Minute

// Leeway absorbs clock skew between the minting and the verifying process.
const Leeway = 30 * time.Second

var (
	ErrInvalid = errors.New("access: invalid assertion")
	ErrExpired = errors.New("access: assertion expired")
)

// Claims is what a verified assertion says.
type Claims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	IssuedAt int64  `json:"iat"`
	Expiry   int64  `json:"exp"`
	ID       string `json:"jti"`
	Source   string `json:"src,omitempty"`
}

// header is fixed and compared exactly, so JWT alg confusion ("none", HS256 with
// the public key) has nothing to act on.
type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

const alg = "EdDSA"

// KeySet signs with one key and verifies with any it lists, so a rotation can
// add the new key everywhere before any process starts signing with it.
type KeySet struct {
	signKID string
	sign    ed25519.PrivateKey
	verify  map[string]ed25519.PublicKey
}

// ParseKeySet: signing "kid:base64seed" (empty to only verify), verify
// "kid:base64pub,…"; the signing key's public half is always verifiable.
func ParseKeySet(signing, verify string) (*KeySet, error) {
	ks := &KeySet{verify: map[string]ed25519.PublicKey{}}
	for _, entry := range strings.Split(verify, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		kid, raw, err := splitKey(entry)
		if err != nil {
			return nil, err
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("access: verify key %q is not an Ed25519 public key", kid)
		}
		ks.verify[kid] = ed25519.PublicKey(raw)
	}
	if signing = strings.TrimSpace(signing); signing != "" {
		kid, raw, err := splitKey(signing)
		if err != nil {
			return nil, err
		}
		if len(raw) != ed25519.SeedSize {
			return nil, fmt.Errorf("access: signing key %q is not an Ed25519 seed", kid)
		}
		ks.signKID, ks.sign = kid, ed25519.NewKeyFromSeed(raw)
		ks.verify[kid] = ks.sign.Public().(ed25519.PublicKey)
	}
	return ks, nil
}

func splitKey(entry string) (string, []byte, error) {
	kid, b64, ok := strings.Cut(entry, ":")
	if !ok || kid == "" || b64 == "" {
		return "", nil, errors.New("access: key must be kid:base64")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", nil, fmt.Errorf("access: key %q: %w", kid, err)
	}
	return kid, raw, nil
}

// CanVerify reports whether any verify key is configured.
func (k *KeySet) CanVerify() bool { return k != nil && len(k.verify) > 0 }

// CanSign reports whether a signing key is configured.
func (k *KeySet) CanSign() bool { return k != nil && k.sign != nil }

// Mint signs an assertion that sub may reach aud until now+ttl.
func (k *KeySet) Mint(sub, aud, src string, ttl time.Duration, now time.Time) (string, time.Time, error) {
	if !k.CanSign() {
		return "", time.Time{}, errors.New("access: no signing key")
	}
	if sub == "" || aud == "" {
		return "", time.Time{}, errors.New("access: subject and audience are required")
	}
	if ttl <= 0 || ttl > MaxTTL {
		return "", time.Time{}, fmt.Errorf("access: ttl %s outside (0, %s]", ttl, MaxTTL)
	}
	var jti [16]byte
	if _, err := rand.Read(jti[:]); err != nil {
		return "", time.Time{}, err
	}
	exp := now.Add(ttl)
	h, _ := json.Marshal(header{Alg: alg, Typ: "JWT", Kid: k.signKID})
	c, _ := json.Marshal(Claims{
		Issuer: Issuer, Subject: sub, Audience: aud,
		IssuedAt: now.Unix(), Expiry: exp.Unix(),
		ID: hex.EncodeToString(jti[:]), Source: src,
	})
	signing := b64(h) + "." + b64(c)
	sig := ed25519.Sign(k.sign, []byte(signing))
	return signing + "." + b64(sig), exp, nil
}

// Verify checks signature, issuer, audience and lifetime, and returns the
// claims only if every one holds.
func (k *KeySet) Verify(token, aud string, now time.Time) (Claims, error) {
	if !k.CanVerify() {
		return Claims{}, ErrInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, ErrInvalid
	}
	var h header
	if err := decodeJSON(parts[0], &h); err != nil || h.Alg != alg || h.Typ != "JWT" {
		return Claims{}, ErrInvalid
	}
	pub, ok := k.verify[h.Kid]
	if !ok {
		return Claims{}, ErrInvalid
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return Claims{}, ErrInvalid
	}
	var c Claims
	if err := decodeJSON(parts[1], &c); err != nil {
		return Claims{}, ErrInvalid
	}
	if c.Issuer != Issuer || c.Subject == "" || aud == "" || c.Audience != aud {
		return Claims{}, ErrInvalid
	}
	iat, exp := time.Unix(c.IssuedAt, 0), time.Unix(c.Expiry, 0)
	// A token claiming a longer life than MaxTTL was not minted by Mint; refuse
	// it even though the signature holds, so a leaked key cannot mint forever.
	if !exp.After(iat) || exp.Sub(iat) > MaxTTL {
		return Claims{}, ErrInvalid
	}
	if iat.After(now.Add(Leeway)) {
		return Claims{}, ErrInvalid
	}
	if now.After(exp.Add(Leeway)) {
		return Claims{}, ErrExpired
	}
	return c, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func decodeJSON(seg string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
