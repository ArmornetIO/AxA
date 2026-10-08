// Package secrethash provides argon2id password/secret hashing with PHC-style
// encoded output. It is copied from the armornet connections package so the
// identity module carries no dependency on armornet internals.
package secrethash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2idParams are the work factors used for new PAT hashes. They follow
// the OWASP 2024 recommendations: 64 MiB memory, 1 iteration, 4 lanes.
// Existing hashes carry their own parameters in the encoded string so these
// can be tuned upward later without breaking verification of older tokens.
type Argon2idParams struct {
	Memory  uint32 // KiB
	Time    uint32
	Threads uint8
	KeyLen  uint32
	SaltLen uint32
}

// DefaultArgon2Params returns the parameters used for newly issued PATs.
func DefaultArgon2Params() Argon2idParams {
	return Argon2idParams{
		Memory:  64 * 1024,
		Time:    1,
		Threads: 4,
		KeyLen:  32,
		SaltLen: 16,
	}
}

// HashToken derives an argon2id hash of token using p and returns the
// standard PHC-style encoded string ($argon2id$v=19$m=…,t=…,p=…$salt$hash).
func HashToken(token string, p Argon2idParams) (string, error) {
	if token == "" {
		return "", errors.New("secrethash: empty token")
	}
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("secrethash: read salt: %w", err)
	}
	hash := argon2.IDKey([]byte(token), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	return encodeArgon2id(p, salt, hash), nil
}

// VerifyToken returns true when token matches the encoded argon2id hash.
// Uses constant-time comparison; rejects malformed or non-argon2id strings.
func VerifyToken(token, encoded string) (bool, error) {
	p, salt, want, err := decodeArgon2id(encoded)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(token), salt, p.Time, p.Memory, p.Threads, uint32(len(want))) // #nosec G115 -- length of a decoded hash, bounded far below 32 bits
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func encodeArgon2id(p Argon2idParams, salt, hash []byte) string {
	b64 := base64.RawStdEncoding.EncodeToString
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Threads, b64(salt), b64(hash),
	)
}

func decodeArgon2id(encoded string) (Argon2idParams, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return Argon2idParams{}, nil, nil, errors.New("secrethash: not an argon2id hash")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return Argon2idParams{}, nil, nil, fmt.Errorf("secrethash: parse version: %w", err)
	}
	if version != argon2.Version {
		return Argon2idParams{}, nil, nil, fmt.Errorf("secrethash: unsupported argon2 version %d", version)
	}
	var p Argon2idParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Threads); err != nil {
		return Argon2idParams{}, nil, nil, fmt.Errorf("secrethash: parse params: %w", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Argon2idParams{}, nil, nil, fmt.Errorf("secrethash: decode salt: %w", err)
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Argon2idParams{}, nil, nil, fmt.Errorf("secrethash: decode hash: %w", err)
	}
	p.SaltLen = uint32(len(salt)) // #nosec G115 -- length of a decoded salt, bounded far below 32 bits
	p.KeyLen = uint32(len(hash))  // #nosec G115 -- length of a decoded hash, bounded far below 32 bits
	return p, salt, hash, nil
}
