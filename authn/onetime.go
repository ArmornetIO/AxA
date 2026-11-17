package authn

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/ArmornetIO/axa/authn/secrethash"
)

// Single-use link tokens: the mechanism a magic link, an admission invite, and
// any other "hand someone a link that works once" share. What a redeemed token
// GRANTS is the caller's business; this file only answers whether the raw token
// is one we issued, is live, and is being redeemed for the first time.
//
// The token is shown once and only its argon2id hash is stored, beside its
// prefix so a redeem narrows the lookup before the constant-time verify.

// ErrTokenInvalid is every redeem failure — unknown, malformed, expired, revoked
// or already used — as one error, so a redeemer cannot tell them apart.
var ErrTokenInvalid = errors.New("authn: token invalid or expired")

// MintedToken is a freshly issued single-use token. Raw goes to the recipient
// exactly once; Prefix and Hash are what the host persists.
type MintedToken struct {
	Raw    string
	Prefix string
	Hash   string
}

// MintToken issues a single-use token of the given kind prefix.
func MintToken(prefix string, params secrethash.Argon2idParams) (MintedToken, error) {
	raw, err := GenerateToken(prefix)
	if err != nil {
		return MintedToken{}, err
	}
	hash, err := secrethash.HashToken(raw, params)
	if err != nil {
		return MintedToken{}, err
	}
	return MintedToken{Raw: raw, Prefix: TokenPrefix(raw), Hash: hash}, nil
}

// StoredToken is the part of a host's record a redeem needs to judge it.
type StoredToken struct {
	ID        string
	Hash      string
	ExpiresAt time.Time
}

// RedeemToken returns the first candidate whose hash matches raw, is unexpired,
// and is won by consume — the host's atomic "mark used" write, which is what
// makes two concurrent redeems of one link produce one winner.
//
// cands are the host's live records for TokenPrefix(raw); stored projects one
// onto the fields judged here, so any record type can be redeemed without the
// host copying it into a shared shape first.
func RedeemToken[T any](
	ctx context.Context,
	prefix, raw string,
	cands []T,
	stored func(T) StoredToken,
	consume func(ctx context.Context, id string) (bool, error),
) (T, error) {
	var zero T
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.HasPrefix(raw, prefix) {
		return zero, ErrTokenInvalid
	}
	now := time.Now()
	for _, c := range cands {
		s := stored(c)
		if now.After(s.ExpiresAt) {
			continue
		}
		if ok, err := secrethash.VerifyToken(raw, s.Hash); err != nil || !ok {
			continue
		}
		won, err := consume(ctx, s.ID)
		if err != nil {
			return zero, errors.Join(ErrTokenInvalid, err)
		}
		if won {
			return c, nil
		}
	}
	return zero, ErrTokenInvalid
}
