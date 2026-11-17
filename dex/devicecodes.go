package dex

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log/slog"

	"github.com/ArmornetIO/axa"
	"github.com/ArmornetIO/axa/authn"
	dexstorage "github.com/ArmornetIO/axa/internal/dex/storage"
	entclient "github.com/ArmornetIO/axa/internal/dex/storage/ent/client"
)

// deviceCodeStore keeps device codes (bearer credentials, raw upstream) out of
// the DB: requests' copy SEALED (must come back), tokens' HASHED (lookup key).
type deviceCodeStore struct {
	dexstorage.Storage
	sealer axa.ConfigSealer
	// gated grants a code only to its approver (deviceapproval.go).
	gated bool
}

func (s deviceCodeStore) CreateDeviceRequest(ctx context.Context, req dexstorage.DeviceRequest) error {
	sealed, err := s.seal(req.DeviceCode)
	if err != nil {
		return fmt.Errorf("dex: seal device code: %w", err)
	}
	req.DeviceCode = sealed
	return s.Storage.CreateDeviceRequest(ctx, req)
}

func (s deviceCodeStore) GetDeviceRequest(ctx context.Context, userCode string) (dexstorage.DeviceRequest, error) {
	req, err := s.Storage.GetDeviceRequest(ctx, userCode)
	if err != nil {
		return req, err
	}
	opened, err := s.open(req.DeviceCode)
	if err != nil {
		return dexstorage.DeviceRequest{}, fmt.Errorf("dex: open device code: %w", err)
	}
	req.DeviceCode = opened
	return req, nil
}

func (s deviceCodeStore) CreateDeviceToken(ctx context.Context, token dexstorage.DeviceToken) error {
	token.DeviceCode = hashDeviceCode(token.DeviceCode)
	return s.Storage.CreateDeviceToken(ctx, token)
}

func (s deviceCodeStore) GetDeviceToken(ctx context.Context, deviceCode string) (dexstorage.DeviceToken, error) {
	return s.Storage.GetDeviceToken(ctx, hashDeviceCode(deviceCode))
}

func (s deviceCodeStore) UpdateDeviceToken(ctx context.Context, deviceCode string, updater func(old dexstorage.DeviceToken) (dexstorage.DeviceToken, error)) error {
	hashed := hashDeviceCode(deviceCode)
	// Pin the digest so no updater can write a cleartext code.
	return s.Storage.UpdateDeviceToken(ctx, hashed, func(old dexstorage.DeviceToken) (dexstorage.DeviceToken, error) {
		next, err := updater(old)
		if err != nil {
			return next, err
		}
		if s.gated && next.Status == deviceTokenComplete && old.Status != deviceTokenComplete {
			if err := approvedFor(ctx, next.Token); err != nil {
				slog.WarnContext(ctx, "dex: device grant refused", "err", err)
				return old, err
			}
		}
		next.DeviceCode = hashed
		return next, nil
	})
}

// hashDeviceCode is the at-rest form of a device code used as a lookup key.
func hashDeviceCode(code string) string {
	if code == "" {
		return ""
	}
	return authn.HashSessionToken(code)
}

// seal and open copy the fork's ANS1+base64 framing, which the CHECK tests for.
func (s deviceCodeStore) seal(plaintext string) (string, error) {
	if s.sealer == nil || plaintext == "" {
		return plaintext, nil
	}
	sealed, err := s.sealer.Seal([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return entclient.SealedStringPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

func (s deviceCodeStore) open(stored string) (string, error) {
	if s.sealer == nil || stored == "" {
		return stored, nil
	}
	// Unmarked means something wrote around this wrapper: refuse, never read it.
	if len(stored) < len(entclient.SealedStringPrefix) || stored[:len(entclient.SealedStringPrefix)] != entclient.SealedStringPrefix {
		return "", fmt.Errorf("stored device code is not sealed (missing %q marker)", entclient.SealedStringPrefix)
	}
	raw, err := base64.StdEncoding.DecodeString(stored[len(entclient.SealedStringPrefix):])
	if err != nil {
		return "", fmt.Errorf("sealed device code is tagged but not valid base64: %w", err)
	}
	opened, err := s.sealer.Open(raw)
	if err != nil {
		return "", err
	}
	return string(opened), nil
}

func (s deviceCodeStore) VerifyClientSecret(stored, plaintext string) bool {
	return verifyClientSecret(s.Storage, stored, plaintext)
}

// verifyClientSecret passes through the type-asserted argon2id check that a
// wrapper would hide (every client → invalid_client). Every wrapper owes this.
func verifyClientSecret(inner dexstorage.Storage, stored, plaintext string) bool {
	type clientSecretVerifier interface {
		VerifyClientSecret(stored, plaintext string) bool
	}
	if v, ok := inner.(clientSecretVerifier); ok {
		return v.VerifyClientSecret(stored, plaintext)
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(plaintext)) == 1
}
