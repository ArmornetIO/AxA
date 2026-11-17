package dex

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/lib/pq"

	dexstorage "github.com/ArmornetIO/axa/internal/dex/storage"
)

// maxTxAttempts bounds the retries. Sixty-four sign-ins landing at once all
// settled inside it (TestConcurrentAuthRequestUpdates at logins=64); the
// ceiling keeps a pathological loop from holding a request open.
const maxTxAttempts = 10

// serializationRetry re-runs every storage update that Postgres aborts as a
// serialization failure. The Ent client opens its transactions SERIALIZABLE,
// which Postgres only makes safe for a caller that retries: on a small table
// its predicate locks cover whole pages, so concurrent sign-ins touching
// different auth requests abort one another (40001), and Dex served each loser
// a "Login error" page. Every attempt is a fresh transaction that re-reads the
// row, so the updater always sees current data.
//
// Only the updates need it: they are the only methods that open a transaction.
type serializationRetry struct {
	dexstorage.Storage
}

func retrySerialization(ctx context.Context, fn func() error) error {
	for attempt := 1; ; attempt++ {
		err := fn()
		if attempt == maxTxAttempts || !isSerializationFailure(err) {
			return err
		}
		// Jittered, so the transactions that collided do not collide again.
		backoff := time.Duration(attempt) * time.Duration(1+rand.IntN(5)) * time.Millisecond
		select {
		case <-ctx.Done():
			return err
		case <-time.After(backoff):
		}
	}
}

// isSerializationFailure is SQLSTATE 40001, or 40P01 for a deadlock, which
// Postgres resolves the same way: abort one side and expect it to retry.
func isSerializationFailure(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && (pqErr.Code == "40001" || pqErr.Code == "40P01")
}

func (s serializationRetry) VerifyClientSecret(stored, plaintext string) bool {
	return verifyClientSecret(s.Storage, stored, plaintext)
}

func (s serializationRetry) UpdateClient(ctx context.Context, id string, updater func(dexstorage.Client) (dexstorage.Client, error)) error {
	return retrySerialization(ctx, func() error { return s.Storage.UpdateClient(ctx, id, updater) })
}

func (s serializationRetry) UpdateKeys(ctx context.Context, updater func(dexstorage.Keys) (dexstorage.Keys, error)) error {
	return retrySerialization(ctx, func() error { return s.Storage.UpdateKeys(ctx, updater) })
}

func (s serializationRetry) UpdateAuthRequest(ctx context.Context, id string, updater func(dexstorage.AuthRequest) (dexstorage.AuthRequest, error)) error {
	return retrySerialization(ctx, func() error { return s.Storage.UpdateAuthRequest(ctx, id, updater) })
}

func (s serializationRetry) UpdateRefreshToken(ctx context.Context, id string, updater func(dexstorage.RefreshToken) (dexstorage.RefreshToken, error)) error {
	return retrySerialization(ctx, func() error { return s.Storage.UpdateRefreshToken(ctx, id, updater) })
}

func (s serializationRetry) UpdatePassword(ctx context.Context, email string, updater func(dexstorage.Password) (dexstorage.Password, error)) error {
	return retrySerialization(ctx, func() error { return s.Storage.UpdatePassword(ctx, email, updater) })
}

func (s serializationRetry) UpdateOfflineSessions(ctx context.Context, userID, connID string, updater func(dexstorage.OfflineSessions) (dexstorage.OfflineSessions, error)) error {
	return retrySerialization(ctx, func() error { return s.Storage.UpdateOfflineSessions(ctx, userID, connID, updater) })
}

func (s serializationRetry) UpdateConnector(ctx context.Context, id string, updater func(dexstorage.Connector) (dexstorage.Connector, error)) error {
	return retrySerialization(ctx, func() error { return s.Storage.UpdateConnector(ctx, id, updater) })
}

func (s serializationRetry) UpdateDeviceToken(ctx context.Context, deviceCode string, updater func(dexstorage.DeviceToken) (dexstorage.DeviceToken, error)) error {
	return retrySerialization(ctx, func() error { return s.Storage.UpdateDeviceToken(ctx, deviceCode, updater) })
}
