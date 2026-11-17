package dex

import (
	"crypto/sha256"
	"database/sql"
	"fmt"

	entSQL "entgo.io/ent/dialect/sql"
	_ "github.com/lib/pq"

	"github.com/ArmornetIO/axa"
	"github.com/ArmornetIO/axa/authn/secrethash"
	dexstorage "github.com/ArmornetIO/axa/internal/dex/storage"
	entclient "github.com/ArmornetIO/axa/internal/dex/storage/ent/client"
	entdb "github.com/ArmornetIO/axa/internal/dex/storage/ent/db"
)

// newStorage opens Ent on Postgres; the host migrates, and the fork disables
// Ent's Schema().Create().
func newStorage(databaseURL string, sealer axa.ConfigSealer, deviceGated bool) (dexstorage.Storage, error) {
	if databaseURL == "" {
		return nil, fmt.Errorf("dex: DatabaseURL is required")
	}

	drv, err := entSQL.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("ent: open postgres: %w", err)
	}

	params := secrethash.DefaultArgon2Params()
	opts := []func(*entclient.Database){
		entclient.WithClient(entdb.NewClient(entdb.Driver(drv))),
		entclient.WithHasher(sha256.New),
		entclient.WithTxIsolationLevel(sql.LevelSerializable),
		entclient.WithSecretHasher(func(plaintext string) (string, error) {
			return secrethash.HashToken(plaintext, params)
		}),
		entclient.WithSecretVerifier(secrethash.VerifyToken),
	}
	// Connector configs hold replayable upstream IdP credentials. Sealed at rest
	// when the host supplies a cipher; stored as cleartext JSON when it does not.
	if sealer != nil {
		opts = append(opts,
			entclient.WithFieldSealer(sealer.Seal),
			entclient.WithFieldOpener(sealer.Open),
		)
	}
	// Device codes are bearer credentials and never reach the database as
	// written by the server — see deviceCodeStore.
	db := serializationRetry{Storage: entclient.NewDatabase(opts...)}
	return deviceCodeStore{Storage: db, sealer: sealer, gated: deviceGated}, nil
}
