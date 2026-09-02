package client

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"fmt"
	"hash"
	"strings"
	"time"

	"github.com/ArmornetIO/identity/internal/dex/storage"
	"github.com/ArmornetIO/identity/internal/dex/storage/ent/db"
	"github.com/ArmornetIO/identity/internal/dex/storage/ent/db/authcode"
	"github.com/ArmornetIO/identity/internal/dex/storage/ent/db/authrequest"
	"github.com/ArmornetIO/identity/internal/dex/storage/ent/db/devicerequest"
	"github.com/ArmornetIO/identity/internal/dex/storage/ent/db/devicetoken"
)

var _ storage.Storage = (*Database)(nil)

type Database struct {
	client    *db.Client
	txOptions *sql.TxOptions
	hasher    func() hash.Hash
	// ARMORNET FORK: orgID scopes all storage queries to a single tenant.
	// Set via WithOrgID when constructing a Database for a specific organization.
	// When empty, org filtering is skipped (test / single-tenant use only).
	orgID string
	// ARMORNET FORK: secretHasher hashes a plaintext client secret before storage.
	// When nil, secrets are stored as-is (plaintext). Set via WithSecretHasher.
	secretHasher func(plaintext string) (string, error)
	// ARMORNET FORK: secretVerifier checks a plaintext secret against a stored hash.
	// When nil, falls back to constant-time string equality. Set via WithSecretVerifier.
	secretVerifier func(plaintext, hash string) (bool, error)
	// ARMORNET FORK: fieldSealer/fieldOpener encrypt and decrypt at-rest values
	// that must stay recoverable in plaintext — connector configs and the device
	// flow's stored client secret. Both nil ⇒ values are stored as-is.
	// Set via WithFieldSealer / WithFieldOpener.
	fieldSealer func(plaintext []byte) ([]byte, error)
	fieldOpener func(sealed []byte) ([]byte, error)
}

// NewDatabase returns new database client with set options.
func NewDatabase(opts ...func(*Database)) *Database {
	database := &Database{}
	for _, f := range opts {
		f(database)
	}
	return database
}

// WithClient sets client option of a Database object.
func WithClient(c *db.Client) func(*Database) {
	return func(s *Database) {
		s.client = c
	}
}

// WithHasher sets client option of a Database object.
func WithHasher(h func() hash.Hash) func(*Database) {
	return func(s *Database) {
		s.hasher = h
	}
}

// WithTxIsolationLevel sets correct isolation level for database transactions.
func WithTxIsolationLevel(level sql.IsolationLevel) func(*Database) {
	return func(s *Database) {
		s.txOptions = &sql.TxOptions{Isolation: level}
	}
}

// WithOrgID scopes all storage operations to the given organization.
// ARMORNET FORK: pass the org's ID when constructing a per-org Dex storage instance.
func WithOrgID(id string) func(*Database) {
	return func(s *Database) {
		s.orgID = id
	}
}

// WithSecretHasher sets the function used to hash client secrets before storage.
// ARMORNET FORK: use connections.HashToken to store argon2id hashes instead of plaintext.
func WithSecretHasher(fn func(plaintext string) (string, error)) func(*Database) {
	return func(s *Database) {
		s.secretHasher = fn
	}
}

// WithSecretVerifier sets the function used to verify a plaintext secret against
// a stored hash. ARMORNET FORK: use connections.VerifyToken for argon2id secrets.
func WithSecretVerifier(fn func(plaintext, hash string) (bool, error)) func(*Database) {
	return func(s *Database) {
		s.secretVerifier = fn
	}
}

// WithFieldSealer sets the function used to encrypt at-rest field values that
// must stay recoverable in plaintext. ARMORNET FORK.
//
// Two kinds of stored value need this, and neither can be hashed the way a
// client secret is:
//
//   - connector configs, which carry upstream IdP credentials (OIDC/GitHub/
//     Google clientSecret, SAML signing keys) that Dex must replay to the
//     upstream provider on every login;
//   - device_requests.client_secret, which holds the confidential client's own
//     secret for the duration of a device-authorization flow.
//
// The cipher is supplied by the host (armornet uses the platform AES-256-GCM
// field cipher keyed by ARMORNET_KEK) so this module needs no crypto dependency
// of its own.
//
// Unset ⇒ values are stored as-is, which is upstream Dex behaviour.
func WithFieldSealer(fn func(plaintext []byte) ([]byte, error)) func(*Database) {
	return func(s *Database) {
		s.fieldSealer = fn
	}
}

// WithFieldOpener sets the function used to decrypt an at-rest field value on
// read. ARMORNET FORK. Must be set whenever WithFieldSealer is, and must
// tolerate values written before sealing was enabled — see WithFieldSealer.
func WithFieldOpener(fn func(sealed []byte) ([]byte, error)) func(*Database) {
	return func(s *Database) {
		s.fieldOpener = fn
	}
}

// sealField encrypts a value for storage. Returns it unchanged when no sealer
// is configured.
func (d *Database) sealField(plaintext []byte) ([]byte, error) {
	if d.fieldSealer == nil || len(plaintext) == 0 {
		return plaintext, nil
	}
	return d.fieldSealer(plaintext)
}

// openField decrypts a stored value. Returns it unchanged when no opener is
// configured.
func (d *Database) openField(sealed []byte) ([]byte, error) {
	if d.fieldOpener == nil || len(sealed) == 0 {
		return sealed, nil
	}
	return d.fieldOpener(sealed)
}

// SealedStringPrefix marks a text column value as sealed. ARMORNET FORK.
//
// The marker is explicit rather than inferred. Detecting "is this sealed?" by
// trying a base64 decode does not work: client secrets are themselves usually
// base64, so a legacy cleartext secret would decode successfully and be
// mistaken for ciphertext. It is also what makes the state checkable in SQL —
// see the sealed-only CHECK constraints in the migrations.
const SealedStringPrefix = "ANS1:"

// sealFieldString is sealField for columns typed as text rather than bytea. The
// sealed bytes are base64-encoded to survive a text column and tagged with
// SealedStringPrefix.
func (d *Database) sealFieldString(plaintext string) (string, error) {
	if d.fieldSealer == nil || plaintext == "" {
		return plaintext, nil
	}
	sealed, err := d.sealField([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return SealedStringPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// openFieldString reverses sealFieldString.
//
// With a sealer configured, an unmarked value is an error rather than a
// cleartext fallback: device_requests rows are ephemeral, so migration 0094
// deleted the unsealed ones outright and its CHECK constraint prevents new ones.
// There is therefore no legitimate unmarked row left to tolerate, and accepting
// one would mean reading a secret that something wrote around the constraint.
//
// With no sealer configured the value is returned unchanged — that deployment
// never sealed anything and has nothing to decrypt.
func (d *Database) openFieldString(stored string) (string, error) {
	if d.fieldOpener == nil || stored == "" {
		return stored, nil
	}
	if !strings.HasPrefix(stored, SealedStringPrefix) {
		return "", fmt.Errorf("stored secret is not sealed (missing %q marker)", SealedStringPrefix)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, SealedStringPrefix))
	if err != nil {
		return "", fmt.Errorf("sealed value is tagged but not valid base64: %w", err)
	}
	opened, err := d.openField(raw)
	if err != nil {
		return "", err
	}
	return string(opened), nil
}

// VerifyClientSecret reports whether plaintext matches the stored secret value.
// When a secretVerifier is configured it is tried first; if the stored value is
// not in the expected hash format, it falls back to constant-time equality so
// existing plaintext records continue to work during the migration window.
// ARMORNET FORK: used by the server layer instead of a raw ConstantTimeCompare.
func (d *Database) VerifyClientSecret(stored, plaintext string) bool {
	if d.secretVerifier != nil {
		ok, err := d.secretVerifier(plaintext, stored)
		if err == nil {
			return ok
		}
		// err means stored value is not in the hash format — fall through to plaintext compare.
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(plaintext)) == 1
}

// hashSecret hashes plaintext using the configured secretHasher.
// Returns plaintext unchanged when no hasher is configured.
func (d *Database) hashSecret(plaintext string) (string, error) {
	if d.secretHasher == nil || plaintext == "" {
		return plaintext, nil
	}
	return d.secretHasher(plaintext)
}

// secretForUpdate decides what to persist for a client secret on update.
// ARMORNET FORK.
//
// UpdateClient hands its updater the client as stored, and the stored secret is
// already a hash. An updater that only changes metadata — every rename and
// redirect-URI edit — returns that hash back unchanged. Hashing it again would
// persist H(H(secret)), and the client could never authenticate: the token
// endpoint verifies the presented plaintext against the stored value, which no
// longer corresponds to it, and the real hash is gone with no way to recover it.
// A cosmetic edit would silently brick the credential.
//
// So an unchanged secret is passed through untouched, and only a genuinely new
// one is hashed. The comparison is a plain != because both values are opaque
// storage values here, not a secret being verified — there is nothing to leak by
// timing, and a non-constant-time compare of two stored values is not a check an
// attacker can steer.
func (d *Database) secretForUpdate(stored, updated string) (string, error) {
	if updated == stored {
		return stored, nil
	}
	return d.hashSecret(updated)
}

// Close calls the corresponding method of the ent database client.
func (d *Database) Close() error {
	return d.client.Close()
}

// BeginTx is a wrapper to begin transaction with defined options.
func (d *Database) BeginTx(ctx context.Context) (*db.Tx, error) {
	return d.client.BeginTx(ctx, d.txOptions)
}

// GarbageCollect removes expired entities from the database.
// ARMORNET FORK: errors if orgID is unset — GC must never delete across org boundaries.
func (d *Database) GarbageCollect(ctx context.Context, now time.Time) (storage.GCResult, error) {
	if err := d.requireOrgID(); err != nil {
		return storage.GCResult{}, err
	}
	result := storage.GCResult{}
	utcNow := now.UTC()

	q, err := d.client.AuthRequest.Delete().
		Where(authrequest.ExpiryLT(utcNow), authrequest.OrgID(d.orgID)).
		Exec(ctx)
	if err != nil {
		return result, convertDBError("gc auth request: %w", err)
	}
	result.AuthRequests = int64(q)

	q, err = d.client.AuthCode.Delete().
		Where(authcode.ExpiryLT(utcNow), authcode.OrgID(d.orgID)).
		Exec(ctx)
	if err != nil {
		return result, convertDBError("gc auth code: %w", err)
	}
	result.AuthCodes = int64(q)

	q, err = d.client.DeviceRequest.Delete().
		Where(devicerequest.ExpiryLT(utcNow), devicerequest.OrgID(d.orgID)).
		Exec(ctx)
	if err != nil {
		return result, convertDBError("gc device request: %w", err)
	}
	result.DeviceRequests = int64(q)

	q, err = d.client.DeviceToken.Delete().
		Where(devicetoken.ExpiryLT(utcNow), devicetoken.OrgID(d.orgID)).
		Exec(ctx)
	if err != nil {
		return result, convertDBError("gc device token: %w", err)
	}
	result.DeviceTokens = int64(q)

	return result, err
}
