package pgstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ArmornetIO/identity/authn"
	"github.com/lib/pq"
)

// MFAChallengeStore checks `expires_at > now()` on every read: a late purge must
// not become an accepted challenge.
type MFAChallengeStore struct {
	db *sql.DB
}

func NewMFAChallengeStore(db *sql.DB) *MFAChallengeStore { return &MFAChallengeStore{db: db} }

var _ authn.MFAChallengeStore = (*MFAChallengeStore)(nil)

func (s *MFAChallengeStore) Create(ctx context.Context, c authn.MFAChallenge) error {
	const q = `
INSERT INTO mfa_challenges (id, subject, org_id, token_expiry, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, now())`
	if _, err := s.db.ExecContext(ctx, q, c.ID, c.Subject, c.OrgID, c.TokenExpiry, c.ExpiresAt); err != nil {
		return fmt.Errorf("pgstore: create mfa challenge: %w", err)
	}
	return nil
}

func (s *MFAChallengeStore) Get(ctx context.Context, id string) (authn.MFAChallenge, error) {
	const q = `
SELECT id, subject, org_id, token_expiry, attempt_count, expires_at, created_at
FROM mfa_challenges
WHERE id = $1 AND expires_at > now()`
	var c authn.MFAChallenge
	err := s.db.QueryRowContext(ctx, q, id).
		Scan(&c.ID, &c.Subject, &c.OrgID, &c.TokenExpiry, &c.AttemptCount, &c.ExpiresAt, &c.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return authn.MFAChallenge{}, authn.ErrNoChallenge
	}
	if err != nil {
		return authn.MFAChallenge{}, fmt.Errorf("pgstore: get mfa challenge: %w", err)
	}
	return c, nil
}

// Consume is DELETE..RETURNING, so two racing verifications cannot both pass.
func (s *MFAChallengeStore) Consume(ctx context.Context, id string) (authn.MFAChallenge, error) {
	const q = `
DELETE FROM mfa_challenges
WHERE id = $1 AND expires_at > now()
RETURNING subject, org_id, token_expiry, attempt_count, expires_at, created_at`
	c := authn.MFAChallenge{ID: id}
	err := s.db.QueryRowContext(ctx, q, id).
		Scan(&c.Subject, &c.OrgID, &c.TokenExpiry, &c.AttemptCount, &c.ExpiresAt, &c.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return authn.MFAChallenge{}, authn.ErrNoChallenge
	}
	if err != nil {
		return authn.MFAChallenge{}, fmt.Errorf("pgstore: consume mfa challenge: %w", err)
	}
	return c, nil
}

func (s *MFAChallengeStore) IncrAttemptCount(ctx context.Context, id string) (int, error) {
	const q = `
UPDATE mfa_challenges
SET attempt_count = attempt_count + 1
WHERE id = $1 AND expires_at > now()
RETURNING attempt_count`
	var n int
	err := s.db.QueryRowContext(ctx, q, id).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, authn.ErrNoChallenge
	}
	if err != nil {
		return 0, fmt.Errorf("pgstore: incr mfa challenge attempts: %w", err)
	}
	return n, nil
}

func (s *MFAChallengeStore) Purge(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM mfa_challenges WHERE expires_at < now()`); err != nil {
		return fmt.Errorf("pgstore: purge mfa challenges: %w", err)
	}
	return nil
}

// TOTPStore seals rather than hashes: the secret must come back out, and anyone
// holding it mints codes forever. enc may be nil (see authn.Encrypter).
type TOTPStore struct {
	db  *sql.DB
	enc authn.Encrypter
}

func NewTOTPStore(db *sql.DB, enc authn.Encrypter) *TOTPStore {
	return &TOTPStore{db: db, enc: enc}
}

var _ authn.TOTPStore = (*TOTPStore)(nil)

func (s *TOTPStore) wrap(b []byte) ([]byte, error) {
	if s.enc == nil || len(b) == 0 {
		return b, nil
	}
	return s.enc.Wrap(b)
}

func (s *TOTPStore) unwrap(b []byte) ([]byte, error) {
	if s.enc == nil || len(b) == 0 {
		return b, nil
	}
	return s.enc.Unwrap(b)
}

// Upsert resets enrolled and last_used_at: both described the old secret.
func (s *TOTPStore) Upsert(ctx context.Context, subject string, secret []byte) error {
	enc, err := s.wrap(secret)
	if err != nil {
		return fmt.Errorf("pgstore: wrap totp secret: %w", err)
	}
	const q = `
INSERT INTO user_totp_credentials (subject, secret, enrolled, created_at)
VALUES ($1, $2, false, now())
ON CONFLICT (subject) DO UPDATE
    SET secret = EXCLUDED.secret, enrolled = false, created_at = now(), last_used_at = NULL`
	if _, err := s.db.ExecContext(ctx, q, subject, enc); err != nil {
		return fmt.Errorf("pgstore: upsert totp credential: %w", err)
	}
	return nil
}

func (s *TOTPStore) Get(ctx context.Context, subject string) (authn.TOTPCredential, error) {
	const q = `
SELECT subject, secret, enrolled, created_at, last_used_at
FROM user_totp_credentials
WHERE subject = $1`
	var (
		cred     authn.TOTPCredential
		enc      []byte
		lastUsed sql.NullTime
	)
	err := s.db.QueryRowContext(ctx, q, subject).
		Scan(&cred.Subject, &enc, &cred.Enrolled, &cred.CreatedAt, &lastUsed)
	if errors.Is(err, sql.ErrNoRows) {
		return authn.TOTPCredential{}, authn.ErrNoTOTPCredential
	}
	if err != nil {
		return authn.TOTPCredential{}, fmt.Errorf("pgstore: get totp credential: %w", err)
	}
	if cred.Secret, err = s.unwrap(enc); err != nil {
		return authn.TOTPCredential{}, fmt.Errorf("pgstore: unwrap totp secret: %w", err)
	}
	if lastUsed.Valid {
		t := lastUsed.Time
		cred.LastUsedAt = &t
	}
	return cred, nil
}

// SetEnrolled stamps last_used_at: the enrolling code was itself a use.
func (s *TOTPStore) SetEnrolled(ctx context.Context, subject string) error {
	const q = `UPDATE user_totp_credentials SET enrolled = true, last_used_at = $2 WHERE subject = $1`
	if _, err := s.db.ExecContext(ctx, q, subject, time.Now().UTC()); err != nil {
		return fmt.Errorf("pgstore: set totp enrolled: %w", err)
	}
	return nil
}

func (s *TOTPStore) UpdateLastUsed(ctx context.Context, subject string, t time.Time) error {
	const q = `UPDATE user_totp_credentials SET last_used_at = $2 WHERE subject = $1`
	if _, err := s.db.ExecContext(ctx, q, subject, t); err != nil {
		return fmt.Errorf("pgstore: update totp last used: %w", err)
	}
	return nil
}

func (s *TOTPStore) Delete(ctx context.Context, subject string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM user_totp_credentials WHERE subject = $1`, subject); err != nil {
		return fmt.Errorf("pgstore: delete totp credential: %w", err)
	}
	return nil
}

// WebAuthnCredentialStore seals nothing: the key is public and the id must match.
type WebAuthnCredentialStore struct {
	db *sql.DB
}

func NewWebAuthnCredentialStore(db *sql.DB) *WebAuthnCredentialStore {
	return &WebAuthnCredentialStore{db: db}
}

var _ authn.WebAuthnCredentialStore = (*WebAuthnCredentialStore)(nil)

func (s *WebAuthnCredentialStore) Create(ctx context.Context, c authn.WebAuthnCredential) error {
	// NULL, not empty: "no attestation returned" differs from "attestation lost".
	var attestation any
	if len(c.AttestationObject) > 0 {
		attestation = c.AttestationObject
	}

	const q = `
INSERT INTO webauthn_credentials
    (id, subject, public_key, attestation_type, transport, aaguid, sign_count,
     clone_warning, flag_user_present, flag_user_verified, flag_backup_eligible,
     flag_backup_state, attestation_object, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, now())`
	_, err := s.db.ExecContext(ctx, q,
		c.ID, c.Subject, c.PublicKey, c.AttestationType, pq.Array(c.Transport), c.AAGUID,
		int64(c.SignCount), c.CloneWarning,
		c.Flags.UserPresent, c.Flags.UserVerified, c.Flags.BackupEligible, c.Flags.BackupState,
		attestation,
	)
	if err != nil {
		return fmt.Errorf("pgstore: create webauthn credential: %w", err)
	}
	return nil
}

func (s *WebAuthnCredentialStore) ListBySubject(ctx context.Context, subject string) ([]authn.WebAuthnCredential, error) {
	const q = `
SELECT id, subject, public_key, attestation_type, transport, aaguid, sign_count,
       clone_warning, flag_user_present, flag_user_verified, flag_backup_eligible,
       flag_backup_state, attestation_object, created_at
FROM webauthn_credentials
WHERE subject = $1
ORDER BY created_at ASC`
	rows, err := s.db.QueryContext(ctx, q, subject)
	if err != nil {
		return nil, fmt.Errorf("pgstore: list webauthn credentials: %w", err)
	}
	defer rows.Close()

	out := []authn.WebAuthnCredential{}
	for rows.Next() {
		var (
			c         authn.WebAuthnCredential
			transport pq.StringArray
			signCount int64
		)
		if err := rows.Scan(
			&c.ID, &c.Subject, &c.PublicKey, &c.AttestationType, &transport, &c.AAGUID,
			&signCount, &c.CloneWarning,
			&c.Flags.UserPresent, &c.Flags.UserVerified, &c.Flags.BackupEligible, &c.Flags.BackupState,
			&c.AttestationObject, &c.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("pgstore: scan webauthn credential: %w", err)
		}
		// bigint on the way out because Postgres has no unsigned integer; the
		// column is the counter's 32-bit range widened, never a larger value.
		c.SignCount = uint32(signCount) // #nosec G115 -- see above: the column never holds more than the counter's 32-bit range
		c.Transport = []string(transport)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstore: iterate webauthn credentials: %w", err)
	}
	return out, nil
}

// UpdateSignCount never writes flag_backup_eligible: a compromised assertion could
// relabel a device-bound key as syncable.
func (s *WebAuthnCredentialStore) UpdateSignCount(ctx context.Context, id []byte, signCount uint32, cloneWarning bool, flags authn.WebAuthnCredentialFlags) error {
	const q = `
UPDATE webauthn_credentials
SET sign_count         = $2,
    clone_warning      = $3,
    flag_user_present  = $4,
    flag_user_verified = $5,
    flag_backup_state  = $6
WHERE id = $1`
	_, err := s.db.ExecContext(ctx, q,
		id, int64(signCount), cloneWarning,
		flags.UserPresent, flags.UserVerified, flags.BackupState,
	)
	if err != nil {
		return fmt.Errorf("pgstore: update webauthn sign count: %w", err)
	}
	return nil
}

func (s *WebAuthnCredentialStore) Delete(ctx context.Context, id []byte, subject string) error {
	const q = `DELETE FROM webauthn_credentials WHERE id = $1 AND subject = $2`
	if _, err := s.db.ExecContext(ctx, q, id, subject); err != nil {
		return fmt.Errorf("pgstore: delete webauthn credential: %w", err)
	}
	return nil
}

func (s *WebAuthnCredentialStore) CountBySubject(ctx context.Context, subject string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM webauthn_credentials WHERE subject = $1`, subject).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("pgstore: count webauthn credentials: %w", err)
	}
	return n, nil
}

// WebAuthnSessionStore implements authn.WebAuthnSessionStore over the
// identity-owned `webauthn_sessions` table.
type WebAuthnSessionStore struct {
	db *sql.DB
}

func NewWebAuthnSessionStore(db *sql.DB) *WebAuthnSessionStore {
	return &WebAuthnSessionStore{db: db}
}

var _ authn.WebAuthnSessionStore = (*WebAuthnSessionStore)(nil)

// Upsert overwrites any ceremony already in flight for the subject, so an
// abandoned challenge cannot be finished after a newer one was issued.
func (s *WebAuthnSessionStore) Upsert(ctx context.Context, subject string, sessionData []byte, challenge string, expiresAt time.Time) error {
	const q = `
INSERT INTO webauthn_sessions (subject, session_data, challenge, expires_at, created_at)
VALUES ($1, $2, $3, $4, now())
ON CONFLICT (subject) DO UPDATE
    SET session_data = EXCLUDED.session_data,
        challenge    = EXCLUDED.challenge,
        expires_at   = EXCLUDED.expires_at,
        created_at   = now()`
	if _, err := s.db.ExecContext(ctx, q, subject, sessionData, challenge, expiresAt); err != nil {
		return fmt.Errorf("pgstore: upsert webauthn session: %w", err)
	}
	return nil
}

func (s *WebAuthnSessionStore) Get(ctx context.Context, subject string) (authn.WebAuthnSession, error) {
	const q = `
SELECT subject, session_data, challenge, expires_at, created_at
FROM webauthn_sessions
WHERE subject = $1 AND expires_at > now()`
	var sess authn.WebAuthnSession
	err := s.db.QueryRowContext(ctx, q, subject).
		Scan(&sess.Subject, &sess.SessionData, &sess.Challenge, &sess.ExpiresAt, &sess.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return authn.WebAuthnSession{}, authn.ErrNoWebAuthnSession
	}
	if err != nil {
		return authn.WebAuthnSession{}, fmt.Errorf("pgstore: get webauthn session: %w", err)
	}
	return sess, nil
}

func (s *WebAuthnSessionStore) Delete(ctx context.Context, subject string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM webauthn_sessions WHERE subject = $1`, subject); err != nil {
		return fmt.Errorf("pgstore: delete webauthn session: %w", err)
	}
	return nil
}

func (s *WebAuthnSessionStore) Purge(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM webauthn_sessions WHERE expires_at < now()`); err != nil {
		return fmt.Errorf("pgstore: purge webauthn sessions: %w", err)
	}
	return nil
}
