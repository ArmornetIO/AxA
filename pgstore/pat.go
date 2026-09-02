package pgstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/ArmornetIO/identity/authn"
	"github.com/lib/pq"
)

// touchTimeout: the request ctx is already gone, and a stalled conn would leak
// the goroutine.
const touchTimeout = 5 * time.Second

// PATStore keeps only the argon2id hash; the clear `prefix` narrows the costly
// verify to a few candidates.
type PATStore struct {
	db *sql.DB
}

func NewPATStore(db *sql.DB) *PATStore { return &PATStore{db: db} }

var _ authn.PATStore = (*PATStore)(nil)

const patColumns = `id, user_id, org_id, name, prefix, token_hash, scopes,
       created_at, expires_at, last_used_at, revoked_at`

// ByPrefix INNER JOINs users on purpose: an orphaned token must stop working,
// not authenticate as nobody. users.id is uuid and user_id is text, and
// Postgres has no uuid = text operator: compare as text, which cannot fail on
// a malformed user_id the way a ::uuid cast would.
func (s *PATStore) ByPrefix(ctx context.Context, prefix string) ([]authn.PATRecord, error) {
	const q = `
SELECT p.id, u.subject, p.org_id, p.token_hash, p.scopes
FROM personal_access_tokens p
JOIN users u ON u.id::text = p.user_id
WHERE p.prefix = $1
  AND p.revoked_at IS NULL
  AND (p.expires_at IS NULL OR p.expires_at > now())`
	rows, err := s.db.QueryContext(ctx, q, prefix)
	if err != nil {
		return nil, fmt.Errorf("pgstore: lookup pats by prefix: %w", err)
	}
	defer rows.Close()

	out := []authn.PATRecord{}
	for rows.Next() {
		var (
			r      authn.PATRecord
			scopes pq.StringArray
		)
		if err := rows.Scan(&r.ID, &r.Subject, &r.OrgID, &r.TokenHash, &scopes); err != nil {
			return nil, fmt.Errorf("pgstore: scan pat: %w", err)
		}
		r.Scopes = []string(scopes)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstore: iterate pats: %w", err)
	}
	return out, nil
}

// Touch drops failures: the timestamp is telemetry and must never fail a request.
func (s *PATStore) Touch(id string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), touchTimeout)
		defer cancel()
		_, _ = s.db.ExecContext(ctx,
			`UPDATE personal_access_tokens SET last_used_at = $2 WHERE id = $1`, id, time.Now().UTC())
	}()
}

// Create relies on the user_id foreign key: no token for a user ByPrefix can't resolve.
func (s *PATStore) Create(ctx context.Context, tok authn.PATToken) (authn.PATToken, error) {
	// created_at is NOT NULL with no default in the host schema, so it is always
	// written rather than left to Postgres.
	if tok.CreatedAt.IsZero() {
		tok.CreatedAt = time.Now().UTC()
	}
	if tok.ID == "" {
		b := make([]byte, 6)
		if _, err := rand.Read(b); err != nil {
			return authn.PATToken{}, fmt.Errorf("pgstore: create pat id: %w", err)
		}
		tok.ID = "pat_" + hex.EncodeToString(b)
	}
	// A nil slice would send NULL into a NOT NULL column; an empty array is the
	// honest encoding of "no scopes".
	if tok.Scopes == nil {
		tok.Scopes = []string{}
	}

	const q = `
INSERT INTO personal_access_tokens
    (id, user_id, org_id, name, prefix, token_hash, scopes, created_at, expires_at, last_used_at, revoked_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING ` + patColumns
	rows, err := s.db.QueryContext(ctx, q,
		tok.ID, tok.UserID, tok.OrgID, tok.Name, tok.Prefix, tok.TokenHash,
		pq.Array(tok.Scopes), tok.CreatedAt,
		nullTime(tok.ExpiresAt), nullTime(tok.LastUsedAt), nullTime(tok.RevokedAt),
	)
	if err != nil {
		return authn.PATToken{}, fmt.Errorf("pgstore: create pat: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return authn.PATToken{}, fmt.Errorf("pgstore: create pat: %w", err)
		}
		return authn.PATToken{}, fmt.Errorf("pgstore: create pat: insert returned no row")
	}
	out, err := scanPATToken(rows)
	if err != nil {
		return authn.PATToken{}, fmt.Errorf("pgstore: scan pat: %w", err)
	}
	return out, nil
}

func (s *PATStore) ListByUser(ctx context.Context, userID string, includeRevoked bool) ([]authn.PATToken, error) {
	const q = `
SELECT ` + patColumns + `
FROM personal_access_tokens
WHERE user_id = $1 AND ($2 OR revoked_at IS NULL)
ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, q, userID, includeRevoked)
	if err != nil {
		return nil, fmt.Errorf("pgstore: list pats: %w", err)
	}
	defer rows.Close()

	out := []authn.PATToken{}
	for rows.Next() {
		tok, err := scanPATToken(rows)
		if err != nil {
			return nil, fmt.Errorf("pgstore: scan pat: %w", err)
		}
		out = append(out, tok)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstore: iterate pats: %w", err)
	}
	return out, nil
}

// Revoke is owner-scoped (an id alone is no authority); a repeat returns ErrNoPAT
// rather than moving the timestamp an auditor reads.
func (s *PATStore) Revoke(ctx context.Context, userID, id string) error {
	const q = `
UPDATE personal_access_tokens
SET revoked_at = $3
WHERE user_id = $1 AND id = $2 AND revoked_at IS NULL
RETURNING id`
	var revoked string
	err := s.db.QueryRowContext(ctx, q, userID, id, time.Now().UTC()).Scan(&revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return authn.ErrNoPAT
	}
	if err != nil {
		return fmt.Errorf("pgstore: revoke pat: %w", err)
	}
	return nil
}

func scanPATToken(rows *sql.Rows) (authn.PATToken, error) {
	var (
		tok                              authn.PATToken
		scopes                           pq.StringArray
		expiresAt, lastUsedAt, revokedAt sql.NullTime
	)
	if err := rows.Scan(
		&tok.ID, &tok.UserID, &tok.OrgID, &tok.Name, &tok.Prefix, &tok.TokenHash,
		&scopes, &tok.CreatedAt, &expiresAt, &lastUsedAt, &revokedAt,
	); err != nil {
		return authn.PATToken{}, err
	}
	tok.Scopes = []string(scopes)
	tok.ExpiresAt = timePtr(expiresAt)
	tok.LastUsedAt = timePtr(lastUsedAt)
	tok.RevokedAt = timePtr(revokedAt)
	return tok, nil
}
