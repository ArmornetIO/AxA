// Package pgstore is Postgres for the tables identity owns: the host injects a
// *sql.DB (and the driver), identity owns the SQL, authn stays database-free.
package pgstore

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/ArmornetIO/identity/authn"
)

// MagicLinkStore stores only the token HASH; the rest is the host's opaque Grant.
type MagicLinkStore struct {
	db *sql.DB
}

func NewMagicLinkStore(db *sql.DB) *MagicLinkStore {
	return &MagicLinkStore{db: db}
}

var _ authn.MagicLinkStore = (*MagicLinkStore)(nil)

func (s *MagicLinkStore) Create(ctx context.Context, rec authn.MagicLinkRecord) error {
	const q = `
INSERT INTO magic_link
    (id, prefix, token_hash, subject, org_id, object_type, object_id, relation, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err := s.db.ExecContext(ctx, q,
		rec.ID, rec.Prefix, rec.TokenHash,
		rec.Grant.Subject, rec.Grant.OrgID, rec.Grant.ObjectType, rec.Grant.ObjectID, rec.Grant.Relation,
		rec.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("pgstore: create magic link: %w", err)
	}
	return nil
}

// ByPrefix returns only live links, so argon2 runs against valid candidates alone.
func (s *MagicLinkStore) ByPrefix(ctx context.Context, prefix string) ([]authn.MagicLinkRecord, error) {
	const q = `
SELECT id, prefix, token_hash, subject, org_id, object_type, object_id, relation, expires_at
FROM magic_link
WHERE prefix = $1 AND consumed_at IS NULL AND expires_at > now()`
	rows, err := s.db.QueryContext(ctx, q, prefix)
	if err != nil {
		return nil, fmt.Errorf("pgstore: query magic links: %w", err)
	}
	defer rows.Close()

	var out []authn.MagicLinkRecord
	for rows.Next() {
		var r authn.MagicLinkRecord
		if err := rows.Scan(
			&r.ID, &r.Prefix, &r.TokenHash,
			&r.Grant.Subject, &r.Grant.OrgID, &r.Grant.ObjectType, &r.Grant.ObjectID, &r.Grant.Relation,
			&r.ExpiresAt,
		); err != nil {
			return nil, fmt.Errorf("pgstore: scan magic link: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstore: iterate magic links: %w", err)
	}
	return out, nil
}

// Consume flips the link to used exactly once. The WHERE clause makes it
// race-free: a second concurrent redeem affects zero rows and gets false.
func (s *MagicLinkStore) Consume(ctx context.Context, id string) (bool, error) {
	const q = `
UPDATE magic_link
SET consumed_at = now()
WHERE id = $1 AND consumed_at IS NULL AND expires_at > now()`
	res, err := s.db.ExecContext(ctx, q, id)
	if err != nil {
		return false, fmt.Errorf("pgstore: consume magic link: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("pgstore: consume rows affected: %w", err)
	}
	return n == 1, nil
}
