package pgstore

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/ArmornetIO/identity/authn"
)

// SessionStore finds rows by token SHA-256, so a DB read yields no credential.
// `id` is matched against provider sids; not secret, never sent to a browser.
type SessionStore struct {
	db *sql.DB
}

func NewSessionStore(db *sql.DB) *SessionStore {
	return &SessionStore{db: db}
}

var _ authn.SessionStore = (*SessionStore)(nil)

func (s *SessionStore) Create(ctx context.Context, rec authn.SessionRecord, token string) error {
	// NULL rather than "": org_id carries a foreign key, and the empty string is
	// not an org. NULL is how a session with no organisation yet is expressed.
	var orgID any
	if rec.OrgID != "" {
		orgID = rec.OrgID
	}

	const q = `
INSERT INTO sessions
    (id, subject, org_id, connector_id, expires_at, created_at, last_seen_at, token_hash)
VALUES ($1, $2, $3, $4, $5, $6, $6, $7)`
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, q,
		rec.ID, rec.Subject, orgID, rec.ConnectorID, rec.ExpiresAt, now, authn.HashSessionToken(token),
	)
	if err != nil {
		return fmt.Errorf("pgstore: create session: %w", err)
	}
	return nil
}

func (s *SessionStore) ByTokenHash(ctx context.Context, tokenHash string) (authn.SessionRecord, error) {
	// COALESCE because org_id is nullable: a session whose owner has no
	// organisation yet reads back as "", which every caller treats as no scope.
	const q = `
SELECT id, subject, COALESCE(org_id, '')::text, connector_id, expires_at
FROM sessions
WHERE token_hash = $1`
	var rec authn.SessionRecord
	err := s.db.QueryRowContext(ctx, q, tokenHash).
		Scan(&rec.ID, &rec.Subject, &rec.OrgID, &rec.ConnectorID, &rec.ExpiresAt)
	if err != nil {
		return authn.SessionRecord{}, fmt.Errorf("pgstore: get session: %w", err)
	}
	return rec, nil
}

func (s *SessionStore) Delete(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = $1`, authn.HashSessionToken(token))
	if err != nil {
		return fmt.Errorf("pgstore: delete session: %w", err)
	}
	return nil
}

func (s *SessionStore) SeatOrg(ctx context.Context, token, orgID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET org_id = $2 WHERE token_hash = $1 AND org_id IS NULL`,
		authn.HashSessionToken(token), orgID)
	if err != nil {
		return fmt.Errorf("pgstore: seat session org: %w", err)
	}
	return nil
}

func (s *SessionStore) Purge(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < now()`)
	if err != nil {
		return fmt.Errorf("pgstore: purge sessions: %w", err)
	}
	return nil
}

func (s *SessionStore) DeleteBySubject(ctx context.Context, subject string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE subject = $1`, subject)
	if err != nil {
		return fmt.Errorf("pgstore: delete sessions by subject: %w", err)
	}
	return nil
}

// DeleteBySubjectAndSID returns the row count: back-channel logout must tell a
// miss (sid never reconciled) from a logout.
func (s *SessionStore) DeleteBySubjectAndSID(ctx context.Context, subject, sid string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE subject = $1 AND id = $2`, subject, sid)
	if err != nil {
		return 0, fmt.Errorf("pgstore: delete session by sid: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("pgstore: delete session by sid: rows affected: %w", err)
	}
	return n, nil
}
