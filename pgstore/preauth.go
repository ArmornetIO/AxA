package pgstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ArmornetIO/identity/authn"
)

// PreAuthStore implements authn.PreAuthStore over the identity-owned
// `preauth_sessions` table.
type PreAuthStore struct {
	db *sql.DB
}

func NewPreAuthStore(db *sql.DB) *PreAuthStore { return &PreAuthStore{db: db} }

var _ authn.PreAuthStore = (*PreAuthStore)(nil)

func (s *PreAuthStore) Create(ctx context.Context, p authn.PreAuthSession) error {
	const q = `
INSERT INTO preauth_sessions
    (id, org_id, connector_id, state, nonce, code_verifier, expires_at, created_at, is_signup, invite_id, intent, return_to)
VALUES ($1, $2, $3, $4, $5, $6, $7, now(), $8, $9, $10, $11)`
	_, err := s.db.ExecContext(ctx, q,
		p.ID, nullString(p.OrgID), p.ConnectorID, p.State, p.Nonce, p.CodeVerifier,
		p.ExpiresAt, p.IsSignup, nullString(p.InviteID), p.Intent, p.ReturnTo,
	)
	if err != nil {
		return fmt.Errorf("pgstore: create preauth session: %w", err)
	}
	return nil
}

// Get filters on expiry in the query rather than after it, so a callback that
// arrives late is indistinguishable from one for a flow that never existed.
func (s *PreAuthStore) Get(ctx context.Context, id string) (authn.PreAuthSession, error) {
	const q = `
SELECT id, org_id, connector_id, state, nonce, code_verifier, expires_at, created_at, is_signup, invite_id, intent, return_to
FROM preauth_sessions
WHERE id = $1 AND expires_at > now()`
	var (
		p               authn.PreAuthSession
		orgID, inviteID sql.NullString
	)
	err := s.db.QueryRowContext(ctx, q, id).Scan(
		&p.ID, &orgID, &p.ConnectorID, &p.State, &p.Nonce, &p.CodeVerifier,
		&p.ExpiresAt, &p.CreatedAt, &p.IsSignup, &inviteID, &p.Intent, &p.ReturnTo,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return authn.PreAuthSession{}, authn.ErrNoPreAuthSession
	}
	if err != nil {
		return authn.PreAuthSession{}, fmt.Errorf("pgstore: get preauth session: %w", err)
	}
	p.OrgID = orgID.String
	p.InviteID = inviteID.String
	return p, nil
}

func (s *PreAuthStore) Delete(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM preauth_sessions WHERE id = $1`, id); err != nil {
		return fmt.Errorf("pgstore: delete preauth session: %w", err)
	}
	return nil
}

func (s *PreAuthStore) Purge(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM preauth_sessions WHERE expires_at < now()`); err != nil {
		return fmt.Errorf("pgstore: purge preauth sessions: %w", err)
	}
	return nil
}
