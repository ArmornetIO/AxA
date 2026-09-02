package pgstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ArmornetIO/identity/authn"
)

// InviteStore joins the grant (org_invites) and its people (org_invite_parties:
// issuer, target, acceptor) on every read; no caller wants one half.
type InviteStore struct {
	db *sql.DB
}

func NewInviteStore(db *sql.DB) *InviteStore { return &InviteStore{db: db} }

var _ authn.InviteStore = (*InviteStore)(nil)

// inviteColumns is shared by every read so the joined column list and
// scanInvite cannot drift apart.
const inviteColumns = `i.id, i.org_id, i.kind_id, i.binding, i.role, i.token,
       p.invited_by, p.target_user_id, p.accepted_by, p.accepted_at,
       i.revoked_at, i.expires_at, i.created_at`

// Create is one CTE, so an invite never exists without its issuer, whatever the
// caller's transaction discipline.
func (s *InviteStore) Create(ctx context.Context, inv authn.Invite, invitedByUserID string) (authn.Invite, error) {
	const q = `
WITH i AS (
    INSERT INTO org_invites (org_id, kind_id, binding, role, token, expires_at, created_at)
    VALUES ($1, $2, $3, $4, $5, $6, now())
    RETURNING id, org_id, kind_id, binding, role, token, revoked_at, expires_at, created_at
),
p AS (
    INSERT INTO org_invite_parties (invite_id, invited_by, created_at)
    SELECT id, $7, now() FROM i
    RETURNING invite_id, invited_by, target_user_id, accepted_by, accepted_at
)
SELECT ` + inviteColumns + `
FROM i
JOIN p ON p.invite_id = i.id`
	rows, err := s.db.QueryContext(ctx, q,
		inv.OrgID, inv.Kind, inv.Binding, inv.Role, inv.Token, inv.ExpiresAt, invitedByUserID)
	if err != nil {
		return authn.Invite{}, fmt.Errorf("pgstore: create invite: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return authn.Invite{}, fmt.Errorf("pgstore: create invite: %w", err)
		}
		return authn.Invite{}, fmt.Errorf("pgstore: create invite: insert returned no row")
	}
	out, err := scanInvite(rows)
	if err != nil {
		return authn.Invite{}, fmt.Errorf("pgstore: scan invite: %w", err)
	}
	return out, nil
}

func (s *InviteStore) ByToken(ctx context.Context, token string) (authn.Invite, error) {
	const q = `
SELECT ` + inviteColumns + `
FROM org_invites i
LEFT JOIN org_invite_parties p ON p.invite_id = i.id
WHERE i.token = $1`
	return s.one(ctx, "get invite by token", q, token)
}

func (s *InviteStore) ByID(ctx context.Context, id string) (authn.Invite, error) {
	const q = `
SELECT ` + inviteColumns + `
FROM org_invites i
LEFT JOIN org_invite_parties p ON p.invite_id = i.id
WHERE i.id = $1`
	return s.one(ctx, "get invite by id", q, id)
}

// Reads LEFT JOIN: an invite that lost its party row stays revocable, not invisible.
func (s *InviteStore) one(ctx context.Context, what, q string, arg any) (authn.Invite, error) {
	rows, err := s.db.QueryContext(ctx, q, arg)
	if err != nil {
		return authn.Invite{}, fmt.Errorf("pgstore: %s: %w", what, err)
	}
	defer rows.Close()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return authn.Invite{}, fmt.Errorf("pgstore: %s: %w", what, err)
		}
		return authn.Invite{}, authn.ErrNoInvite
	}
	inv, err := scanInvite(rows)
	if err != nil {
		return authn.Invite{}, fmt.Errorf("pgstore: scan invite: %w", err)
	}
	return inv, nil
}

func (s *InviteStore) ListByOrg(ctx context.Context, orgID string) ([]authn.Invite, error) {
	const q = `
SELECT ` + inviteColumns + `
FROM org_invites i
LEFT JOIN org_invite_parties p ON p.invite_id = i.id
WHERE i.org_id = $1
ORDER BY i.created_at DESC`
	rows, err := s.db.QueryContext(ctx, q, orgID)
	if err != nil {
		return nil, fmt.Errorf("pgstore: list invites: %w", err)
	}
	defer rows.Close()

	out := []authn.Invite{}
	for rows.Next() {
		inv, err := scanInvite(rows)
		if err != nil {
			return nil, fmt.Errorf("pgstore: scan invite: %w", err)
		}
		out = append(out, inv)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstore: iterate invites: %w", err)
	}
	return out, nil
}

func (s *InviteStore) Revoke(ctx context.Context, id, orgID string) error {
	const q = `
UPDATE org_invites
SET revoked_at = now()
WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL
RETURNING id`
	var revoked string
	err := s.db.QueryRowContext(ctx, q, id, orgID).Scan(&revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return authn.ErrNoInvite
	}
	if err != nil {
		return fmt.Errorf("pgstore: revoke invite: %w", err)
	}
	return nil
}

// MarkAccepted: `accepted_by IS NULL` makes it single-use under a race. target is
// set too, so the acceptor-matches-target check holds for untargeted invites.
func (s *InviteStore) MarkAccepted(ctx context.Context, inviteID, accepterUserID string) error {
	const q = `
UPDATE org_invite_parties
SET accepted_by = $1, target_user_id = $1, accepted_at = now()
WHERE invite_id = $2 AND accepted_by IS NULL
RETURNING invite_id`
	var claimed string
	err := s.db.QueryRowContext(ctx, q, accepterUserID, inviteID).Scan(&claimed)
	if errors.Is(err, sql.ErrNoRows) {
		return authn.ErrNoInvite
	}
	if err != nil {
		return fmt.Errorf("pgstore: mark invite accepted: %w", err)
	}
	return nil
}

func scanInvite(rows *sql.Rows) (authn.Invite, error) {
	var (
		inv                                 authn.Invite
		invitedBy, targetUserID, acceptedBy sql.NullString
		acceptedAt, revokedAt               sql.NullTime
	)
	if err := rows.Scan(
		&inv.ID, &inv.OrgID, &inv.Kind, &inv.Binding, &inv.Role, &inv.Token,
		&invitedBy, &targetUserID, &acceptedBy, &acceptedAt,
		&revokedAt, &inv.ExpiresAt, &inv.CreatedAt,
	); err != nil {
		return authn.Invite{}, err
	}
	inv.InvitedBy = invitedBy.String
	inv.TargetUserID = targetUserID.String
	inv.AcceptedBy = acceptedBy.String
	inv.AcceptedAt = timePtr(acceptedAt)
	inv.RevokedAt = timePtr(revokedAt)
	return inv, nil
}
