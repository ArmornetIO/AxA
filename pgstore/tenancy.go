package pgstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ArmornetIO/identity/authn"
)

// UserStore implements authn.UserStore over the identity-owned `users` and
// `organization_users` tables.
type UserStore struct {
	db *sql.DB
}

func NewUserStore(db *sql.DB) *UserStore { return &UserStore{db: db} }

var _ authn.UserStore = (*UserStore)(nil)

// UpsertUser keys on subject, never email: emails change hands, and the row
// would hand one person another's history.
func (s *UserStore) UpsertUser(ctx context.Context, u authn.UserRecord) (string, error) {
	const q = `
INSERT INTO users (id, subject, created_at, updated_at)
VALUES (gen_random_uuid(), $1, now(), now())
ON CONFLICT (subject) WHERE subject <> ''
DO UPDATE SET updated_at = now()
RETURNING id`
	var id string
	if err := s.db.QueryRowContext(ctx, q, u.Subject).Scan(&id); err != nil {
		return "", fmt.Errorf("pgstore: upsert user: %w", err)
	}
	return id, nil
}

// ResolveOrgScope is one query, so no grant lands between reads. No rows means
// unprovisioned; a NULL org means provisioned with no memberships.
func (s *UserStore) ResolveOrgScope(ctx context.Context, subject string) (authn.OrgScope, error) {
	const q = `
WITH u AS (
    SELECT id FROM users WHERE subject = $1
)
SELECT u.id, ou.org_id, ou.role
FROM u
LEFT JOIN organization_users ou ON ou.user_id = u.id`
	rows, err := s.db.QueryContext(ctx, q, subject)
	if err != nil {
		return authn.OrgScope{}, fmt.Errorf("pgstore: resolve org scope: %w", err)
	}
	defer rows.Close()

	// Non-nil from the start: an empty membership set must read as "matches
	// nothing" downstream, and a nil slice invites the opposite reading.
	scope := authn.OrgScope{Memberships: []authn.OrgMembership{}}
	for rows.Next() {
		var id string
		var orgID, role sql.NullString
		if err := rows.Scan(&id, &orgID, &role); err != nil {
			return authn.OrgScope{}, fmt.Errorf("pgstore: scan org scope: %w", err)
		}
		scope.UserID = id
		scope.Provisioned = true
		if orgID.Valid {
			scope.Memberships = append(scope.Memberships, authn.OrgMembership{
				OrgID: orgID.String,
				Role:  role.String,
			})
		}
	}
	if err := rows.Err(); err != nil {
		return authn.OrgScope{}, fmt.Errorf("pgstore: resolve org scope: %w", err)
	}
	return scope, nil
}

func (s *UserStore) LinkOrgUser(ctx context.Context, orgID, userID, role string) error {
	const q = `
INSERT INTO organization_users (org_id, user_id, role, created_at)
VALUES ($1, $2, $3, now())
ON CONFLICT DO NOTHING`
	if _, err := s.db.ExecContext(ctx, q, orgID, userID, role); err != nil {
		return fmt.Errorf("pgstore: link org user: %w", err)
	}
	return nil
}

func (s *UserStore) GetOrgRole(ctx context.Context, subject, orgID string) (string, error) {
	const q = `
SELECT ou.role
FROM organization_users ou
JOIN users u ON ou.user_id = u.id
WHERE u.subject = $1 AND ou.org_id = $2`
	var role string
	err := s.db.QueryRowContext(ctx, q, subject, orgID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", authn.ErrNoMembership
	}
	if err != nil {
		return "", fmt.Errorf("pgstore: get org role: %w", err)
	}
	return role, nil
}

type OrgStore struct {
	db     *sql.DB
	global map[string]struct{}
}

// NewOrgStore's globalConnectors are open to org-less signup (static, env-held
// secrets, so config not a query). None closes signup.
func NewOrgStore(db *sql.DB, globalConnectors ...string) *OrgStore {
	g := make(map[string]struct{}, len(globalConnectors))
	for _, id := range globalConnectors {
		g[id] = struct{}{}
	}
	return &OrgStore{db: db, global: g}
}

var _ authn.OrgStore = (*OrgStore)(nil)

func (s *OrgStore) CreateOrg(ctx context.Context, org authn.Organization) error {
	// Both timestamps written explicitly: a host's table may well declare them
	// NOT NULL without defaults, as armornet's does.
	const q = `INSERT INTO organizations (id, name, slug, created_at, updated_at) VALUES ($1, $2, $3, now(), now())`
	if _, err := s.db.ExecContext(ctx, q, org.ID, org.Name, org.Slug); err != nil {
		return fmt.Errorf("pgstore: create org: %w", err)
	}
	return nil
}

func (s *OrgStore) GetOrg(ctx context.Context, id string) (authn.Organization, error) {
	const q = `SELECT id, name, slug FROM organizations WHERE id = $1`
	var org authn.Organization
	err := s.db.QueryRowContext(ctx, q, id).Scan(&org.ID, &org.Name, &org.Slug)
	if errors.Is(err, sql.ErrNoRows) {
		return authn.Organization{}, authn.ErrNoOrg
	}
	if err != nil {
		return authn.Organization{}, fmt.Errorf("pgstore: get org: %w", err)
	}
	return org, nil
}

func (s *OrgStore) OrgExists(ctx context.Context, id string) (bool, error) {
	var exists bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM organizations WHERE id = $1)`, id).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("pgstore: org exists: %w", err)
	}
	return exists, nil
}

// UpdateOrg is one statement so two orgs racing for a slug cannot both win.
func (s *OrgStore) UpdateOrg(ctx context.Context, org authn.Organization) error {
	const q = `
WITH slug_check AS (
    SELECT EXISTS(SELECT 1 FROM organizations WHERE slug = $3 AND id <> $1) AS taken
),
updated AS (
    UPDATE organizations SET name = $2, slug = $3, updated_at = now()
    WHERE id = $1 AND NOT (SELECT taken FROM slug_check)
    RETURNING id
)
SELECT (SELECT taken FROM slug_check), (SELECT id FROM updated)`
	var taken bool
	var updated sql.NullString
	if err := s.db.QueryRowContext(ctx, q, org.ID, org.Name, org.Slug).Scan(&taken, &updated); err != nil {
		return fmt.Errorf("pgstore: update org: %w", err)
	}
	if taken {
		return authn.ErrSlugTaken
	}
	if !updated.Valid {
		return authn.ErrNoOrg
	}
	return nil
}

// ResolveSlug LEFT JOINs so an org with no connectors still resolves. A
// connector with an empty org_id is global, unless the org turned it off.
func (s *OrgStore) ResolveSlug(ctx context.Context, slug string) (string, []authn.ConnectorInfo, error) {
	const q = `
SELECT o.id, c.id, c.type, c.name
FROM organizations o
LEFT JOIN connectors c ON (c.org_id = o.id OR c.org_id = '')
	AND NOT EXISTS (SELECT 1 FROM org_disabled_connectors d WHERE d.org_id = o.id AND d.connector_id = c.id)
WHERE o.slug = $1`
	rows, err := s.db.QueryContext(ctx, q, slug)
	if err != nil {
		return "", nil, fmt.Errorf("pgstore: resolve slug: %w", err)
	}
	defer rows.Close()

	var orgID string
	conns := []authn.ConnectorInfo{}
	for rows.Next() {
		var id string
		var cID, cType, cName sql.NullString
		if err := rows.Scan(&id, &cID, &cType, &cName); err != nil {
			return "", nil, fmt.Errorf("pgstore: scan slug row: %w", err)
		}
		orgID = id
		if cID.Valid {
			conns = append(conns, authn.ConnectorInfo{ID: cID.String, Type: cType.String, Name: cName.String})
		}
	}
	if err := rows.Err(); err != nil {
		return "", nil, fmt.Errorf("pgstore: resolve slug: %w", err)
	}
	if orgID == "" {
		return "", nil, authn.ErrNoOrg
	}
	return orgID, conns, nil
}

func (s *OrgStore) ListConnectors(ctx context.Context, orgID string) ([]authn.ConnectorInfo, error) {
	const q = `
SELECT c.id, c.type, c.name, d.connector_id IS NOT NULL
FROM connectors c
LEFT JOIN org_disabled_connectors d ON d.org_id = $1 AND d.connector_id = c.id AND c.org_id = ''
WHERE c.org_id = $1 OR c.org_id = ''`
	rows, err := s.db.QueryContext(ctx, q, orgID)
	if err != nil {
		return nil, fmt.Errorf("pgstore: list connectors: %w", err)
	}
	defer rows.Close()

	out := []authn.ConnectorInfo{}
	for rows.Next() {
		var c authn.ConnectorInfo
		if err := rows.Scan(&c.ID, &c.Type, &c.Name, &c.Disabled); err != nil {
			return nil, fmt.Errorf("pgstore: scan connector: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *OrgStore) ListConnectorIDs(ctx context.Context, orgID string) ([]string, error) {
	conns, err := s.ListConnectors(ctx, orgID)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(conns))
	for _, c := range conns {
		if !c.Disabled {
			ids = append(ids, c.ID)
		}
	}
	return ids, nil
}

// SetConnectorDisabled refuses an org's own connector: that one is deleted,
// not hidden.
func (s *OrgStore) SetConnectorDisabled(ctx context.Context, orgID, connectorID string, disabled bool) error {
	if _, global := s.global[connectorID]; !global {
		return fmt.Errorf("pgstore: set connector disabled: %q is not a global connector", connectorID)
	}
	q := `DELETE FROM org_disabled_connectors WHERE org_id = $1 AND connector_id = $2`
	if disabled {
		q = `INSERT INTO org_disabled_connectors (org_id, connector_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`
	}
	if _, err := s.db.ExecContext(ctx, q, orgID, connectorID); err != nil {
		return fmt.Errorf("pgstore: set connector disabled: %w", err)
	}
	return nil
}

// CreateOrgConnector lets the org OFFER a connector Dex has just created. Dex
// writes the row with an empty org_id, which reads as global — on every org's
// login page — so this claims it. An UPDATE, not an upsert: the row is Dex's,
// and an insert would trip connectors_config_sealed before ON CONFLICT is
// reached. It fails rather than claim a row another org or the platform owns.
func (s *OrgStore) CreateOrgConnector(ctx context.Context, orgID, id, _, _ string) error {
	if orgID == "" {
		return fmt.Errorf("pgstore: create org connector: org id required")
	}
	if _, global := s.global[id]; global {
		return fmt.Errorf("pgstore: create org connector: %q is a global connector", id)
	}
	const q = `UPDATE connectors SET org_id = $2 WHERE id = $1 AND org_id IN ('', $2) RETURNING id`
	var got string
	err := s.db.QueryRowContext(ctx, q, id, orgID).Scan(&got)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("pgstore: create org connector: %q missing or owned by another org", id)
	}
	if err != nil {
		return fmt.Errorf("pgstore: create org connector: %w", err)
	}
	return nil
}

// DeleteOrgConnector is scoped by org so one tenant cannot remove another's.
func (s *OrgStore) DeleteOrgConnector(ctx context.Context, orgID, connectorID string) error {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM connectors WHERE id = $1 AND org_id = $2`, connectorID, orgID); err != nil {
		return fmt.Errorf("pgstore: delete org connector: %w", err)
	}
	return nil
}

func (s *OrgStore) IsGlobalConnector(_ context.Context, connectorID string) (bool, error) {
	_, ok := s.global[connectorID]
	return ok, nil
}
