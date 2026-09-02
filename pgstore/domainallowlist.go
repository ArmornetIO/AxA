package pgstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ArmornetIO/identity/authn"
)

// DomainAllowlistStore implements authn.DomainAllowlistStore over the
// identity-owned `org_domain_allowlist` table.
type DomainAllowlistStore struct {
	db *sql.DB
}

func NewDomainAllowlistStore(db *sql.DB) *DomainAllowlistStore {
	return &DomainAllowlistStore{db: db}
}

var _ authn.DomainAllowlistStore = (*DomainAllowlistStore)(nil)

const allowlistColumns = `id, org_id, domain, role, created_by, created_at`

func (s *DomainAllowlistStore) Add(ctx context.Context, entry authn.DomainAllowlistEntry) (authn.DomainAllowlistEntry, error) {
	const q = `
INSERT INTO org_domain_allowlist (org_id, domain, role, created_by, created_at)
VALUES ($1, $2, $3, $4, now())
RETURNING ` + allowlistColumns
	rows, err := s.db.QueryContext(ctx, q, entry.OrgID, entry.Domain, entry.Role, nullString(entry.CreatedBy))
	if err != nil {
		return authn.DomainAllowlistEntry{}, fmt.Errorf("pgstore: add allowlist domain: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return authn.DomainAllowlistEntry{}, fmt.Errorf("pgstore: add allowlist domain: %w", err)
		}
		return authn.DomainAllowlistEntry{}, fmt.Errorf("pgstore: add allowlist domain: insert returned no row")
	}
	out, err := scanAllowlistEntry(rows)
	if err != nil {
		return authn.DomainAllowlistEntry{}, fmt.Errorf("pgstore: scan allowlist entry: %w", err)
	}
	return out, nil
}

func (s *DomainAllowlistStore) ListByOrg(ctx context.Context, orgID string) ([]authn.DomainAllowlistEntry, error) {
	const q = `
SELECT ` + allowlistColumns + `
FROM org_domain_allowlist
WHERE org_id = $1
ORDER BY domain`
	rows, err := s.db.QueryContext(ctx, q, orgID)
	if err != nil {
		return nil, fmt.Errorf("pgstore: list allowlist domains: %w", err)
	}
	defer rows.Close()

	out := []authn.DomainAllowlistEntry{}
	for rows.Next() {
		e, err := scanAllowlistEntry(rows)
		if err != nil {
			return nil, fmt.Errorf("pgstore: scan allowlist entry: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstore: iterate allowlist domains: %w", err)
	}
	return out, nil
}

func (s *DomainAllowlistStore) Remove(ctx context.Context, id, orgID string) error {
	const q = `DELETE FROM org_domain_allowlist WHERE id = $1 AND org_id = $2 RETURNING id`
	var removed string
	err := s.db.QueryRowContext(ctx, q, id, orgID).Scan(&removed)
	if errors.Is(err, sql.ErrNoRows) {
		return authn.ErrNoAllowlistEntry
	}
	if err != nil {
		return fmt.Errorf("pgstore: remove allowlist domain: %w", err)
	}
	return nil
}

func (s *DomainAllowlistStore) Match(ctx context.Context, orgID, domain string) (authn.DomainAllowlistEntry, error) {
	const q = `
SELECT ` + allowlistColumns + `
FROM org_domain_allowlist
WHERE org_id = $1 AND domain = $2`
	var (
		e         authn.DomainAllowlistEntry
		createdBy sql.NullString
	)
	err := s.db.QueryRowContext(ctx, q, orgID, domain).
		Scan(&e.ID, &e.OrgID, &e.Domain, &e.Role, &createdBy, &e.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return authn.DomainAllowlistEntry{}, authn.ErrNoAllowlistEntry
	}
	if err != nil {
		return authn.DomainAllowlistEntry{}, fmt.Errorf("pgstore: match allowlist domain: %w", err)
	}
	e.CreatedBy = createdBy.String
	return e, nil
}

func scanAllowlistEntry(rows *sql.Rows) (authn.DomainAllowlistEntry, error) {
	var (
		e         authn.DomainAllowlistEntry
		createdBy sql.NullString
	)
	if err := rows.Scan(&e.ID, &e.OrgID, &e.Domain, &e.Role, &createdBy, &e.CreatedAt); err != nil {
		return authn.DomainAllowlistEntry{}, err
	}
	e.CreatedBy = createdBy.String
	return e, nil
}
