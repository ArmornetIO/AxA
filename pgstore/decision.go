package pgstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ArmornetIO/identity"
	"github.com/ArmornetIO/identity/access"
)

// DecisionStore keeps only lookup keys (subject, resource, outcome, time) clear
// and seals the rest; a row still reveals that a decision happened.
type DecisionStore struct {
	db     *sql.DB
	sealer identity.ConfigSealer
	origin access.OriginSealer
}

// NewDecisionStore: a nil sealer stores plain JSON; a nil origin stores no
// origin at all, NEVER a clear one.
func NewDecisionStore(db *sql.DB, sealer identity.ConfigSealer, origin access.OriginSealer) *DecisionStore {
	return &DecisionStore{db: db, sealer: sealer, origin: origin}
}

// sealedRecord is one blob, so a new attribute needs no migration.
type sealedRecord struct {
	Action     access.Action    `json:"action"`
	Reason     string           `json:"reason"`
	Predicates []access.Verdict `json:"predicates,omitempty"`
}

// Write stores one decision. It is called off the request path: the outcome is
// already determined, so a failure here costs a record, never a request.
func (s *DecisionStore) Write(ctx context.Context, d access.Decision) error {
	blob, err := json.Marshal(sealedRecord{Action: d.Action, Reason: d.Reason, Predicates: d.Predicates})
	if err != nil {
		return fmt.Errorf("pgstore: marshal decision: %w", err)
	}
	if s.sealer != nil {
		if blob, err = s.sealer.Seal(blob); err != nil {
			return fmt.Errorf("pgstore: seal decision: %w", err)
		}
	}

	var orgID, subjectID, subjectKind any
	if d.Subject != nil {
		subjectID, subjectKind = d.Subject.ID, string(d.Subject.Kind)
		if d.Subject.OrgID != "" {
			orgID = d.Subject.OrgID
		}
	}

	const q = `
		INSERT INTO access_decisions
			(id, org_id, subject_id, subject_kind, resource_type, resource_id,
			 outcome, decided_at, correlation_key, content, nonce, sealed_origin)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULL,$11)
		ON CONFLICT (id) DO NOTHING`
	_, err = s.db.ExecContext(ctx, q,
		d.ID, orgID, subjectID, subjectKind,
		nullIfEmpty(d.Resource.Type), nullIfEmpty(d.Resource.ID),
		string(d.Outcome), d.At, nullIfEmpty(d.CorrelationKey),
		blob, d.SealedOrigin,
	)
	if err != nil {
		return fmt.Errorf("pgstore: write decision: %w", err)
	}
	return nil
}

// Get answers "why was this request refused?".
func (s *DecisionStore) Get(ctx context.Context, id string) (access.Decision, error) {
	const q = `
		SELECT id, org_id, subject_id, subject_kind, resource_type, resource_id,
		       outcome, decided_at, correlation_key, content, sealed_origin
		FROM access_decisions WHERE id = $1`
	d, err := s.scanOne(s.db.QueryRowContext(ctx, q, id))
	if err != nil {
		return access.Decision{}, err
	}
	return d, nil
}

// ForSubject answers "what does this subject need?": failed predicates name it.
func (s *DecisionStore) ForSubject(ctx context.Context, subjectID string, since time.Time, limit int) ([]access.Decision, error) {
	const q = `
		SELECT id, org_id, subject_id, subject_kind, resource_type, resource_id,
		       outcome, decided_at, correlation_key, content, sealed_origin
		FROM access_decisions
		WHERE subject_id = $1 AND decided_at >= $2
		ORDER BY decided_at DESC
		LIMIT $3`
	return s.scanMany(ctx, q, subjectID, since, limit)
}

// ReachedResource answers "who got in?", so permits only; refusals would make it
// "who tried".
func (s *DecisionStore) ReachedResource(ctx context.Context, resourceType, resourceID string, from, to time.Time) ([]access.Decision, error) {
	const q = `
		SELECT id, org_id, subject_id, subject_kind, resource_type, resource_id,
		       outcome, decided_at, correlation_key, content, sealed_origin
		FROM access_decisions
		WHERE resource_type = $1 AND resource_id = $2
		  AND decided_at >= $3 AND decided_at < $4
		  AND outcome = $5
		ORDER BY decided_at DESC`
	return s.scanMany(ctx, q, resourceType, resourceID, from, to, string(access.Permit))
}

// Unseal is break-glass and retrospective (why no collection flag). Recording
// the unsealing is the caller's job: only it knows who and under which rule.
func (s *DecisionStore) Unseal(ctx context.Context, from, to time.Time) (map[string]string, error) {
	if s.origin == nil {
		return nil, fmt.Errorf("pgstore: no origin sealer configured")
	}
	const q = `
		SELECT id, sealed_origin FROM access_decisions
		WHERE decided_at >= $1 AND decided_at < $2 AND sealed_origin IS NOT NULL`
	rows, err := s.db.QueryContext(ctx, q, from, to)
	if err != nil {
		return nil, fmt.Errorf("pgstore: unseal: %w", err)
	}
	defer rows.Close()

	out := map[string]string{}
	for rows.Next() {
		var id string
		var sealed []byte
		if err := rows.Scan(&id, &sealed); err != nil {
			return nil, fmt.Errorf("pgstore: unseal scan: %w", err)
		}
		origin, err := s.origin.Open(sealed)
		if err != nil {
			// One unreadable row — a superseded key, a value written before
			// sealing — must not cost the whole incident's worth of evidence.
			continue
		}
		out[id] = origin
	}
	return out, rows.Err()
}

// DeleteBefore is the retention sweep's hook. The window is the host's, stated
// in cmd/internal/retention, and it backs the published privacy notice.
func (s *DecisionStore) DeleteBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM access_decisions WHERE decided_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("pgstore: sweep decisions: %w", err)
	}
	return res.RowsAffected()
}

type scanner interface{ Scan(dest ...any) error }

func (s *DecisionStore) scanOne(row scanner) (access.Decision, error) {
	var (
		d                                 access.Decision
		orgID, subjectID, subjectKind     sql.NullString
		resourceType, resourceID, corrKey sql.NullString
		outcome                           string
		blob, sealedOrigin                []byte
	)
	if err := row.Scan(&d.ID, &orgID, &subjectID, &subjectKind, &resourceType,
		&resourceID, &outcome, &d.At, &corrKey, &blob, &sealedOrigin); err != nil {
		return access.Decision{}, err
	}

	d.Outcome = access.Outcome(outcome)
	d.Resource = access.Resource{Type: resourceType.String, ID: resourceID.String}
	d.CorrelationKey = corrKey.String
	d.SealedOrigin = sealedOrigin
	if subjectID.Valid {
		d.Subject = &access.Subject{
			Kind:  access.Kind(subjectKind.String),
			ID:    subjectID.String,
			OrgID: orgID.String,
		}
	}

	if s.sealer != nil && len(blob) > 0 {
		opened, err := s.sealer.Open(blob)
		if err != nil {
			return access.Decision{}, fmt.Errorf("pgstore: open decision: %w", err)
		}
		blob = opened
	}
	if len(blob) > 0 {
		var rec sealedRecord
		if err := json.Unmarshal(blob, &rec); err != nil {
			return access.Decision{}, fmt.Errorf("pgstore: decode decision: %w", err)
		}
		d.Action, d.Reason, d.Predicates = rec.Action, rec.Reason, rec.Predicates
	}
	return d, nil
}

func (s *DecisionStore) scanMany(ctx context.Context, q string, args ...any) ([]access.Decision, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("pgstore: query decisions: %w", err)
	}
	defer rows.Close()

	var out []access.Decision
	for rows.Next() {
		d, err := s.scanOne(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
