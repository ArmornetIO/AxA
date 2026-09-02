package pgstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ArmornetIO/identity/authn"
)

// LegalStore never filters on org (operator terms; the guard is user_id). ABSENCE
// IS DENIAL: status reads start from versions in force and LEFT JOIN acceptances.
type LegalStore struct {
	db *sql.DB
}

func NewLegalStore(db *sql.DB) *LegalStore { return &LegalStore{db: db} }

var _ authn.LegalStore = (*LegalStore)(nil)

// versionColumns is the full row including the prose; versionMetaColumns omits
// it for the reads that only need to identify a version.
const (
	versionColumns     = `v.id, d.kind, d.title, v.version, v.body, v.content_hash, v.effective_at, v.created_at`
	versionMetaColumns = `v.id, d.kind, d.title, v.version, v.content_hash, v.effective_at, v.created_at`
)

func (s *LegalStore) ListDocuments(ctx context.Context) ([]authn.LegalDocument, error) {
	const q = `SELECT id, kind, title, created_at FROM legal_documents ORDER BY title`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("pgstore: list legal documents: %w", err)
	}
	defer rows.Close()

	out := []authn.LegalDocument{}
	for rows.Next() {
		var d authn.LegalDocument
		if err := rows.Scan(&d.ID, &d.Kind, &d.Title, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("pgstore: scan legal document: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstore: iterate legal documents: %w", err)
	}
	return out, nil
}

// UpsertDocument conflicts on kind, what a gate keys on: re-registering renames,
// never duplicates.
func (s *LegalStore) UpsertDocument(ctx context.Context, doc authn.LegalDocument) (authn.LegalDocument, error) {
	const q = `
INSERT INTO legal_documents (id, kind, title)
VALUES ($1, $2, $3)
ON CONFLICT (kind) DO UPDATE SET title = EXCLUDED.title
RETURNING id, kind, title, created_at`
	var out authn.LegalDocument
	err := s.db.QueryRowContext(ctx, q, doc.ID, doc.Kind, doc.Title).
		Scan(&out.ID, &out.Kind, &out.Title, &out.CreatedAt)
	if err != nil {
		return authn.LegalDocument{}, fmt.Errorf("pgstore: upsert legal document: %w", err)
	}
	return out, nil
}

// CountVersions feeds label minting for the next version to be published.
func (s *LegalStore) CountVersions(ctx context.Context, kind string) (int, error) {
	const q = `
SELECT count(*)
FROM legal_document_versions v
JOIN legal_documents d ON d.id = v.document_id
WHERE d.kind = $1`
	var n int
	if err := s.db.QueryRowContext(ctx, q, kind).Scan(&n); err != nil {
		return 0, fmt.Errorf("pgstore: count legal versions: %w", err)
	}
	return n, nil
}

func (s *LegalStore) VersionByHash(ctx context.Context, kind, contentHash string) (authn.LegalVersion, error) {
	const q = `
SELECT ` + versionMetaColumns + `
FROM legal_document_versions v
JOIN legal_documents d ON d.id = v.document_id
WHERE d.kind = $1 AND v.content_hash = $2`
	var v authn.LegalVersion
	err := s.db.QueryRowContext(ctx, q, kind, contentHash).
		Scan(&v.ID, &v.Kind, &v.Title, &v.Version, &v.ContentHash, &v.EffectiveAt, &v.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return authn.LegalVersion{}, authn.ErrNoLegalVersion
	}
	if err != nil {
		return authn.LegalVersion{}, fmt.Errorf("pgstore: get legal version by hash: %w", err)
	}
	return v, nil
}

// InsertVersion selects from the parent, so an unknown kind inserts nothing. Only
// content_hash conflicts quietly; a LABEL clash raises (two texts, one version).
func (s *LegalStore) InsertVersion(ctx context.Context, kind string, v authn.LegalVersion) (authn.LegalVersion, error) {
	const q = `
INSERT INTO legal_document_versions (id, document_id, version, body, content_hash, effective_at)
SELECT $1, d.id, $3, $4, $5, $6
FROM legal_documents d
WHERE d.kind = $2
ON CONFLICT (document_id, content_hash) DO NOTHING
RETURNING id, version, content_hash, effective_at, created_at`
	out := authn.LegalVersion{Kind: kind, Title: v.Title, Body: v.Body}
	err := s.db.QueryRowContext(ctx, q, v.ID, kind, v.Version, v.Body, v.ContentHash, v.EffectiveAt).
		Scan(&out.ID, &out.Version, &out.ContentHash, &out.EffectiveAt, &out.CreatedAt)
	// Same text already published, or an unregistered kind: one error for both.
	if errors.Is(err, sql.ErrNoRows) {
		return authn.LegalVersion{}, authn.ErrLegalVersionExists
	}
	if err != nil {
		return authn.LegalVersion{}, fmt.Errorf("pgstore: insert legal version: %w", err)
	}
	// kind, title and body are the caller's inputs and are not re-read.
	return out, nil
}

// ListVersions folds in acceptance_count, the reason anyone reads it (no N+1).
func (s *LegalStore) ListVersions(ctx context.Context, kind string) ([]authn.LegalVersion, error) {
	const q = `
SELECT ` + versionMetaColumns + `,
       (SELECT count(*) FROM legal_acceptance a WHERE a.version_id = v.id)
FROM legal_document_versions v
JOIN legal_documents d ON d.id = v.document_id
WHERE d.kind = $1
ORDER BY v.effective_at DESC, v.created_at DESC`
	rows, err := s.db.QueryContext(ctx, q, kind)
	if err != nil {
		return nil, fmt.Errorf("pgstore: list legal versions: %w", err)
	}
	defer rows.Close()

	out := []authn.LegalVersion{}
	for rows.Next() {
		var v authn.LegalVersion
		if err := rows.Scan(&v.ID, &v.Kind, &v.Title, &v.Version, &v.ContentHash,
			&v.EffectiveAt, &v.CreatedAt, &v.AcceptanceCount); err != nil {
			return nil, fmt.Errorf("pgstore: scan legal version: %w", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstore: iterate legal versions: %w", err)
	}
	return out, nil
}

// GetVersion has no date filter so a future version can be reviewed; Accept
// enforces the date.
func (s *LegalStore) GetVersion(ctx context.Context, versionID string) (authn.LegalVersion, error) {
	const q = `
SELECT ` + versionColumns + `
FROM legal_document_versions v
JOIN legal_documents d ON d.id = v.document_id
WHERE v.id = $1`
	return s.oneVersion(ctx, "get legal version", q, versionID)
}

// CurrentVersion hides a future-dated version until its date.
func (s *LegalStore) CurrentVersion(ctx context.Context, kind string) (authn.LegalVersion, error) {
	const q = `
SELECT ` + versionColumns + `
FROM legal_document_versions v
JOIN legal_documents d ON d.id = v.document_id
WHERE d.kind = $1 AND v.effective_at <= now()
ORDER BY v.effective_at DESC, v.created_at DESC
LIMIT 1`
	return s.oneVersion(ctx, "get current legal version", q, kind)
}

func (s *LegalStore) oneVersion(ctx context.Context, what, q string, arg any) (authn.LegalVersion, error) {
	var v authn.LegalVersion
	err := s.db.QueryRowContext(ctx, q, arg).
		Scan(&v.ID, &v.Kind, &v.Title, &v.Version, &v.Body, &v.ContentHash, &v.EffectiveAt, &v.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return authn.LegalVersion{}, authn.ErrNoLegalVersion
	}
	if err != nil {
		return authn.LegalVersion{}, fmt.Errorf("pgstore: %s: %w", what, err)
	}
	return v, nil
}

// Status is THE gate query: each document's version in force, with this user's
// acceptance or NULL. Unpublished documents drop out rather than gate anyone.
func (s *LegalStore) Status(ctx context.Context, userID string) ([]authn.LegalDocumentStatus, error) {
	const q = `
WITH in_force AS (
    SELECT DISTINCT ON (v.document_id)
           v.id, v.document_id, v.version, v.effective_at, v.created_at
    FROM legal_document_versions v
    WHERE v.effective_at <= now()
    ORDER BY v.document_id, v.effective_at DESC, v.created_at DESC
)
SELECT d.kind, d.title, f.id, f.version, f.effective_at, f.created_at, a.accepted_at
FROM in_force f
JOIN legal_documents d ON d.id = f.document_id
LEFT JOIN legal_acceptance a ON a.version_id = f.id AND a.user_id = $1::uuid
ORDER BY d.title`
	rows, err := s.db.QueryContext(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("pgstore: legal acceptance status: %w", err)
	}
	defer rows.Close()

	out := []authn.LegalDocumentStatus{}
	for rows.Next() {
		var (
			st       authn.LegalDocumentStatus
			accepted sql.NullTime
		)
		if err := rows.Scan(&st.Kind, &st.Title, &st.VersionID, &st.Version,
			&st.EffectiveAt, &st.CreatedAt, &accepted); err != nil {
			return nil, fmt.Errorf("pgstore: scan legal status: %w", err)
		}
		st.AcceptedAt = timePtr(accepted)
		out = append(out, st)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstore: iterate legal status: %w", err)
	}
	return out, nil
}

// Accept refuses a version not yet in force. ON CONFLICT sets accepted_at to ITS
// OWN value, not EXCLUDED: the first agreement stands, yet a row still returns.
func (s *LegalStore) Accept(ctx context.Context, acc authn.LegalAcceptance) (authn.LegalAcceptance, error) {
	const q = `
INSERT INTO legal_acceptance (user_id, version_id, context, nonce)
SELECT $1::uuid, v.id, $3, $4
FROM legal_document_versions v
WHERE v.id = $2 AND v.effective_at <= now()
ON CONFLICT (user_id, version_id) DO UPDATE
    SET accepted_at = legal_acceptance.accepted_at
RETURNING user_id::text, version_id, accepted_at`
	var out authn.LegalAcceptance
	err := s.db.QueryRowContext(ctx, q, acc.UserID, acc.VersionID, acc.Context, acc.Nonce).
		Scan(&out.UserID, &out.VersionID, &out.AcceptedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return authn.LegalAcceptance{}, authn.ErrNoLegalVersion
	}
	if err != nil {
		return authn.LegalAcceptance{}, fmt.Errorf("pgstore: accept legal version: %w", err)
	}
	return out, nil
}

func (s *LegalStore) ListAcceptances(ctx context.Context, versionID string) ([]authn.LegalAcceptance, error) {
	const q = `
SELECT a.user_id::text, a.version_id, a.accepted_at, a.context, a.nonce
FROM legal_acceptance a
WHERE a.version_id = $1
ORDER BY a.accepted_at DESC`
	rows, err := s.db.QueryContext(ctx, q, versionID)
	if err != nil {
		return nil, fmt.Errorf("pgstore: list legal acceptances: %w", err)
	}
	defer rows.Close()

	out := []authn.LegalAcceptance{}
	for rows.Next() {
		var a authn.LegalAcceptance
		if err := rows.Scan(&a.UserID, &a.VersionID, &a.AcceptedAt, &a.Context, &a.Nonce); err != nil {
			return nil, fmt.Errorf("pgstore: scan legal acceptance: %w", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstore: iterate legal acceptances: %w", err)
	}
	return out, nil
}
