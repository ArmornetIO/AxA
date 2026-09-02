package authn

import (
	"context"
	"errors"
	"time"
)

// Legal terms are an auth-time gate like MFA; content is the host's. NOT
// org-scoped by design: the guard is the user id, from the principal, never a body.

// ErrNoLegalDocument is returned when no document is registered under a kind.
var ErrNoLegalDocument = errors.New("authn: no such legal document")

// ErrNoLegalVersion also covers not-yet-in-force, so scheduling never leaks.
var ErrNoLegalVersion = errors.New("authn: no such legal version")

// ErrLegalVersionExists is the idempotence signal: a re-run publisher's success.
var ErrLegalVersionExists = errors.New("authn: legal version already published")

// LegalDocument's Kind ("terms", "privacy") is unique: one document per kind.
type LegalDocument struct {
	ID        string
	Kind      string
	Title     string
	CreatedAt time.Time
}

// LegalVersion is immutable; Body is plaintext (public terms, no linkage).
// EffectiveAt hides it until then; only ListVersions fills AcceptanceCount.
type LegalVersion struct {
	ID              string
	Kind            string
	Title           string
	Version         string
	Body            string
	ContentHash     string
	EffectiveAt     time.Time
	CreatedAt       time.Time
	AcceptanceCount int
}

// LegalAcceptance's Context and Nonce arrive sealed by the host and pass through
// opaque; identity never sees plaintext or key.
type LegalAcceptance struct {
	UserID     string
	VersionID  string
	AcceptedAt time.Time
	Context    []byte
	Nonce      []byte
}

// LegalDocumentStatus: a nil AcceptedAt IS the answer, outstanding.
type LegalDocumentStatus struct {
	Kind        string
	Title       string
	VersionID   string
	Version     string
	EffectiveAt time.Time
	CreatedAt   time.Time
	AcceptedAt  *time.Time
}

// Outstanding reports whether this document is still owed.
func (d LegalDocumentStatus) Outstanding() bool { return d.AcceptedAt == nil }

// LegalStore persists published documents and the acceptances against them.
type LegalStore interface {
	ListDocuments(ctx context.Context) ([]LegalDocument, error)
	// UpsertDocument cannot invent a kind: kinds are seeded with the schema.
	UpsertDocument(ctx context.Context, doc LegalDocument) (LegalDocument, error)

	CountVersions(ctx context.Context, kind string) (int, error)
	// VersionByHash answers "is this exact text already published?" — the
	// idempotence check a publisher runs before minting anything.
	VersionByHash(ctx context.Context, kind, contentHash string) (LegalVersion, error)
	// InsertVersion publishes an immutable cut, returning ErrLegalVersionExists
	// when the identical text is already published.
	InsertVersion(ctx context.Context, kind string, v LegalVersion) (LegalVersion, error)
	ListVersions(ctx context.Context, kind string) ([]LegalVersion, error)
	GetVersion(ctx context.Context, versionID string) (LegalVersion, error)
	// CurrentVersion returns the version of one document in force right now.
	CurrentVersion(ctx context.Context, kind string) (LegalVersion, error)

	// Status is one call: diffing two lists reads a failed request or a version
	// published in between as accepted.
	Status(ctx context.Context, userID string) ([]LegalDocumentStatus, error)
	// Accept twice keeps the first time: that is what an auditor reads.
	Accept(ctx context.Context, acc LegalAcceptance) (LegalAcceptance, error)
	// ListAcceptances is the roster for one version, returning the sealed
	// context untouched.
	ListAcceptances(ctx context.Context, versionID string) ([]LegalAcceptance, error)
}
