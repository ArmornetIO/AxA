package authn

import (
	"context"
	"errors"
	"time"
)

// MFA keys on the IdP subject, not a user id: the challenge lives between the
// OIDC callback and verify, before any user is resolved.

// ErrNoChallenge covers absent, consumed and expired alike, so ids can't be probed.
var ErrNoChallenge = errors.New("authn: no such MFA challenge")

// ErrNoTOTPCredential is returned when a subject has never enrolled a
// authenticator, or has deleted the one they had.
var ErrNoTOTPCredential = errors.New("authn: no TOTP credential")

// ErrNoWebAuthnSession is returned when no live ceremony matches — the Finish
// half of a Begin/Finish pair that timed out or never happened.
var ErrNoWebAuthnSession = errors.New("authn: no WebAuthn session")

// MFAChallenge: TokenExpiry caps the later session (ExpiresAt is the time to
// answer); AttemptCount is stored so the rate limit survives restarts and replicas.
type MFAChallenge struct {
	// ID is the opaque handle returned to the client. It is the only thing
	// naming this challenge, so it must be unguessable.
	ID           string
	Subject      string
	OrgID        string
	TokenExpiry  time.Time
	AttemptCount int
	ExpiresAt    time.Time
	CreatedAt    time.Time
}

// MFAChallengeStore persists MFA challenges.
type MFAChallengeStore interface {
	Create(ctx context.Context, c MFAChallenge) error
	// Get reads a live challenge without spending it.
	Get(ctx context.Context, id string) (MFAChallenge, error)
	// Consume is atomic: a racing loser gets ErrNoChallenge, final, never retried.
	Consume(ctx context.Context, id string) (MFAChallenge, error)
	// IncrAttemptCount raises the counter and returns the new value, so a caller
	// decides on a number the database produced rather than one it held.
	IncrAttemptCount(ctx context.Context, id string) (int, error)
	Purge(ctx context.Context) error
}

// TOTPCredential gates logins only once Enrolled (a code verified), or a botched
// enrollment locks the account. Secret is plaintext here; stores seal it.
type TOTPCredential struct {
	Subject    string
	Secret     []byte
	Enrolled   bool
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// TOTPStore persists one TOTP secret per subject.
type TOTPStore interface {
	// Upsert always lands unenrolled, or an unverified secret would be active.
	Upsert(ctx context.Context, subject string, secret []byte) error
	// Get returns the credential, or ErrNoTOTPCredential.
	Get(ctx context.Context, subject string) (TOTPCredential, error)
	SetEnrolled(ctx context.Context, subject string) error
	UpdateLastUsed(ctx context.Context, subject string, t time.Time) error
	Delete(ctx context.Context, subject string) error
}

// WebAuthnCredentialFlags are grouped: four bare bools invite a transposition.
type WebAuthnCredentialFlags struct {
	UserPresent    bool
	UserVerified   bool
	BackupEligible bool
	BackupState    bool
}

// WebAuthnCredential: a non-rising SignCount sets CloneWarning, recorded not
// fatal (many keys never count). AttestationObject allows later re-checks.
type WebAuthnCredential struct {
	ID                []byte
	Subject           string
	PublicKey         []byte
	AttestationType   string
	Transport         []string
	AAGUID            []byte
	SignCount         uint32
	CloneWarning      bool
	Flags             WebAuthnCredentialFlags
	AttestationObject []byte
	CreatedAt         time.Time
}

// WebAuthnCredentialStore persists registered credentials.
type WebAuthnCredentialStore interface {
	Create(ctx context.Context, c WebAuthnCredential) error
	// ListBySubject returns every credential for a subject, oldest first, and an
	// empty slice rather than an error when there are none.
	ListBySubject(ctx context.Context, subject string) ([]WebAuthnCredential, error)
	// UpdateSignCount persists what an assertion changed.
	UpdateSignCount(ctx context.Context, id []byte, signCount uint32, cloneWarning bool, flags WebAuthnCredentialFlags) error
	// Delete is subject-scoped: the id reaches the client, so unscoped is an IDOR.
	Delete(ctx context.Context, id []byte, subject string) error
	// CountBySubject answers "would removing this leave them locked out?"
	// without reading the keys themselves.
	CountBySubject(ctx context.Context, subject string) (int, error)
}

// WebAuthnSession holds opaque ceremony JSON between Begin and Finish, so the
// WebAuthn library stays the host's choice.
type WebAuthnSession struct {
	Subject     string
	SessionData []byte
	Challenge   string
	ExpiresAt   time.Time
	CreatedAt   time.Time
}

// WebAuthnSessionStore keeps one per subject: a new Begin voids an abandoned one.
type WebAuthnSessionStore interface {
	Upsert(ctx context.Context, subject string, sessionData []byte, challenge string, expiresAt time.Time) error
	// Get returns the live session, or ErrNoWebAuthnSession.
	Get(ctx context.Context, subject string) (WebAuthnSession, error)
	Delete(ctx context.Context, subject string) error
	Purge(ctx context.Context) error
}
