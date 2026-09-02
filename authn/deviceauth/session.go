package deviceauth

import (
	"fmt"
	"os"
	"strings"
)

// TokenEnvVar holds the access token for a signed-in CLI session.
const TokenEnvVar = "ARMORNET_TOKEN" // #nosec G101 -- env var name, not a credential

// RefreshEnvVar holds the refresh token, so a session survives access-token
// expiry without another browser round trip.
const RefreshEnvVar = "ARMORNET_REFRESH_TOKEN"

// IDTokenEnvVar holds the ID token, which a host's break-glass access check
// takes.
const IDTokenEnvVar = "ARMORNET_ID_TOKEN" // #nosec G101 -- env var name, not a credential

// Store persists a signed-in session on this device.
//
// Only the environment is implemented today, deliberately: `engine.Load` already
// binds `${ARMORNET_TOKEN}` in agent config from the environment, so an env-backed
// session works end to end with no new resolver. A keyring backend is the next
// one — hence the interface, so adding it does not mean rewriting callers.
//
// The reference syntax is `${keyring:NAME}` / `${env:NAME}` / `${NAME}`, bound
// by the host's secret resolver. Extend it rather than duplicating it.
type Store interface {
	// Name identifies the backend in user-facing output.
	Name() string
	// Load returns the stored session, or ok=false when none is present.
	Load() (Session, bool)
	// Save persists a session. EnvStore cannot, and says so.
	Save(Session) error
}

// Session is a signed-in user's tokens on this device.
type Session struct {
	AccessToken  string
	RefreshToken string
	// IDToken is what an identity-aware proxy's check verifies, since it names
	// the person to a specific client (armornet-cli). Optional.
	IDToken string
}

// EnvStore reads a session from the process environment.
//
// It is read-only on purpose. A process cannot durably set its own parent's
// environment, so rather than pretend, Save returns an error carrying the exact
// shell lines to export — which is honest and, on a headless box or in CI, is
// exactly how the credential should be delivered anyway.
type EnvStore struct{}

func (EnvStore) Name() string { return "environment" }

func (EnvStore) Load() (Session, bool) {
	s := Session{
		AccessToken:  os.Getenv(TokenEnvVar),
		RefreshToken: os.Getenv(RefreshEnvVar),
		IDToken:      os.Getenv(IDTokenEnvVar),
	}
	return s, s.AccessToken != ""
}

// ErrEnvStoreReadOnly reports that a session cannot be written to the
// environment. It carries the export lines the caller should show.
type ErrEnvStoreReadOnly struct{ Exports string }

func (e ErrEnvStoreReadOnly) Error() string {
	return "the environment store cannot persist a session; export it instead"
}

func (EnvStore) Save(s Session) error {
	return ErrEnvStoreReadOnly{Exports: ExportLines(s)}
}

// ExportLines renders a session as shell exports, for a user to eval or paste.
func ExportLines(s Session) string {
	var b strings.Builder
	fmt.Fprintf(&b, "export %s=%s\n", TokenEnvVar, s.AccessToken)
	if s.RefreshToken != "" {
		fmt.Fprintf(&b, "export %s=%s\n", RefreshEnvVar, s.RefreshToken)
	}
	if s.IDToken != "" {
		fmt.Fprintf(&b, "export %s=%s\n", IDTokenEnvVar, s.IDToken)
	}
	return b.String()
}
