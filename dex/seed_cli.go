package dex

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"

	"github.com/ArmornetIO/identity"
	dexstorage "github.com/ArmornetIO/identity/internal/dex/storage"
)

// CLIClientID authenticates a HUMAN by device grant (RFC 8628); agents are
// MACHINES on client credentials.
const CLIClientID = "armornet-cli"

// CLIClientSeeder runs in production: the CLI is PUBLIC (a shipped binary keeps
// no secret; the human approval protects it). Never add a fixed secret.
type CLIClientSeeder struct{}

func (CLIClientSeeder) Name() string { return "cli-client" }

func (CLIClientSeeder) Seed(ctx context.Context, b identity.Broker) error {
	bk, ok := b.(*broker)
	if !ok {
		return fmt.Errorf("dex: CLIClientSeeder requires *broker, got %T", b)
	}

	secret, err := randomSecret()
	if err != nil {
		return fmt.Errorf("dex: seed cli client: %w", err)
	}

	cl := dexstorage.Client{
		ID:     CLIClientID,
		Name:   "Armornet CLI",
		Public: true,
		// Dex's storage validates this column as non-empty even for a public client;
		// see randomSecret for why it is random rather than fixed.
		Secret: secret,
		// Dex's storage validates a minimum length here too, so it cannot be
		// empty even though a CLI never renders a logo.
		LogoURL: "https://app.armornet.io/favicon.ico",
		// No RedirectURIs: the device grant lands on the server's own page.
	}

	err = bk.stor.CreateClient(ctx, cl)
	switch {
	case errors.Is(err, dexstorage.ErrAlreadyExists):
		slog.DebugContext(ctx, "dex: cli client already present, skipping seed", "client_id", CLIClientID)
		return nil
	case err != nil:
		return fmt.Errorf("dex: seed cli client: %w", err)
	}

	slog.InfoContext(ctx, "dex: seeded cli client", "client_id", CLIClientID, "public", true)
	return nil
}

// randomSecret fills the storage layer's mandatory-but-unused secret column.
// Random rather than fixed so it can never become a de facto shared credential.
func randomSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate client secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
