package dex

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/ArmornetIO/axa"
	dexstorage "github.com/ArmornetIO/axa/internal/dex/storage"
)

// BFFClientSeeder upserts armornet-bff on every start so the stored secret
// matches ARMORNET_IDENTITY_CLIENT_SECRET; drift meant 502s on callback.
type BFFClientSeeder struct {
	// Secret is plaintext; Dex hashes it on write.
	Secret string
	// RedirectURI must match identity.redirect_uri in the server config.
	RedirectURI string
}

func (s *BFFClientSeeder) Name() string { return "bff-oauth2-client" }

func (s *BFFClientSeeder) Seed(ctx context.Context, b axa.Broker) error {
	if s.Secret == "" {
		slog.WarnContext(ctx, "dex: BFF client not seeded — ARMORNET_IDENTITY_CLIENT_SECRET is unset")
		return nil
	}

	bk, ok := b.(*broker)
	if !ok {
		return fmt.Errorf("dex: BFFClientSeeder requires *broker, got %T", b)
	}

	cl := dexstorage.Client{
		ID:           "armornet-bff",
		Secret:       s.Secret,
		Name:         "Armornet BFF",
		LogoURL:      "https://placeholder.invalid/logo.png",
		RedirectURIs: []string{s.RedirectURI},
		Public:       false,
	}

	err := bk.stor.CreateClient(ctx, cl)
	if err == nil {
		slog.InfoContext(ctx, "dex: seeded BFF oauth2 client", "redirect_uri", s.RedirectURI)
		return nil
	}
	if !errors.Is(err, dexstorage.ErrAlreadyExists) {
		return fmt.Errorf("dex: create BFF client: %w", err)
	}

	// Exists: resync to the env var, or the seed and k8s secret drift apart.
	if err := bk.stor.UpdateClient(ctx, "armornet-bff", func(old dexstorage.Client) (dexstorage.Client, error) {
		old.Secret = s.Secret
		old.RedirectURIs = []string{s.RedirectURI}
		if old.LogoURL == "" {
			old.LogoURL = cl.LogoURL
		}
		return old, nil
	}); err != nil {
		return fmt.Errorf("dex: update BFF client: %w", err)
	}
	slog.InfoContext(ctx, "dex: synchronized BFF oauth2 client", "redirect_uri", s.RedirectURI)
	return nil
}
