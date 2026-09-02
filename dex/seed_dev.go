package dex

import (
	"context"
	"errors"
	"fmt"

	"github.com/ArmornetIO/identity"
	dexstorage "github.com/ArmornetIO/identity/internal/dex/storage"
)

// SeedClient writes a confidential client under a secret the caller fixes, so
// a local config can carry it. A fixed secret is a dev convenience: gate the
// call on the host's dev mode. An existing client is left as it is.
func SeedClient(id, secret, name string) identity.SeedFunc {
	return func(ctx context.Context, b identity.Broker) error {
		bk, ok := b.(*broker)
		if !ok {
			return fmt.Errorf("dex: SeedClient requires *broker, got %T", b)
		}
		err := bk.stor.CreateClient(ctx, dexstorage.Client{
			ID: id, Secret: secret, Name: name, LogoURL: "http://localhost",
		})
		if err != nil && !errors.Is(err, dexstorage.ErrAlreadyExists) {
			return fmt.Errorf("dex: seed client %q: %w", id, err)
		}
		return nil
	}
}
