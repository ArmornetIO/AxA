package dex

import (
	"context"
	"errors"
	"fmt"

	"github.com/ArmornetIO/identity"
	dexstorage "github.com/ArmornetIO/identity/internal/dex/storage"
)

// SeedPassword writes one account for Dex's "local" password connector. The
// username doubles as the stable user ID, so a changed hash keeps the same
// subject and the account keeps its memberships.
func SeedPassword(username string, bcryptHash []byte) identity.SeedFunc {
	return func(ctx context.Context, b identity.Broker) error {
		bk, ok := b.(*broker)
		if !ok {
			return fmt.Errorf("dex: SeedPassword requires *broker, got %T", b)
		}
		p := dexstorage.Password{Email: username, Username: username, UserID: username, Hash: bcryptHash}
		err := bk.stor.CreatePassword(ctx, p)
		if errors.Is(err, dexstorage.ErrAlreadyExists) {
			err = bk.stor.UpdatePassword(ctx, username, func(old dexstorage.Password) (dexstorage.Password, error) {
				old.Hash = bcryptHash
				return old, nil
			})
		}
		if err != nil {
			return fmt.Errorf("dex: seed password %q: %w", username, err)
		}
		return nil
	}
}
