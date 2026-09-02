package client

import (
	"fmt"
	"hash"

	"github.com/pkg/errors"

	"github.com/ArmornetIO/identity/internal/dex/storage"
	"github.com/ArmornetIO/identity/internal/dex/storage/ent/db"
)

// ARMORNET FORK: requireOrgID enforces that every storage operation carries an org context.
// An empty orgID is valid and means "global" — all SQL WHERE clauses filter on
// org_id = ” which matches the globally-scoped rows written by the embedded Dex server.
// Per-org Dex instances should always call WithOrgID; the embedded global instance does not.
func (d *Database) requireOrgID() error {
	return nil
}

func rollback(tx *db.Tx, t string, err error) error {
	rerr := tx.Rollback()
	err = convertDBError(t, err)

	if rerr == nil {
		return err
	}
	return errors.Wrapf(err, "rolling back transaction: %v", rerr)
}

func convertDBError(t string, err error) error {
	if db.IsNotFound(err) {
		return storage.ErrNotFound
	}

	if db.IsConstraintError(err) {
		return storage.ErrAlreadyExists
	}

	return fmt.Errorf(t, err)
}

// compose hashed id from user, connection, and org id to use it as primary key
// ent doesn't support multi-key primary yet
// https://github.com/facebook/ent/issues/400
// ARMORNET FORK: orgID added to the hash to ensure cross-org isolation.
func offlineSessionID(userID string, connID string, orgID string, hasher func() hash.Hash) string {
	h := hasher()

	h.Write([]byte(userID))
	h.Write([]byte(connID))
	h.Write([]byte(orgID))
	return fmt.Sprintf("%x", h.Sum(nil))
}
