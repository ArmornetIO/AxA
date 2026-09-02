package client

import (
	"context"
	"strings"

	"github.com/ArmornetIO/identity/internal/dex/storage"
	"github.com/ArmornetIO/identity/internal/dex/storage/ent/db/password"
)

// CreatePassword saves provided password into the database.
func (d *Database) CreatePassword(ctx context.Context, p storage.Password) error {
	if err := d.requireOrgID(); err != nil {
		return err
	}
	_, err := d.client.Password.Create().
		SetEmail(p.Email).
		SetHash(p.Hash).
		SetUsername(p.Username).
		SetName(p.Name).
		SetPreferredUsername(p.PreferredUsername).
		SetNillableEmailVerified(p.EmailVerified).
		SetUserID(p.UserID).
		SetGroups(p.Groups).
		// ARMORNET FORK: scope to organization
		SetOrgID(d.orgID).
		Save(ctx)
	if err != nil {
		return convertDBError("create password: %w", err)
	}
	return nil
}

// ListPasswords extracts an array of passwords from the database.
// ARMORNET FORK: always scoped to d.orgID — errors if orgID is unset.
func (d *Database) ListPasswords(ctx context.Context) ([]storage.Password, error) {
	if err := d.requireOrgID(); err != nil {
		return nil, err
	}
	passwords, err := d.client.Password.Query().
		Where(password.OrgID(d.orgID)).
		All(ctx)
	if err != nil {
		return nil, convertDBError("list passwords: %w", err)
	}

	storagePasswords := make([]storage.Password, 0, len(passwords))
	for _, p := range passwords {
		storagePasswords = append(storagePasswords, toStoragePassword(p))
	}
	return storagePasswords, nil
}

// GetPassword extracts a password from the database by email.
// ARMORNET FORK: always scoped to d.orgID — errors if orgID is unset.
func (d *Database) GetPassword(ctx context.Context, email string) (storage.Password, error) {
	if err := d.requireOrgID(); err != nil {
		return storage.Password{}, err
	}
	email = strings.ToLower(email)
	p, err := d.client.Password.Query().
		Where(password.Email(email), password.OrgID(d.orgID)).
		Only(ctx)
	if err != nil {
		return storage.Password{}, convertDBError("get password: %w", err)
	}
	return toStoragePassword(p), nil
}

// DeletePassword deletes a password from the database by email.
// ARMORNET FORK: always scoped to d.orgID — errors if orgID is unset.
func (d *Database) DeletePassword(ctx context.Context, email string) error {
	if err := d.requireOrgID(); err != nil {
		return err
	}
	email = strings.ToLower(email)
	_, err := d.client.Password.Delete().
		Where(password.Email(email), password.OrgID(d.orgID)).
		Exec(ctx)
	if err != nil {
		return convertDBError("delete password: %w", err)
	}
	return nil
}

// UpdatePassword changes a password by email using an updater function and saves it to the database.
func (d *Database) UpdatePassword(ctx context.Context, email string, updater func(old storage.Password) (storage.Password, error)) error {
	if err := d.requireOrgID(); err != nil {
		return err
	}
	email = strings.ToLower(email)

	tx, err := d.BeginTx(ctx)
	if err != nil {
		return convertDBError("update password tx: %w", err)
	}

	// ARMORNET FORK: always scope to org within transaction
	passwordToUpdate, err := tx.Password.Query().
		Where(password.Email(email), password.OrgID(d.orgID)).
		Only(ctx)
	if err != nil {
		return rollback(tx, "update password database: %w", err)
	}

	newPassword, err := updater(toStoragePassword(passwordToUpdate))
	if err != nil {
		return rollback(tx, "update password updating: %w", err)
	}

	_, err = tx.Password.Update().
		Where(password.Email(newPassword.Email), password.OrgID(d.orgID)).
		SetEmail(newPassword.Email).
		SetHash(newPassword.Hash).
		SetUsername(newPassword.Username).
		SetName(newPassword.Name).
		SetPreferredUsername(newPassword.PreferredUsername).
		SetNillableEmailVerified(newPassword.EmailVerified).
		SetUserID(newPassword.UserID).
		SetGroups(newPassword.Groups).
		Save(ctx)
	if err != nil {
		return rollback(tx, "update password uploading: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return rollback(tx, "update password commit: %w", err)
	}

	return nil
}
