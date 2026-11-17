package client

import (
	"context"

	"github.com/ArmornetIO/axa/internal/dex/storage"
	"github.com/ArmornetIO/axa/internal/dex/storage/ent/db/oauth2client"
)

// CreateClient saves provided oauth2 client settings into the database.
// ARMORNET FORK: hashes the client secret via secretHasher before storage when configured.
func (d *Database) CreateClient(ctx context.Context, c storage.Client) error {
	if err := d.requireOrgID(); err != nil {
		return err
	}
	secret, err := d.hashSecret(c.Secret)
	if err != nil {
		return convertDBError("create oauth2 client: hash secret: %w", err)
	}
	_, err = d.client.OAuth2Client.Create().
		SetID(c.ID).
		SetName(c.Name).
		SetSecret(secret).
		SetPublic(c.Public).
		SetLogoURL(c.LogoURL).
		SetRedirectUris(c.RedirectURIs).
		SetTrustedPeers(c.TrustedPeers).
		// ARMORNET FORK: scope to organization
		SetOrgID(d.orgID).
		Save(ctx)
	if err != nil {
		return convertDBError("create oauth2 client: %w", err)
	}
	return nil
}

// ListClients extracts an array of oauth2 clients from the database.
// ARMORNET FORK: always scoped to d.orgID — errors if orgID is unset.
func (d *Database) ListClients(ctx context.Context) ([]storage.Client, error) {
	if err := d.requireOrgID(); err != nil {
		return nil, err
	}
	clients, err := d.client.OAuth2Client.Query().
		Where(oauth2client.OrgID(d.orgID)).
		All(ctx)
	if err != nil {
		return nil, convertDBError("list clients: %w", err)
	}

	storageClients := make([]storage.Client, 0, len(clients))
	for _, c := range clients {
		storageClients = append(storageClients, toStorageClient(c))
	}
	return storageClients, nil
}

// GetClient extracts an oauth2 client from the database by id.
// ARMORNET FORK: always scoped to d.orgID — errors if orgID is unset.
func (d *Database) GetClient(ctx context.Context, id string) (storage.Client, error) {
	if err := d.requireOrgID(); err != nil {
		return storage.Client{}, err
	}
	c, err := d.client.OAuth2Client.Query().
		Where(oauth2client.ID(id), oauth2client.OrgID(d.orgID)).
		Only(ctx)
	if err != nil {
		return storage.Client{}, convertDBError("get client: %w", err)
	}
	return toStorageClient(c), nil
}

// DeleteClient deletes an oauth2 client from the database by id.
func (d *Database) DeleteClient(ctx context.Context, id string) error {
	if err := d.requireOrgID(); err != nil {
		return err
	}
	err := d.client.OAuth2Client.DeleteOneID(id).Exec(ctx)
	if err != nil {
		return convertDBError("delete client: %w", err)
	}
	return nil
}

// UpdateClient changes an oauth2 client by id using an updater function and saves it to the database.
func (d *Database) UpdateClient(ctx context.Context, id string, updater func(old storage.Client) (storage.Client, error)) error {
	if err := d.requireOrgID(); err != nil {
		return err
	}
	tx, err := d.BeginTx(ctx)
	if err != nil {
		return convertDBError("update client tx: %w", err)
	}

	// ARMORNET FORK: always scope to org within transaction
	c, err := tx.OAuth2Client.Query().
		Where(oauth2client.ID(id), oauth2client.OrgID(d.orgID)).
		Only(ctx)
	if err != nil {
		return rollback(tx, "update client database: %w", err)
	}

	newClient, err := updater(toStorageClient(c))
	if err != nil {
		return rollback(tx, "update client updating: %w", err)
	}

	// ARMORNET FORK: hash the updated secret only when the updater changed it.
	newSecret, err := d.secretForUpdate(c.Secret, newClient.Secret)
	if err != nil {
		return rollback(tx, "update client: hash secret: %w", err)
	}

	_, err = tx.OAuth2Client.UpdateOneID(newClient.ID).
		SetName(newClient.Name).
		SetSecret(newSecret).
		SetPublic(newClient.Public).
		SetLogoURL(newClient.LogoURL).
		SetRedirectUris(newClient.RedirectURIs).
		SetTrustedPeers(newClient.TrustedPeers).
		Save(ctx)
	if err != nil {
		return rollback(tx, "update client uploading: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return rollback(tx, "update client commit: %w", err)
	}

	return nil
}
