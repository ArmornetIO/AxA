package client

import (
	"context"

	"github.com/ArmornetIO/axa/internal/dex/storage"
	"github.com/ArmornetIO/axa/internal/dex/storage/ent/db"
	"github.com/ArmornetIO/axa/internal/dex/storage/ent/db/connector"
	"github.com/ArmornetIO/axa/internal/dex/storage/ent/db/predicate"
)

// CreateConnector saves a connector into the database.
func (d *Database) CreateConnector(ctx context.Context, c storage.Connector) error {
	if err := d.requireOrgID(); err != nil {
		return err
	}
	// ARMORNET FORK: encrypt the config before storage when configured.
	config, err := d.sealField(c.Config)
	if err != nil {
		return convertDBError("create connector: seal config: %w", err)
	}
	_, err = d.client.Connector.Create().
		SetID(c.ID).
		SetName(c.Name).
		SetType(c.Type).
		SetResourceVersion(c.ResourceVersion).
		SetConfig(config).
		// ARMORNET FORK: scope to organization
		SetOrgID(d.orgID).
		Save(ctx)
	if err != nil {
		return convertDBError("create connector: %w", err)
	}
	return nil
}

// connectorScope is ARMORNET FORK. The embedded instance (no org) serves every
// org's login, so it finds connectors by id alone: org_id on a connector is
// armornet's tenancy marker (whose login page offers it), claimed after Dex
// creates the row. Filtering on an empty org_id forced every org connector to
// keep one — which armornet reads as "global" — to stay loadable.
func (d *Database) connectorScope() []predicate.Connector {
	if d.orgID == "" {
		return nil
	}
	return []predicate.Connector{connector.OrgID(d.orgID)}
}

// ListConnectors extracts an array of connectors from the database.
// ARMORNET FORK: always scoped to d.orgID — errors if orgID is unset.
func (d *Database) ListConnectors(ctx context.Context) ([]storage.Connector, error) {
	if err := d.requireOrgID(); err != nil {
		return nil, err
	}
	connectors, err := d.client.Connector.Query().
		Where(d.connectorScope()...).
		All(ctx)
	if err != nil {
		return nil, convertDBError("list connectors: %w", err)
	}

	storageConnectors := make([]storage.Connector, 0, len(connectors))
	for _, c := range connectors {
		// ARMORNET FORK: decrypt the config on read when configured.
		sc, err := d.toStorageConnectorOpened(c)
		if err != nil {
			return nil, convertDBError("list connectors: open config: %w", err)
		}
		storageConnectors = append(storageConnectors, sc)
	}
	return storageConnectors, nil
}

// toStorageConnectorOpened converts a stored connector and decrypts its config.
// ARMORNET FORK: the config column holds replayable upstream IdP credentials and
// is sealed at rest; every read path must go through here rather than calling
// toStorageConnector directly, or Dex is handed ciphertext as its config JSON.
func (d *Database) toStorageConnectorOpened(c *db.Connector) (storage.Connector, error) {
	sc := toStorageConnector(c)
	config, err := d.openField(sc.Config)
	if err != nil {
		return storage.Connector{}, err
	}
	sc.Config = config
	return sc, nil
}

// GetConnector extracts a connector from the database by id.
// ARMORNET FORK: always scoped to d.orgID — errors if orgID is unset.
func (d *Database) GetConnector(ctx context.Context, id string) (storage.Connector, error) {
	if err := d.requireOrgID(); err != nil {
		return storage.Connector{}, err
	}
	c, err := d.client.Connector.Query().
		Where(append(d.connectorScope(), connector.ID(id))...).
		Only(ctx)
	if err != nil {
		return storage.Connector{}, convertDBError("get connector: %w", err)
	}
	// ARMORNET FORK: decrypt the config on read when configured.
	sc, err := d.toStorageConnectorOpened(c)
	if err != nil {
		return storage.Connector{}, convertDBError("get connector: open config: %w", err)
	}
	return sc, nil
}

// DeleteConnector deletes a connector from the database by id.
func (d *Database) DeleteConnector(ctx context.Context, id string) error {
	if err := d.requireOrgID(); err != nil {
		return err
	}
	err := d.client.Connector.DeleteOneID(id).Exec(ctx)
	if err != nil {
		return convertDBError("delete connector: %w", err)
	}
	return nil
}

// UpdateConnector changes a connector by id using an updater function and saves it to the database.
func (d *Database) UpdateConnector(ctx context.Context, id string, updater func(old storage.Connector) (storage.Connector, error)) error {
	if err := d.requireOrgID(); err != nil {
		return err
	}
	tx, err := d.BeginTx(ctx)
	if err != nil {
		return convertDBError("update connector tx: %w", err)
	}

	// ARMORNET FORK: always scope to org within transaction
	c, err := tx.Connector.Query().
		Where(append(d.connectorScope(), connector.ID(id))...).
		Only(ctx)
	if err != nil {
		return rollback(tx, "update connector database: %w", err)
	}

	// ARMORNET FORK: the updater must see the config as plaintext JSON — that is
	// what every caller reads and rewrites — so open before and seal after. Doing
	// it in the other order would hand the updater ciphertext and then seal it
	// again, storing Seal(Seal(config)); the connector would decrypt to garbage on
	// the next read and the upstream IdP credentials inside would be unrecoverable.
	old, err := d.toStorageConnectorOpened(c)
	if err != nil {
		return rollback(tx, "update connector: open config: %w", err)
	}

	newConnector, err := updater(old)
	if err != nil {
		return rollback(tx, "update connector updating: %w", err)
	}

	config, err := d.sealField(newConnector.Config)
	if err != nil {
		return rollback(tx, "update connector: seal config: %w", err)
	}

	_, err = tx.Connector.UpdateOneID(newConnector.ID).
		SetName(newConnector.Name).
		SetType(newConnector.Type).
		SetResourceVersion(newConnector.ResourceVersion).
		SetConfig(config).
		Save(ctx)
	if err != nil {
		return rollback(tx, "update connector uploading: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return rollback(tx, "update connector commit: %w", err)
	}

	return nil
}
