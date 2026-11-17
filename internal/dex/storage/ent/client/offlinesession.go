package client

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ArmornetIO/axa/internal/dex/storage"
	"github.com/ArmornetIO/axa/internal/dex/storage/ent/db/offlinesession"
)

// CreateOfflineSessions saves provided offline session into the database.
func (d *Database) CreateOfflineSessions(ctx context.Context, session storage.OfflineSessions) error {
	if err := d.requireOrgID(); err != nil {
		return err
	}
	encodedRefresh, err := json.Marshal(session.Refresh)
	if err != nil {
		return fmt.Errorf("encode refresh offline session: %w", err)
	}

	// ARMORNET FORK: orgID is included in the ID hash for cross-org isolation
	id := offlineSessionID(session.UserID, session.ConnID, d.orgID, d.hasher)
	_, err = d.client.OfflineSession.Create().
		SetID(id).
		SetUserID(session.UserID).
		SetConnID(session.ConnID).
		SetConnectorData(session.ConnectorData).
		SetRefresh(encodedRefresh).
		SetOrgID(d.orgID).
		Save(ctx)
	if err != nil {
		return convertDBError("create offline session: %w", err)
	}
	return nil
}

// GetOfflineSessions extracts an offline session from the database by user id and connector id.
// ARMORNET FORK: always scoped to d.orgID — errors if orgID is unset.
func (d *Database) GetOfflineSessions(ctx context.Context, userID, connID string) (storage.OfflineSessions, error) {
	if err := d.requireOrgID(); err != nil {
		return storage.OfflineSessions{}, err
	}
	id := offlineSessionID(userID, connID, d.orgID, d.hasher)
	os, err := d.client.OfflineSession.Query().
		Where(offlinesession.ID(id), offlinesession.OrgID(d.orgID)).
		Only(ctx)
	if err != nil {
		return storage.OfflineSessions{}, convertDBError("get offline session: %w", err)
	}
	return toStorageOfflineSession(os), nil
}

// DeleteOfflineSessions deletes an offline session from the database by user id and connector id.
func (d *Database) DeleteOfflineSessions(ctx context.Context, userID, connID string) error {
	if err := d.requireOrgID(); err != nil {
		return err
	}
	id := offlineSessionID(userID, connID, d.orgID, d.hasher)
	err := d.client.OfflineSession.DeleteOneID(id).Exec(ctx)
	if err != nil {
		return convertDBError("delete offline session: %w", err)
	}
	return nil
}

// UpdateOfflineSessions changes an offline session by user id and connector id using an updater function.
func (d *Database) UpdateOfflineSessions(ctx context.Context, userID string, connID string, updater func(s storage.OfflineSessions) (storage.OfflineSessions, error)) error {
	if err := d.requireOrgID(); err != nil {
		return err
	}
	id := offlineSessionID(userID, connID, d.orgID, d.hasher)

	tx, err := d.BeginTx(ctx)
	if err != nil {
		return convertDBError("update offline session tx: %w", err)
	}

	// ARMORNET FORK: always scope to org within transaction
	os, err := tx.OfflineSession.Query().
		Where(offlinesession.ID(id), offlinesession.OrgID(d.orgID)).
		Only(ctx)
	if err != nil {
		return rollback(tx, "update offline session database: %w", err)
	}

	newOfflineSession, err := updater(toStorageOfflineSession(os))
	if err != nil {
		return rollback(tx, "update offline session updating: %w", err)
	}

	encodedRefresh, err := json.Marshal(newOfflineSession.Refresh)
	if err != nil {
		return rollback(tx, "encode refresh offline session: %w", err)
	}

	_, err = tx.OfflineSession.UpdateOneID(id).
		SetUserID(newOfflineSession.UserID).
		SetConnID(newOfflineSession.ConnID).
		SetConnectorData(newOfflineSession.ConnectorData).
		SetRefresh(encodedRefresh).
		Save(ctx)
	if err != nil {
		return rollback(tx, "update offline session uploading: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return rollback(tx, "update offline session commit: %w", err)
	}

	return nil
}
