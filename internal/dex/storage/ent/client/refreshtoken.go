package client

import (
	"context"

	"github.com/ArmornetIO/axa/internal/dex/storage"
	"github.com/ArmornetIO/axa/internal/dex/storage/ent/db/refreshtoken"
)

// CreateRefresh saves provided refresh token into the database.
func (d *Database) CreateRefresh(ctx context.Context, refresh storage.RefreshToken) error {
	if err := d.requireOrgID(); err != nil {
		return err
	}
	// ARMORNET FORK: seal claims.Email at rest — a refresh token outlives every
	// other Dex row, so this is where the address would otherwise sit longest.
	claims, err := d.sealClaims(refresh.Claims)
	if err != nil {
		return convertDBError("create refresh token: seal claims: %w", err)
	}
	_, err = d.client.RefreshToken.Create().
		SetID(refresh.ID).
		SetClientID(refresh.ClientID).
		SetScopes(refresh.Scopes).
		SetNonce(refresh.Nonce).
		SetClaimsUserID(refresh.Claims.UserID).
		SetClaimsEmail(claims.Email).
		SetClaimsEmailVerified(refresh.Claims.EmailVerified).
		SetClaimsUsername(claims.Username).
		SetClaimsPreferredUsername(claims.PreferredUsername).
		SetClaimsGroups(refresh.Claims.Groups).
		SetConnectorID(refresh.ConnectorID).
		SetConnectorData(refresh.ConnectorData).
		SetToken(refresh.Token).
		SetObsoleteToken(refresh.ObsoleteToken).
		// Save utc time into database because ent doesn't support comparing dates with different timezones
		SetLastUsed(refresh.LastUsed.UTC()).
		SetCreatedAt(refresh.CreatedAt.UTC()).
		// ARMORNET FORK: scope to organization
		SetOrgID(d.orgID).
		Save(ctx)
	if err != nil {
		return convertDBError("create refresh token: %w", err)
	}
	return nil
}

// ListRefreshTokens extracts an array of refresh tokens from the database.
// ARMORNET FORK: always scoped to d.orgID — errors if orgID is unset.
func (d *Database) ListRefreshTokens(ctx context.Context) ([]storage.RefreshToken, error) {
	if err := d.requireOrgID(); err != nil {
		return nil, err
	}
	refreshTokens, err := d.client.RefreshToken.Query().
		Where(refreshtoken.OrgID(d.orgID)).
		All(ctx)
	if err != nil {
		return nil, convertDBError("list refresh tokens: %w", err)
	}

	storageRefreshTokens := make([]storage.RefreshToken, 0, len(refreshTokens))
	for _, r := range refreshTokens {
		st := toStorageRefreshToken(r)
		// ARMORNET FORK: unseal claims.Email on read.
		if st.Claims, err = d.openClaims(st.Claims); err != nil {
			return nil, convertDBError("list refresh tokens: open claims: %w", err)
		}
		storageRefreshTokens = append(storageRefreshTokens, st)
	}
	return storageRefreshTokens, nil
}

// GetRefresh extracts a refresh token from the database by id.
// ARMORNET FORK: always scoped to d.orgID — errors if orgID is unset.
func (d *Database) GetRefresh(ctx context.Context, id string) (storage.RefreshToken, error) {
	if err := d.requireOrgID(); err != nil {
		return storage.RefreshToken{}, err
	}
	rt, err := d.client.RefreshToken.Query().
		Where(refreshtoken.ID(id), refreshtoken.OrgID(d.orgID)).
		Only(ctx)
	if err != nil {
		return storage.RefreshToken{}, convertDBError("get refresh token: %w", err)
	}
	// ARMORNET FORK: unseal claims.Email on read.
	st := toStorageRefreshToken(rt)
	if st.Claims, err = d.openClaims(st.Claims); err != nil {
		return storage.RefreshToken{}, convertDBError("get refresh token: open claims: %w", err)
	}
	return st, nil
}

// DeleteRefresh deletes a refresh token from the database by id.
func (d *Database) DeleteRefresh(ctx context.Context, id string) error {
	if err := d.requireOrgID(); err != nil {
		return err
	}
	err := d.client.RefreshToken.DeleteOneID(id).Exec(ctx)
	if err != nil {
		return convertDBError("delete refresh token: %w", err)
	}
	return nil
}

// UpdateRefreshToken changes a refresh token by id using an updater function and saves it to the database.
func (d *Database) UpdateRefreshToken(ctx context.Context, id string, updater func(old storage.RefreshToken) (storage.RefreshToken, error)) error {
	if err := d.requireOrgID(); err != nil {
		return err
	}
	tx, err := d.BeginTx(ctx)
	if err != nil {
		return convertDBError("update refresh token tx: %w", err)
	}

	// ARMORNET FORK: always scope to org within transaction
	token, err := tx.RefreshToken.Query().
		Where(refreshtoken.ID(id), refreshtoken.OrgID(d.orgID)).
		Only(ctx)
	if err != nil {
		return rollback(tx, "update refresh token database: %w", err)
	}

	// ARMORNET FORK: the updater sees plaintext, so open before and seal after —
	// refreshhandlers rewrites Claims.Email from the upstream identity here.
	old := toStorageRefreshToken(token)
	if old.Claims, err = d.openClaims(old.Claims); err != nil {
		return rollback(tx, "update refresh token opening claims: %w", err)
	}

	newToken, err := updater(old)
	if err != nil {
		return rollback(tx, "update refresh token updating: %w", err)
	}
	sealed, err := d.sealClaims(newToken.Claims)
	if err != nil {
		return rollback(tx, "update refresh token sealing claims: %w", err)
	}

	_, err = tx.RefreshToken.UpdateOneID(newToken.ID).
		SetClientID(newToken.ClientID).
		SetScopes(newToken.Scopes).
		SetNonce(newToken.Nonce).
		SetClaimsUserID(newToken.Claims.UserID).
		SetClaimsEmail(sealed.Email).
		SetClaimsEmailVerified(newToken.Claims.EmailVerified).
		SetClaimsUsername(sealed.Username).
		SetClaimsPreferredUsername(sealed.PreferredUsername).
		SetClaimsGroups(newToken.Claims.Groups).
		SetConnectorID(newToken.ConnectorID).
		SetConnectorData(newToken.ConnectorData).
		SetToken(newToken.Token).
		SetObsoleteToken(newToken.ObsoleteToken).
		// Save utc time into database because ent doesn't support comparing dates with different timezones
		SetLastUsed(newToken.LastUsed.UTC()).
		SetCreatedAt(newToken.CreatedAt.UTC()).
		Save(ctx)
	if err != nil {
		return rollback(tx, "update refresh token uploading: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return rollback(tx, "update refresh token commit: %w", err)
	}
	return nil
}
