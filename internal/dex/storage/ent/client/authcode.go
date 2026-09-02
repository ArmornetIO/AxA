package client

import (
	"context"

	"github.com/ArmornetIO/identity/internal/dex/storage"
	"github.com/ArmornetIO/identity/internal/dex/storage/ent/db/authcode"
)

// CreateAuthCode saves provided auth code into the database.
func (d *Database) CreateAuthCode(ctx context.Context, code storage.AuthCode) error {
	if err := d.requireOrgID(); err != nil {
		return err
	}
	// ARMORNET FORK: seal claims.Email at rest.
	claims, err := d.sealClaims(code.Claims)
	if err != nil {
		return convertDBError("create auth code: seal claims: %w", err)
	}
	_, err = d.client.AuthCode.Create().
		SetID(code.ID).
		SetClientID(code.ClientID).
		SetScopes(code.Scopes).
		SetRedirectURI(code.RedirectURI).
		SetNonce(code.Nonce).
		SetClaimsUserID(code.Claims.UserID).
		SetClaimsEmail(claims.Email).
		SetClaimsEmailVerified(code.Claims.EmailVerified).
		SetClaimsUsername(claims.Username).
		SetClaimsPreferredUsername(claims.PreferredUsername).
		SetClaimsGroups(code.Claims.Groups).
		SetCodeChallenge(code.PKCE.CodeChallenge).
		SetCodeChallengeMethod(code.PKCE.CodeChallengeMethod).
		// Save utc time into database because ent doesn't support comparing dates with different timezones
		SetExpiry(code.Expiry.UTC()).
		SetConnectorID(code.ConnectorID).
		SetConnectorData(code.ConnectorData).
		// ARMORNET FORK: scope to organization
		SetOrgID(d.orgID).
		Save(ctx)
	if err != nil {
		return convertDBError("create auth code: %w", err)
	}
	return nil
}

// GetAuthCode extracts an auth code from the database by id.
// ARMORNET FORK: always scoped to d.orgID — errors if orgID is unset.
func (d *Database) GetAuthCode(ctx context.Context, id string) (storage.AuthCode, error) {
	if err := d.requireOrgID(); err != nil {
		return storage.AuthCode{}, err
	}
	ac, err := d.client.AuthCode.Query().
		Where(authcode.ID(id), authcode.OrgID(d.orgID)).
		Only(ctx)
	if err != nil {
		return storage.AuthCode{}, convertDBError("get auth code: %w", err)
	}
	// ARMORNET FORK: unseal claims.Email on read.
	st := toStorageAuthCode(ac)
	if st.Claims, err = d.openClaims(st.Claims); err != nil {
		return storage.AuthCode{}, convertDBError("get auth code: open claims: %w", err)
	}
	return st, nil
}

// DeleteAuthCode deletes an auth code from the database by id.
func (d *Database) DeleteAuthCode(ctx context.Context, id string) error {
	if err := d.requireOrgID(); err != nil {
		return err
	}
	err := d.client.AuthCode.DeleteOneID(id).Exec(ctx)
	if err != nil {
		return convertDBError("delete auth code: %w", err)
	}
	return nil
}
