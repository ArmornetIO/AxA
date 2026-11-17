package client

import (
	"context"
	"fmt"

	"github.com/ArmornetIO/axa/internal/dex/storage"
	"github.com/ArmornetIO/axa/internal/dex/storage/ent/db/authrequest"
)

// CreateAuthRequest saves provided auth request into the database.
func (d *Database) CreateAuthRequest(ctx context.Context, a storage.AuthRequest) error {
	if err := d.requireOrgID(); err != nil {
		return err
	}
	// ARMORNET FORK: seal claims.Email at rest.
	claims, err := d.sealClaims(a.Claims)
	if err != nil {
		return convertDBError("create auth request: seal claims: %w", err)
	}
	_, err = d.client.AuthRequest.Create().
		SetID(a.ID).
		SetClientID(a.ClientID).
		SetScopes(a.Scopes).
		SetResponseTypes(a.ResponseTypes).
		SetRedirectURI(a.RedirectURI).
		SetState(a.State).
		SetNonce(a.Nonce).
		SetForceApprovalPrompt(a.ForceApprovalPrompt).
		SetLoggedIn(a.LoggedIn).
		SetClaimsUserID(a.Claims.UserID).
		SetClaimsEmail(claims.Email).
		SetClaimsEmailVerified(a.Claims.EmailVerified).
		SetClaimsUsername(claims.Username).
		SetClaimsPreferredUsername(claims.PreferredUsername).
		SetClaimsGroups(a.Claims.Groups).
		SetCodeChallenge(a.PKCE.CodeChallenge).
		SetCodeChallengeMethod(a.PKCE.CodeChallengeMethod).
		// Save utc time into database because ent doesn't support comparing dates with different timezones
		SetExpiry(a.Expiry.UTC()).
		SetConnectorID(a.ConnectorID).
		SetConnectorData(a.ConnectorData).
		SetHmacKey(a.HMACKey).
		// ARMORNET FORK: scope to organization
		SetOrgID(d.orgID).
		Save(ctx)
	if err != nil {
		return convertDBError("create auth request: %w", err)
	}
	return nil
}

// GetAuthRequest extracts an auth request from the database by id.
// ARMORNET FORK: always scoped to d.orgID — errors if orgID is unset.
func (d *Database) GetAuthRequest(ctx context.Context, id string) (storage.AuthRequest, error) {
	if err := d.requireOrgID(); err != nil {
		return storage.AuthRequest{}, err
	}
	ar, err := d.client.AuthRequest.Query().
		Where(authrequest.ID(id), authrequest.OrgID(d.orgID)).
		Only(ctx)
	if err != nil {
		return storage.AuthRequest{}, convertDBError("get auth request: %w", err)
	}
	// ARMORNET FORK: unseal claims.Email on read.
	st := toStorageAuthRequest(ar)
	if st.Claims, err = d.openClaims(st.Claims); err != nil {
		return storage.AuthRequest{}, convertDBError("get auth request: open claims: %w", err)
	}
	return st, nil
}

// DeleteAuthRequest deletes an auth request from the database by id.
func (d *Database) DeleteAuthRequest(ctx context.Context, id string) error {
	if err := d.requireOrgID(); err != nil {
		return err
	}
	err := d.client.AuthRequest.DeleteOneID(id).Exec(ctx)
	if err != nil {
		return convertDBError("delete auth request: %w", err)
	}
	return nil
}

// UpdateAuthRequest changes an auth request by id using an updater function and saves it to the database.
func (d *Database) UpdateAuthRequest(ctx context.Context, id string, updater func(old storage.AuthRequest) (storage.AuthRequest, error)) error {
	if err := d.requireOrgID(); err != nil {
		return err
	}
	tx, err := d.BeginTx(ctx)
	if err != nil {
		return fmt.Errorf("update auth request tx: %w", err)
	}

	// ARMORNET FORK: always scope to org within transaction
	ar, err := tx.AuthRequest.Query().
		Where(authrequest.ID(id), authrequest.OrgID(d.orgID)).
		Only(context.TODO())
	if err != nil {
		return rollback(tx, "update auth request database: %w", err)
	}

	// ARMORNET FORK: the updater sees plaintext — finalizeLogin writes the
	// connector's claims through here — so open before and seal after.
	old := toStorageAuthRequest(ar)
	if old.Claims, err = d.openClaims(old.Claims); err != nil {
		return rollback(tx, "update auth request opening claims: %w", err)
	}

	newAuthRequest, err := updater(old)
	if err != nil {
		return rollback(tx, "update auth request updating: %w", err)
	}
	sealed, err := d.sealClaims(newAuthRequest.Claims)
	if err != nil {
		return rollback(tx, "update auth request sealing claims: %w", err)
	}

	_, err = tx.AuthRequest.UpdateOneID(newAuthRequest.ID).
		SetClientID(newAuthRequest.ClientID).
		SetScopes(newAuthRequest.Scopes).
		SetResponseTypes(newAuthRequest.ResponseTypes).
		SetRedirectURI(newAuthRequest.RedirectURI).
		SetState(newAuthRequest.State).
		SetNonce(newAuthRequest.Nonce).
		SetForceApprovalPrompt(newAuthRequest.ForceApprovalPrompt).
		SetLoggedIn(newAuthRequest.LoggedIn).
		SetClaimsUserID(newAuthRequest.Claims.UserID).
		SetClaimsEmail(sealed.Email).
		SetClaimsEmailVerified(newAuthRequest.Claims.EmailVerified).
		SetClaimsUsername(sealed.Username).
		SetClaimsPreferredUsername(sealed.PreferredUsername).
		SetClaimsGroups(newAuthRequest.Claims.Groups).
		SetCodeChallenge(newAuthRequest.PKCE.CodeChallenge).
		SetCodeChallengeMethod(newAuthRequest.PKCE.CodeChallengeMethod).
		// Save utc time into database because ent doesn't support comparing dates with different timezones
		SetExpiry(newAuthRequest.Expiry.UTC()).
		SetConnectorID(newAuthRequest.ConnectorID).
		SetConnectorData(newAuthRequest.ConnectorData).
		SetHmacKey(newAuthRequest.HMACKey).
		Save(context.TODO())
	if err != nil {
		return rollback(tx, "update auth request uploading: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return rollback(tx, "update auth request commit: %w", err)
	}

	return nil
}
