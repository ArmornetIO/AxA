package client

import (
	"context"

	"github.com/ArmornetIO/identity/internal/dex/storage"
	"github.com/ArmornetIO/identity/internal/dex/storage/ent/db/devicerequest"
)

// CreateDeviceRequest saves provided device request into the database.
func (d *Database) CreateDeviceRequest(ctx context.Context, request storage.DeviceRequest) error {
	if err := d.requireOrgID(); err != nil {
		return err
	}
	// ARMORNET FORK: the device flow parks a CONFIDENTIAL client's real secret in
	// this row for the lifetime of the request, so it is sealed at rest like a
	// connector config. (A public client stores only the "-" placeholder, which
	// seals harmlessly.)
	clientSecret, err := d.sealFieldString(request.ClientSecret)
	if err != nil {
		return convertDBError("create device request: seal client secret: %w", err)
	}
	_, err = d.client.DeviceRequest.Create().
		SetClientID(request.ClientID).
		SetClientSecret(clientSecret).
		SetScopes(request.Scopes).
		SetUserCode(request.UserCode).
		SetDeviceCode(request.DeviceCode).
		// Save utc time into database because ent doesn't support comparing dates with different timezones
		SetExpiry(request.Expiry.UTC()).
		// ARMORNET FORK: scope to organization
		SetOrgID(d.orgID).
		Save(ctx)
	if err != nil {
		return convertDBError("create device request: %w", err)
	}
	return nil
}

// GetDeviceRequest extracts a device request from the database by user code.
// ARMORNET FORK: always scoped to d.orgID — errors if orgID is unset.
func (d *Database) GetDeviceRequest(ctx context.Context, userCode string) (storage.DeviceRequest, error) {
	if err := d.requireOrgID(); err != nil {
		return storage.DeviceRequest{}, err
	}
	dr, err := d.client.DeviceRequest.Query().
		Where(devicerequest.UserCode(userCode), devicerequest.OrgID(d.orgID)).
		Only(ctx)
	if err != nil {
		return storage.DeviceRequest{}, convertDBError("get device request: %w", err)
	}
	// ARMORNET FORK: decrypt the stored client secret on read.
	sr := toStorageDeviceRequest(dr)
	secret, err := d.openFieldString(sr.ClientSecret)
	if err != nil {
		return storage.DeviceRequest{}, convertDBError("get device request: open client secret: %w", err)
	}
	sr.ClientSecret = secret
	return sr, nil
}
