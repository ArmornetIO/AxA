package client

import (
	"context"
	"errors"
	"fmt"

	"github.com/ArmornetIO/axa/internal/dex/storage"
	"github.com/ArmornetIO/axa/internal/dex/storage/ent/db"
	"github.com/go-jose/go-jose/v4"
)

// SealedSigningKeyID marks a signing key JWK as sealed. ARMORNET FORK.
//
// The signing key is the private half of the key that mints every ID token, so
// a raw read of this row must not yield it — with it, anyone can issue a token
// for any subject, including a god admin, with MFA nowhere in the path.
//
// It cannot be sealed the way connector configs are. ent types this column
// `field.JSON(jose.JSONWebKey{})`, so the generated setter takes a JWK, and
// storing ciphertext as bytea would mean regenerating the fork's ent code and
// migrating the column. Instead the ciphertext rides inside a symmetric JWK:
// the private key is marshalled, sealed, and stored as the `k` of an `oct` key
// tagged with this kid. Same rule as SealedStringPrefix — the marker is
// explicit rather than inferred, so the state stays checkable in SQL
// (`signing_key->>'kid'`).
const SealedSigningKeyID = "ANS1"

// sealSigningKey wraps the private JWK as described on SealedSigningKeyID.
// Returns it unchanged when no sealer is configured.
func (d *Database) sealSigningKey(k jose.JSONWebKey) (jose.JSONWebKey, error) {
	if d.fieldSealer == nil {
		return k, nil
	}
	plaintext, err := k.MarshalJSON()
	if err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("marshal signing key: %w", err)
	}
	sealed, err := d.sealField(plaintext)
	if err != nil {
		return jose.JSONWebKey{}, err
	}
	return jose.JSONWebKey{Key: sealed, KeyID: SealedSigningKeyID}, nil
}

// openSigningKey reverses sealSigningKey.
//
// A key without the marker is returned as-is: rows written before sealing was
// enabled must keep working, and Dex rewrites this row on its own rotation
// schedule, so a legacy row seals itself within one rotation period without a
// backfill.
func (d *Database) openSigningKey(k jose.JSONWebKey) (jose.JSONWebKey, error) {
	if k.KeyID != SealedSigningKeyID {
		return k, nil
	}
	sealed, ok := k.Key.([]byte)
	if !ok {
		return jose.JSONWebKey{}, fmt.Errorf("signing key is marked sealed but holds %T", k.Key)
	}
	plaintext, err := d.openField(sealed)
	if err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("open signing key: %w", err)
	}
	var open jose.JSONWebKey
	if err := open.UnmarshalJSON(plaintext); err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("unmarshal signing key: %w", err)
	}
	return open, nil
}

func (d *Database) getKeys(ctx context.Context, client *db.KeysClient) (storage.Keys, error) {
	rawKeys, err := client.Get(ctx, keysRowID)
	if err != nil {
		return storage.Keys{}, convertDBError("get keys: %w", err)
	}
	keys := toStorageKeys(rawKeys)
	// ARMORNET FORK: decrypt the signing key on read when configured.
	open, err := d.openSigningKey(*keys.SigningKey)
	if err != nil {
		return storage.Keys{}, convertDBError("get keys: %w", err)
	}
	keys.SigningKey = &open
	return keys, nil
}

// GetKeys returns signing keys, public keys and verification keys from the database.
func (d *Database) GetKeys(ctx context.Context) (storage.Keys, error) {
	return d.getKeys(ctx, d.client.Keys)
}

// UpdateKeys rotates keys using updater function.
func (d *Database) UpdateKeys(ctx context.Context, updater func(old storage.Keys) (storage.Keys, error)) error {
	firstUpdate := false

	tx, err := d.BeginTx(ctx)
	if err != nil {
		return convertDBError("update keys tx: %w", err)
	}

	storageKeys, err := d.getKeys(ctx, tx.Keys)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			return rollback(tx, "update keys get: %w", err)
		}
		firstUpdate = true
	}

	newKeys, err := updater(storageKeys)
	if err != nil {
		return rollback(tx, "update keys updating: %w", err)
	}

	// ARMORNET FORK: encrypt the signing key before storage when configured.
	// Only the private half — signing_key_pub and verification_keys are public
	// by definition, and sealing them would break nothing but reveal nothing.
	sealedSigningKey, err := d.sealSigningKey(*newKeys.SigningKey)
	if err != nil {
		return rollback(tx, "update keys: seal signing key: %w", err)
	}

	// ent doesn't have an upsert support yet
	// https://github.com/facebook/ent/issues/139
	if firstUpdate {
		_, err = tx.Keys.Create().
			SetID(keysRowID).
			SetNextRotation(newKeys.NextRotation).
			SetSigningKey(sealedSigningKey).
			SetSigningKeyPub(*newKeys.SigningKeyPub).
			SetVerificationKeys(newKeys.VerificationKeys).
			Save(ctx)
		if err != nil {
			return rollback(tx, "create keys: %w", err)
		}
		if err = tx.Commit(); err != nil {
			return rollback(tx, "update keys commit: %w", err)
		}
		return nil
	}

	err = tx.Keys.UpdateOneID(keysRowID).
		SetNextRotation(newKeys.NextRotation.UTC()).
		SetSigningKey(sealedSigningKey).
		SetSigningKeyPub(*newKeys.SigningKeyPub).
		SetVerificationKeys(newKeys.VerificationKeys).
		Exec(ctx)
	if err != nil {
		return rollback(tx, "update keys uploading: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return rollback(tx, "update keys commit: %w", err)
	}

	return nil
}
