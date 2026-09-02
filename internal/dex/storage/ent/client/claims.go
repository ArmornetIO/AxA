package client

import "github.com/ArmornetIO/identity/internal/dex/storage"

// ARMORNET FORK: claims.Email is sealed at rest.
//
// It is the only directly identifying value Dex persists. It arrives from the
// upstream connector identity and is written unconditionally — finalizeLogin
// copies it into the stored claims with no scope check — so a deployment cannot
// opt out of holding it by narrowing what it requests. Sealing is therefore the
// only lever on the storage side.
//
// A text column plus the ANS1: marker is used rather than a bytea pair because
// it needs no schema change: an earlier attempt dropped these columns without
// the companion ent change and broke every login, and had to be reverted a
// migration later. The column stays exactly as the generated ent layer expects.
//
// No blind index is needed — unlike assessment_assignments, no claims field is
// ever a query predicate. Dex looks rows up by id, token, or user id only, and
// reads the email solely to reissue an ID token on refresh.
//
// Username and PreferredUsername are sealed for the same reason: they carry the
// person's real name and upstream login handle. UserID is NOT sealed — it is the
// join key Dex and armornet find rows by, and it is an opaque provider id rather
// than an identifier a reader can resolve to a person on its own.
func (d *Database) sealClaims(c storage.Claims) (storage.Claims, error) {
	var err error
	if c.Email, err = d.sealFieldString(c.Email); err != nil {
		return storage.Claims{}, err
	}
	if c.Username, err = d.sealFieldString(c.Username); err != nil {
		return storage.Claims{}, err
	}
	if c.PreferredUsername, err = d.sealFieldString(c.PreferredUsername); err != nil {
		return storage.Claims{}, err
	}
	return c, nil
}

// openClaims reverses sealClaims. Like openFieldString it rejects an unmarked
// value when a sealer is configured — the schema's *_claims_email_sealed,
// *_claims_username_sealed and *_claims_preferred_username_sealed constraints
// admit only an ANS1:-marked value or the empty string, so an unmarked one means
// something wrote around them.
func (d *Database) openClaims(c storage.Claims) (storage.Claims, error) {
	var err error
	if c.Email, err = d.openFieldString(c.Email); err != nil {
		return storage.Claims{}, err
	}
	if c.Username, err = d.openFieldString(c.Username); err != nil {
		return storage.Claims{}, err
	}
	if c.PreferredUsername, err = d.openFieldString(c.PreferredUsername); err != nil {
		return storage.Claims{}, err
	}
	return c, nil
}
