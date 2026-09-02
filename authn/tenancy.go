package authn

import (
	"context"
	"errors"
)

// ErrNoMembership is returned when a subject holds no role in the named org.
// Distinct from a lookup failure so a caller can deny rather than 500.
var ErrNoMembership = errors.New("authn: no membership")

// ErrNoOrg is returned when no organization matches.
var ErrNoOrg = errors.New("authn: no such organization")

// Who a person is, and which tenants they belong to.
//
// This is the half of tenancy that is identity's: the mapping from an IDP
// subject to a stable internal id, and the memberships that decide what scope a
// credential may claim. What a host then hangs off an org — entitlements,
// quotas, invoices — is the host's, and stays there.
//
// A role is an opaque string here. Identity records and returns it; the
// vocabulary ("owner", "admin", …) and what each permits are the host's policy,
// enforced above this layer.

// UserRecord is the identity claims needed to provision or update a user.
type UserRecord struct {
	// Subject is the IDP's subject claim — the only stable identifier across
	// logins. Never an email: those change hands.
	Subject string
	Email   string
}

// OrgMembership is one (org, role) pair a user holds.
type OrgMembership struct {
	OrgID string
	Role  string
}

// OrgScope is everything a request needs to know about a caller's tenancy,
// resolved in one lookup.
//
// Provisioned distinguishes "no such user" from "user with no memberships", and
// callers must keep them distinct: the first is an unknown principal, the second
// is a known person who simply belongs to nothing yet. Collapsing them turns a
// legitimate empty scope into an unauthenticated one, or worse, the reverse.
type OrgScope struct {
	// UserID is the internal id. Empty when Provisioned is false.
	UserID string
	// Provisioned reports whether a user row exists for the subject.
	Provisioned bool
	// Memberships is empty — not nil-meaningful — when the user belongs to no
	// orgs. A caller filtering by these must treat empty as "matches nothing",
	// never as "matches everything".
	Memberships []OrgMembership
}

// UserStore persists user identity and org membership.
//
// The host implements this over its own database, or uses pgstore's
// implementation over identity's own tables.
type UserStore interface {
	// UpsertUser provisions or refreshes a user from IDP claims, returning the
	// internal id.
	UpsertUser(ctx context.Context, u UserRecord) (id string, err error)
	// ResolveOrgScope maps an IDP subject to its internal id and memberships in
	// one round-trip. It is THE authority a session's claimed org is checked
	// against, so it must never report a membership that is not recorded.
	ResolveOrgScope(ctx context.Context, subject string) (OrgScope, error)
	// LinkOrgUser records a membership with a role.
	LinkOrgUser(ctx context.Context, orgID, userID, role string) error
	// GetOrgRole returns the subject's role in one org, or ErrNoMembership.
	GetOrgRole(ctx context.Context, subject, orgID string) (string, error)
}

// Organization is a tenant's identity — nothing a host hangs off it.
type Organization struct {
	ID   string
	Name string
	Slug string
}

// ConnectorInfo summarises an upstream IdP an org may sign in through.
type ConnectorInfo struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
	// Disabled marks a global the org has turned off. Only ListConnectors
	// returns one; every sign-in path leaves it out.
	Disabled bool `json:"disabled,omitempty"`
}

// ErrSlugTaken is returned when a requested slug already belongs to another
// org. Distinct from a write failure because it is a user-correctable conflict.
var ErrSlugTaken = errors.New("authn: slug already taken")

// OrgStore persists organizations and the connectors they may authenticate
// through.
//
// Connectors live here rather than with the host because they ARE identity: a
// connector row is a Dex connector, and which upstream IdPs a tenant may use is
// an authentication decision, not a product one.
type OrgStore interface {
	CreateOrg(ctx context.Context, org Organization) error
	GetOrg(ctx context.Context, id string) (Organization, error)
	OrgExists(ctx context.Context, id string) (bool, error)
	// UpdateOrg renames an org, returning ErrSlugTaken if the slug is in use.
	UpdateOrg(ctx context.Context, org Organization) error

	// ResolveSlug maps a public slug to the org and the connectors it may use,
	// returning ErrNoOrg when nothing matches. This is what a login page calls
	// before any credential exists, so it must reveal nothing beyond the
	// connectors an anonymous visitor is about to be offered.
	ResolveSlug(ctx context.Context, slug string) (orgID string, connectors []ConnectorInfo, err error)

	// ListConnectors includes the globals the org turned off, marked Disabled,
	// so an admin can turn them back on; ListConnectorIDs is what sign-in may use.
	ListConnectors(ctx context.Context, orgID string) ([]ConnectorInfo, error)
	ListConnectorIDs(ctx context.Context, orgID string) ([]string, error)
	// SetConnectorDisabled takes a global connector off one org's sign-in, or
	// puts it back. Members who signed in through it are locked out meanwhile.
	SetConnectorDisabled(ctx context.Context, orgID, connectorID string, disabled bool) error
	CreateOrgConnector(ctx context.Context, orgID, id, connType, name string) error
	DeleteOrgConnector(ctx context.Context, orgID, connectorID string) error
	// IsGlobalConnector reports whether a connector is available to every org
	// rather than registered to one.
	IsGlobalConnector(ctx context.Context, connectorID string) (bool, error)
}
