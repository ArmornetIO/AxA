package identity

import (
	"context"
	"encoding/json"
	"errors"
)

// ConnectorStore is CRUD for upstream IdP connectors. Unknown IDs return
// ErrConnectorNotFound; a duplicate Create returns ErrConnectorExists.
type ConnectorStore interface {
	Create(ctx context.Context, c Connector) error
	List(ctx context.Context) ([]Connector, error)
	Get(ctx context.Context, id string) (Connector, error)
	Update(ctx context.Context, c Connector) error
	Delete(ctx context.Context, id string) error
}

type Connector struct {
	// ID is the seeding idempotency key and the login URL segment.
	ID   string
	Name string
	// Config's concrete type is the connector kind.
	Config ConnectorConfig
}

// ConnectorConfig is sealed: the unexported method keeps the set of kinds here.
type ConnectorConfig interface {
	connectorType() string
}

// ConnectorType is the kind label for logs and validation; type-switch for the value.
func ConnectorType(c ConnectorConfig) string {
	return c.connectorType()
}

// SecretRef names a key in a Kubernetes Secret. Configs take no raw credentials,
// so none reach Dex storage or an API response.
type SecretRef struct {
	Namespace string
	Name      string
	Key       string
}

// OIDCConnectorConfig is any upstream OIDC provider (Auth0, Okta, Google…).
type OIDCConnectorConfig struct {
	// IssuerURL keeps its trailing slash ("https://example.us.auth0.com/").
	IssuerURL    string
	ClientID     string
	ClientSecret SecretRef
	// Scopes are requested on top of "openid".
	Scopes []string
	// RedirectURI must be issuerURL + "/callback"; Dex refuses the callback otherwise.
	RedirectURI string
	// InsecureSkipVerify: never in production.
	InsecureSkipVerify bool
}

func (OIDCConnectorConfig) connectorType() string { return "oidc" }

// SAMLConnectorConfig makes Armornet the SP. Dex never signs AuthnRequests, so
// there is no SP key.
type SAMLConnectorConfig struct {
	SSOURL string
	// CARef holds the PEM cert(s) the IdP signs responses with.
	CARef SecretRef
	// EntityIssuer is the SP entity ID sent in AuthnRequests.
	EntityIssuer string
	// SSOIssuer, when set, must equal every response's Issuer.
	SSOIssuer string
	// Dex will not open the connector without UsernameAttr and EmailAttr.
	UsernameAttr string
	EmailAttr    string
	GroupsAttr   string
	// GroupsDelim splits a single-valued groups attribute.
	GroupsDelim string
	// NameIDPolicyFormat becomes the Dex subject; defaults to persistent.
	NameIDPolicyFormat string
	// RedirectURI is the ACS URL: issuerURL + "/callback".
	RedirectURI string
}

func (SAMLConnectorConfig) connectorType() string { return "saml" }

type LDAPUserSearch struct {
	BaseDN string
	Filter string
	// Username is the attribute the login name matches (e.g. "uid").
	Username string
	// IDAttr, EmailAttr and NameAttr map LDAP attributes to token claims.
	IDAttr    string
	EmailAttr string
	NameAttr  string
}

type LDAPGroupSearch struct {
	BaseDN       string
	Filter       string
	UserMatchers []LDAPUserMatcher
	NameAttr     string
}

// LDAPUserMatcher joins a group entry attribute to a user entry attribute.
type LDAPUserMatcher struct {
	UserAttr  string
	GroupAttr string
}

// LDAPConnectorConfig is LDAP or Active Directory.
type LDAPConnectorConfig struct {
	// Host is "host:port".
	Host       string
	BindDN     string
	BindSecret SecretRef
	// StartTLS is ignored on 636 (LDAPS).
	StartTLS bool
	// InsecureSkipVerify: never in production.
	InsecureSkipVerify bool
	UserSearch         LDAPUserSearch
	GroupSearch        LDAPGroupSearch
}

func (LDAPConnectorConfig) connectorType() string { return "ldap" }

// MicrosoftConnectorConfig is Azure AD / Entra.
type MicrosoftConnectorConfig struct {
	ClientID     string
	ClientSecret SecretRef
	// Tenant is required and must be single-tenant; "common", "organizations"
	// and "consumers" are refused (see identity/dex marshalMicrosoft).
	Tenant string
	// OnlySecurityGroups keeps tokens small for users in many groups.
	OnlySecurityGroups bool
	// Groups, when set, is an allowlist of group object IDs.
	Groups []string
}

func (MicrosoftConnectorConfig) connectorType() string { return "microsoft" }

type GitHubConnectorConfig struct {
	ClientID     string
	ClientSecret SecretRef
	// RedirectURI must be issuerURL + "/callback".
	RedirectURI string
	// Orgs, when set, restricts login to their members.
	Orgs []GitHubOrg
	// HostName points the connector at a GitHub Enterprise host instead of
	// github.com; Dex always dials it over https.
	HostName string
	// RootCA is a PEM, or a path to one, trusted for HostName only.
	RootCA string
}

// GitHubOrg optionally narrows the org to Teams.
type GitHubOrg struct {
	Name  string
	Teams []string
}

func (GitHubConnectorConfig) connectorType() string { return "github" }

type GoogleConnectorConfig struct {
	ClientID     string
	ClientSecret SecretRef
	// RedirectURI is issuerURL + "/callback", registered in the Google OAuth client.
	RedirectURI string
	// HostedDomains, when set, restricts login to those Workspace domains.
	HostedDomains []string
}

func (GoogleConnectorConfig) connectorType() string { return "google" }

// OpaqueConnectorConfig is what Get and List return: the kind and the stored
// config. Credentials appear only as Secret refs; they are never round-tripped.
type OpaqueConnectorConfig struct {
	Type      string
	RawConfig json.RawMessage
}

func (o OpaqueConnectorConfig) connectorType() string { return o.Type }

var (
	ErrConnectorNotFound = errors.New("identity: connector not found")
	ErrConnectorExists   = errors.New("identity: connector already exists")
)
