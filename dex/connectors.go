package dex

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ArmornetIO/identity"
	"github.com/ArmornetIO/identity/internal/dex/connector/saml"
	dexstorage "github.com/ArmornetIO/identity/internal/dex/storage"
)

// connectorStore implements identity.ConnectorStore via Dex's K8s CRD storage.
type connectorStore struct {
	storage dexstorage.Storage
	secrets SecretResolver
}

func (s *connectorStore) Create(ctx context.Context, c identity.Connector) error {
	dc, err := s.toDex(ctx, c)
	if err != nil {
		return err
	}
	if err := s.storage.CreateConnector(ctx, dc); err != nil {
		if errors.Is(err, dexstorage.ErrAlreadyExists) {
			return identity.ErrConnectorExists
		}
		return fmt.Errorf("identity/dex: create connector: %w", err)
	}
	return nil
}

func (s *connectorStore) List(ctx context.Context) ([]identity.Connector, error) {
	dcs, err := s.storage.ListConnectors(ctx)
	if err != nil {
		return nil, fmt.Errorf("identity/dex: list connectors: %w", err)
	}
	out := make([]identity.Connector, len(dcs))
	for i, dc := range dcs {
		out[i] = fromDex(dc)
	}
	return out, nil
}

func (s *connectorStore) Get(ctx context.Context, id string) (identity.Connector, error) {
	dc, err := s.storage.GetConnector(ctx, id)
	if err != nil {
		if errors.Is(err, dexstorage.ErrNotFound) {
			return identity.Connector{}, identity.ErrConnectorNotFound
		}
		return identity.Connector{}, fmt.Errorf("identity/dex: get connector %q: %w", id, err)
	}
	return fromDex(dc), nil
}

func (s *connectorStore) Update(ctx context.Context, c identity.Connector) error {
	dc, err := s.toDex(ctx, c)
	if err != nil {
		return err
	}
	updater := func(old dexstorage.Connector) (dexstorage.Connector, error) {
		old.Name = dc.Name
		old.Type = dc.Type
		old.Config = dc.Config
		return old, nil
	}
	if err := s.storage.UpdateConnector(ctx, c.ID, updater); err != nil {
		if errors.Is(err, dexstorage.ErrNotFound) {
			return identity.ErrConnectorNotFound
		}
		return fmt.Errorf("identity/dex: update connector %q: %w", c.ID, err)
	}
	return nil
}

func (s *connectorStore) Delete(ctx context.Context, id string) error {
	if err := s.storage.DeleteConnector(ctx, id); err != nil {
		if errors.Is(err, dexstorage.ErrNotFound) {
			return identity.ErrConnectorNotFound
		}
		return fmt.Errorf("identity/dex: delete connector %q: %w", id, err)
	}
	return nil
}

// toDex is the only place resolved credentials touch memory; they go straight
// into the storage call.
func (s *connectorStore) toDex(ctx context.Context, c identity.Connector) (dexstorage.Connector, error) {
	cfgBytes, err := marshalConnectorConfig(ctx, c.Config, s.secrets)
	if err != nil {
		return dexstorage.Connector{}, fmt.Errorf("connector %q: %w", c.ID, err)
	}
	return dexstorage.Connector{
		ID:     c.ID,
		Name:   c.Name,
		Type:   identity.ConnectorType(c.Config),
		Config: cfgBytes,
	}, nil
}

// BuildDexConnector builds a static, never-persisted connector for
// Config.Connectors.
func BuildDexConnector(ctx context.Context, c identity.Connector, secrets SecretResolver) (dexstorage.Connector, error) {
	cfgBytes, err := marshalConnectorConfig(ctx, c.Config, secrets)
	if err != nil {
		return dexstorage.Connector{}, fmt.Errorf("connector %q: %w", c.ID, err)
	}
	return dexstorage.Connector{
		ID:     c.ID,
		Name:   c.Name,
		Type:   identity.ConnectorType(c.Config),
		Config: cfgBytes,
	}, nil
}

// fromDex converts a Dex storage connector to an identity.Connector.
// The Config is always OpaqueConnectorConfig — credentials are not round-tripped.
func fromDex(dc dexstorage.Connector) identity.Connector {
	return identity.Connector{
		ID:   dc.ID,
		Name: dc.Name,
		Config: identity.OpaqueConnectorConfig{
			Type:      dc.Type,
			RawConfig: json.RawMessage(dc.Config),
		},
	}
}

// marshalConnectorConfig resolves SecretRefs and marshals a ConnectorConfig to
// the JSON shape that Dex's connector implementations expect on unmarshal.
func marshalConnectorConfig(ctx context.Context, cfg identity.ConnectorConfig, secrets SecretResolver) ([]byte, error) {
	switch c := cfg.(type) {
	case identity.OIDCConnectorConfig:
		return marshalOIDC(ctx, c, secrets)
	case identity.SAMLConnectorConfig:
		return marshalSAML(ctx, c, secrets)
	case identity.LDAPConnectorConfig:
		return marshalLDAP(ctx, c, secrets)
	case identity.MicrosoftConnectorConfig:
		return marshalMicrosoft(ctx, c, secrets)
	case identity.GitHubConnectorConfig:
		return marshalGitHub(ctx, c, secrets)
	case identity.GoogleConnectorConfig:
		return marshalGoogle(ctx, c, secrets)
	case identity.OpaqueConnectorConfig:
		// Pass raw bytes through unchanged (e.g. when re-storing after a read).
		return c.RawConfig, nil
	default:
		return nil, fmt.Errorf("unsupported connector config type %T", cfg)
	}
}

// dexOIDCConfig mirrors the JSON shape Dex's oidc connector expects.
type dexOIDCConfig struct {
	Issuer             string   `json:"issuer"`
	ClientID           string   `json:"clientID"`
	ClientSecret       string   `json:"clientSecret"`
	Scopes             []string `json:"scopes,omitempty"`
	RedirectURI        string   `json:"redirectURI,omitempty"`
	InsecureSkipVerify bool     `json:"insecureSkipVerify,omitempty"`
}

func marshalOIDC(ctx context.Context, c identity.OIDCConnectorConfig, s SecretResolver) ([]byte, error) {
	secret, err := s.Resolve(ctx, c.ClientSecret)
	if err != nil {
		return nil, fmt.Errorf("oidc clientSecret: %w", err)
	}
	// #nosec G117 -- Dex's own connector schema: the secret must ride the connector config
	return json.Marshal(dexOIDCConfig{
		Issuer:             c.IssuerURL,
		ClientID:           c.ClientID,
		ClientSecret:       secret,
		Scopes:             c.Scopes,
		RedirectURI:        c.RedirectURI,
		InsecureSkipVerify: c.InsecureSkipVerify,
	})
}

// marshalSAML uses Dex's own saml.Config: a mirror once sent PEM where Dex wants
// base64, and no SAML connector could open.
func marshalSAML(ctx context.Context, c identity.SAMLConnectorConfig, s SecretResolver) ([]byte, error) {
	ca, err := s.Resolve(ctx, c.CARef)
	if err != nil {
		return nil, fmt.Errorf("saml CA cert: %w", err)
	}
	return json.Marshal(saml.Config{
		SSOURL:             c.SSOURL,
		CAData:             []byte(ca),
		EntityIssuer:       c.EntityIssuer,
		SSOIssuer:          c.SSOIssuer,
		UsernameAttr:       c.UsernameAttr,
		EmailAttr:          c.EmailAttr,
		GroupsAttr:         c.GroupsAttr,
		GroupsDelim:        c.GroupsDelim,
		NameIDPolicyFormat: c.NameIDPolicyFormat,
		RedirectURI:        c.RedirectURI,
	})
}

// dexLDAPConfig mirrors the JSON shape Dex's ldap connector expects.
type dexLDAPConfig struct {
	Host               string             `json:"host"`
	InsecureSkipVerify bool               `json:"insecureSkipVerify,omitempty"`
	StartTLS           bool               `json:"startTLS,omitempty"`
	BindDN             string             `json:"bindDN"`
	BindPW             string             `json:"bindPW"`
	UserSearch         dexLDAPUserSearch  `json:"userSearch"`
	GroupSearch        dexLDAPGroupSearch `json:"groupSearch,omitempty"`
}

type dexLDAPUserSearch struct {
	BaseDN    string `json:"baseDN"`
	Filter    string `json:"filter,omitempty"`
	Username  string `json:"username"`
	IDAttr    string `json:"idAttr"`
	EmailAttr string `json:"emailAttr"`
	NameAttr  string `json:"nameAttr,omitempty"`
}

type dexLDAPGroupSearch struct {
	BaseDN       string           `json:"baseDN,omitempty"`
	Filter       string           `json:"filter,omitempty"`
	UserMatchers []dexUserMatcher `json:"userMatchers,omitempty"`
	NameAttr     string           `json:"nameAttr,omitempty"`
}

type dexUserMatcher struct {
	UserAttr  string `json:"userAttr"`
	GroupAttr string `json:"groupAttr"`
}

func marshalLDAP(ctx context.Context, c identity.LDAPConnectorConfig, s SecretResolver) ([]byte, error) {
	bindPW, err := s.Resolve(ctx, c.BindSecret)
	if err != nil {
		return nil, fmt.Errorf("ldap bindPW: %w", err)
	}

	matchers := make([]dexUserMatcher, len(c.GroupSearch.UserMatchers))
	for i, m := range c.GroupSearch.UserMatchers {
		matchers[i] = dexUserMatcher{UserAttr: m.UserAttr, GroupAttr: m.GroupAttr}
	}

	return json.Marshal(dexLDAPConfig{
		Host:               c.Host,
		InsecureSkipVerify: c.InsecureSkipVerify,
		StartTLS:           c.StartTLS,
		BindDN:             c.BindDN,
		BindPW:             bindPW,
		UserSearch: dexLDAPUserSearch{
			BaseDN:    c.UserSearch.BaseDN,
			Filter:    c.UserSearch.Filter,
			Username:  c.UserSearch.Username,
			IDAttr:    c.UserSearch.IDAttr,
			EmailAttr: c.UserSearch.EmailAttr,
			NameAttr:  c.UserSearch.NameAttr,
		},
		GroupSearch: dexLDAPGroupSearch{
			BaseDN:       c.GroupSearch.BaseDN,
			Filter:       c.GroupSearch.Filter,
			UserMatchers: matchers,
			NameAttr:     c.GroupSearch.NameAttr,
		},
	})
}

// dexMicrosoftConfig mirrors the JSON shape Dex's microsoft connector expects.
type dexMicrosoftConfig struct {
	ClientID           string   `json:"clientID"`
	ClientSecret       string   `json:"clientSecret"`
	Tenant             string   `json:"tenant"`
	OnlySecurityGroups bool     `json:"onlySecurityGroups,omitempty"`
	Groups             []string `json:"groups,omitempty"`
}

var (
	msTenantGUID   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	msTenantDomain = regexp.MustCompile(`^[a-z0-9-]+(\.[a-z0-9-]+)+$`)
)

// msConsumersTenant is the personal-account tenant: anyone can sign up to it.
const msConsumersTenant = "9188040d-6c67-4c5b-b112-36a304b66dad"

// checkMicrosoftTenant requires one named tenant. Dex marks every Microsoft
// email verified and defaults an empty tenant to "common", so a multi-tenant
// connector lets any tenant's users vouch for this org's domain and auto-join.
// An allowlist, not a denylist: the tenant lands in a URL path, where
// "acme.com/../common" would otherwise read as single-tenant.
func checkMicrosoftTenant(tenant string) error {
	t := strings.ToLower(tenant)
	if t == msConsumersTenant || (!msTenantGUID.MatchString(t) && !msTenantDomain.MatchString(t)) {
		return fmt.Errorf("microsoft tenant must be the org's own tenant ID or domain, not %q", tenant)
	}
	return nil
}

func marshalMicrosoft(ctx context.Context, c identity.MicrosoftConnectorConfig, s SecretResolver) ([]byte, error) {
	if err := checkMicrosoftTenant(c.Tenant); err != nil {
		return nil, err
	}
	secret, err := s.Resolve(ctx, c.ClientSecret)
	if err != nil {
		return nil, fmt.Errorf("microsoft clientSecret: %w", err)
	}
	// #nosec G117 -- Dex's own connector schema: the secret must ride the connector config
	return json.Marshal(dexMicrosoftConfig{
		ClientID:           c.ClientID,
		ClientSecret:       secret,
		Tenant:             c.Tenant,
		OnlySecurityGroups: c.OnlySecurityGroups,
		Groups:             c.Groups,
	})
}

// dexGitHubConfig mirrors the JSON shape Dex's github connector expects.
type dexGitHubConfig struct {
	ClientID     string         `json:"clientID"`
	ClientSecret string         `json:"clientSecret"`
	RedirectURI  string         `json:"redirectURI"`
	Orgs         []dexGitHubOrg `json:"orgs,omitempty"`
	HostName     string         `json:"hostName,omitempty"`
	RootCA       string         `json:"rootCA,omitempty"`
}

type dexGitHubOrg struct {
	Name  string   `json:"name"`
	Teams []string `json:"teams,omitempty"`
}

func marshalGitHub(ctx context.Context, c identity.GitHubConnectorConfig, s SecretResolver) ([]byte, error) {
	secret, err := s.Resolve(ctx, c.ClientSecret)
	if err != nil {
		return nil, fmt.Errorf("github clientSecret: %w", err)
	}
	orgs := make([]dexGitHubOrg, len(c.Orgs))
	for i, o := range c.Orgs {
		orgs[i] = dexGitHubOrg{Name: o.Name, Teams: o.Teams}
	}
	// #nosec G117 -- Dex's own connector schema: the secret must ride the connector config
	return json.Marshal(dexGitHubConfig{
		ClientID:     c.ClientID,
		ClientSecret: secret,
		RedirectURI:  c.RedirectURI,
		Orgs:         orgs,
		HostName:     c.HostName,
		RootCA:       c.RootCA,
	})
}

// dexGoogleConfig mirrors the JSON shape Dex's google connector expects.
type dexGoogleConfig struct {
	ClientID      string   `json:"clientID"`
	ClientSecret  string   `json:"clientSecret"`
	RedirectURI   string   `json:"redirectURI"`
	HostedDomains []string `json:"hostedDomains,omitempty"`
}

func marshalGoogle(ctx context.Context, c identity.GoogleConnectorConfig, s SecretResolver) ([]byte, error) {
	secret, err := s.Resolve(ctx, c.ClientSecret)
	if err != nil {
		return nil, fmt.Errorf("google clientSecret: %w", err)
	}
	// #nosec G117 -- Dex's own connector schema: the secret must ride the connector config
	return json.Marshal(dexGoogleConfig{
		ClientID:      c.ClientID,
		ClientSecret:  secret,
		RedirectURI:   c.RedirectURI,
		HostedDomains: c.HostedDomains,
	})
}

var _ identity.ConnectorStore = (*connectorStore)(nil)
