package dex

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"slices"
	"strings"

	"github.com/ArmornetIO/identity/internal/dex/connector/microsoft"
	"github.com/ArmornetIO/identity/internal/dex/connector/oidc"
	"github.com/ArmornetIO/identity/internal/dex/connector/saml"
)

// TenantConnectorTypes excludes mocks (a fixed fake user), authproxy (trusts a
// header) and ldap (dials into the tenant's network).
var TenantConnectorTypes = []string{"oidc", "saml", "microsoft"}

// ErrInvalidTenantConnector wraps every refusal, so a handler can answer 400
// without string matching.
var ErrInvalidTenantConnector = errors.New("invalid connector")

// tenantDeniedKeys are server-disk paths; insecure* switches are refused too, as
// they void the upstream's verification.
var tenantDeniedKeys = []string{"ca", "rootCAs"}

// PrepareTenantConnector decodes strictly (a typo is refused) and always sets
// redirectURI itself: a tenant never picks where the upstream responds.
func PrepareTenantConnector(typ string, raw json.RawMessage, issuerURL string) (json.RawMessage, error) {
	if !slices.Contains(TenantConnectorTypes, typ) {
		return nil, fmt.Errorf("%w: type %q is not one of %v", ErrInvalidTenantConnector, typ, TenantConnectorTypes)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil, fmt.Errorf("%w: config must be a JSON object: %v", ErrInvalidTenantConnector, err)
	}
	for k := range keys {
		if slices.Contains(tenantDeniedKeys, k) || strings.HasPrefix(k, "insecure") {
			return nil, fmt.Errorf("%w: field %q may not be set", ErrInvalidTenantConnector, k)
		}
	}

	redirectURI := strings.TrimRight(issuerURL, "/") + "/callback"
	var cfg any
	var check func() error
	switch typ {
	case "oidc":
		c := &oidc.Config{}
		cfg, check = c, func() error {
			c.RedirectURI = redirectURI
			if err := required(map[string]string{"issuer": c.Issuer, "clientID": c.ClientID, "clientSecret": c.ClientSecret}); err != nil {
				return err
			}
			return requireHTTPS("issuer", c.Issuer)
		}
	case "microsoft":
		c := &microsoft.Config{}
		cfg, check = c, func() error {
			c.RedirectURI = redirectURI
			if err := required(map[string]string{"clientID": c.ClientID, "clientSecret": c.ClientSecret}); err != nil {
				return err
			}
			return checkMicrosoftTenant(c.Tenant)
		}
	case "saml":
		c := &saml.Config{}
		cfg, check = c, func() error {
			c.RedirectURI = redirectURI
			// Open makes no network call; it enforces Dex's required fields and
			// parses the CA, which is exactly what a save should catch.
			if _, err := c.Open("validate", slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
				return err
			}
			return requireHTTPS("ssoURL", c.SSOURL)
		}
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidTenantConnector, err)
	}
	if err := check(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidTenantConnector, err)
	}
	return json.Marshal(cfg)
}

// requireHTTPS refuses plaintext and a query or fragment, which would swallow
// the path Dex appends for discovery. It cannot refuse internal hosts: DNS can
// change after the save, so that check belongs to Config.DialControl.
func requireHTTPS(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fmt.Errorf("%s must be an https URL with no query or fragment", field)
	}
	return nil
}

func required(fields map[string]string) error {
	var missing []string
	for name, v := range fields {
		if v == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return fmt.Errorf("missing required fields %q", missing)
	}
	return nil
}
