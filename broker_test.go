package identity_test

import (
	"testing"

	"github.com/ArmornetIO/identity"
)

func TestConnectorType(t *testing.T) {
	cases := []struct {
		cfg  identity.ConnectorConfig
		want string
	}{
		{identity.OIDCConnectorConfig{}, "oidc"},
		{identity.SAMLConnectorConfig{}, "saml"},
		{identity.LDAPConnectorConfig{}, "ldap"},
		{identity.MicrosoftConnectorConfig{}, "microsoft"},
		{identity.GitHubConnectorConfig{}, "github"},
		{identity.OpaqueConnectorConfig{Type: "custom"}, "custom"},
	}
	for _, tc := range cases {
		got := identity.ConnectorType(tc.cfg)
		if got != tc.want {
			t.Errorf("ConnectorType(%T) = %q, want %q", tc.cfg, got, tc.want)
		}
	}
}

func TestSecretRefZeroValue(t *testing.T) {
	var ref identity.SecretRef
	if ref.Namespace != "" || ref.Name != "" || ref.Key != "" {
		t.Error("zero SecretRef should have empty fields")
	}
}
