package axa_test

import (
	"testing"

	"github.com/ArmornetIO/axa"
)

func TestConnectorType(t *testing.T) {
	cases := []struct {
		cfg  axa.ConnectorConfig
		want string
	}{
		{axa.OIDCConnectorConfig{}, "oidc"},
		{axa.SAMLConnectorConfig{}, "saml"},
		{axa.LDAPConnectorConfig{}, "ldap"},
		{axa.MicrosoftConnectorConfig{}, "microsoft"},
		{axa.GitHubConnectorConfig{}, "github"},
		{axa.OpaqueConnectorConfig{Type: "custom"}, "custom"},
	}
	for _, tc := range cases {
		got := axa.ConnectorType(tc.cfg)
		if got != tc.want {
			t.Errorf("ConnectorType(%T) = %q, want %q", tc.cfg, got, tc.want)
		}
	}
}

func TestSecretRefZeroValue(t *testing.T) {
	var ref axa.SecretRef
	if ref.Namespace != "" || ref.Name != "" || ref.Key != "" {
		t.Error("zero SecretRef should have empty fields")
	}
}
