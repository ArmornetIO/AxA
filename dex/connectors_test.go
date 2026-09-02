package dex

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ArmornetIO/identity"
)

// staticResolver resolves any SecretRef to its fixed value.
type staticResolver struct{ value string }

func (r *staticResolver) Resolve(_ context.Context, _ identity.SecretRef) (string, error) {
	return r.value, nil
}

func TestMarshalConnectorConfig_OIDC(t *testing.T) {
	cfg := identity.OIDCConnectorConfig{
		IssuerURL:    "https://example.us.auth0.com/",
		ClientID:     "my-client-id",
		ClientSecret: identity.SecretRef{Namespace: "ns", Name: "secret", Key: "key"},
		Scopes:       []string{"openid", "email"},
	}
	b, err := marshalConnectorConfig(context.Background(), cfg, &staticResolver{"supersecret"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if got := out["issuer"]; got != "https://example.us.auth0.com/" {
		t.Errorf("issuer = %v, want https://example.us.auth0.com/", got)
	}
	if got := out["clientID"]; got != "my-client-id" {
		t.Errorf("clientID = %v, want my-client-id", got)
	}
	if got := out["clientSecret"]; got != "supersecret" {
		t.Errorf("clientSecret = %v, want supersecret", got)
	}
	scopes, _ := out["scopes"].([]any)
	if len(scopes) != 2 {
		t.Errorf("scopes len = %d, want 2", len(scopes))
	}
}

func TestMarshalConnectorConfig_LDAP(t *testing.T) {
	cfg := identity.LDAPConnectorConfig{
		Host:       "ldap.example.com:636",
		BindDN:     "cn=readonly,dc=example,dc=com",
		BindSecret: identity.SecretRef{Namespace: "ns", Name: "ldap-secret", Key: "bindPW"},
		UserSearch: identity.LDAPUserSearch{
			BaseDN:    "ou=users,dc=example,dc=com",
			Username:  "uid",
			IDAttr:    "uid",
			EmailAttr: "mail",
		},
	}
	b, err := marshalConnectorConfig(context.Background(), cfg, &staticResolver{"bindpassword"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if got := out["host"]; got != "ldap.example.com:636" {
		t.Errorf("host = %v, want ldap.example.com:636", got)
	}
	if got := out["bindPW"]; got != "bindpassword" {
		t.Errorf("bindPW = %v, want bindpassword", got)
	}
}

func TestMarshalConnectorConfig_Microsoft(t *testing.T) {
	cfg := identity.MicrosoftConnectorConfig{
		ClientID:     "azure-client-id",
		ClientSecret: identity.SecretRef{Namespace: "ns", Name: "az", Key: "secret"},
		Tenant:       "mytenant.onmicrosoft.com",
	}
	b, err := marshalConnectorConfig(context.Background(), cfg, &staticResolver{"azsecret"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if got := out["tenant"]; got != "mytenant.onmicrosoft.com" {
		t.Errorf("tenant = %v", got)
	}
	if got := out["clientSecret"]; got != "azsecret" {
		t.Errorf("clientSecret = %v, want azsecret", got)
	}
}

func TestMarshalConnectorConfig_MicrosoftRefusesMultiTenant(t *testing.T) {
	for _, tenant := range []string{
		"", "common", "Organizations", "consumers", " common",
		"9188040d-6c67-4c5b-b112-36a304b66dad", // consumers, by id
		"acme.com/../common", "acme.com?x=", "acme",
	} {
		cfg := identity.MicrosoftConnectorConfig{ClientID: "id", Tenant: tenant}
		if _, err := marshalConnectorConfig(context.Background(), cfg, &staticResolver{"s"}); err == nil {
			t.Errorf("tenant %q accepted", tenant)
		}
	}
}

func TestMarshalConnectorConfig_GitHub(t *testing.T) {
	cfg := identity.GitHubConnectorConfig{
		ClientID:     "gh-client",
		ClientSecret: identity.SecretRef{Namespace: "ns", Name: "gh", Key: "secret"},
		Orgs: []identity.GitHubOrg{
			{Name: "myorg", Teams: []string{"eng"}},
		},
	}
	b, err := marshalConnectorConfig(context.Background(), cfg, &staticResolver{"ghsecret"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	orgs, _ := out["orgs"].([]any)
	if len(orgs) != 1 {
		t.Errorf("orgs len = %d, want 1", len(orgs))
	}
}

func TestMarshalConnectorConfig_Opaque_PassThrough(t *testing.T) {
	raw := json.RawMessage(`{"issuer":"https://example.com/","clientID":"foo"}`)
	cfg := identity.OpaqueConnectorConfig{Type: "oidc", RawConfig: raw}

	b, err := marshalConnectorConfig(context.Background(), cfg, &staticResolver{""})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(b) != string(raw) {
		t.Errorf("opaque config not passed through: got %s", b)
	}
}

func TestMarshalConnectorConfig_UnsupportedType(t *testing.T) {
	type unknown struct{}
	// unknown does not implement ConnectorConfig; we test via OpaqueConnectorConfig
	// with a nil RawConfig to confirm it passes nil through safely.
	cfg := identity.OpaqueConnectorConfig{Type: "future", RawConfig: nil}
	b, err := marshalConnectorConfig(context.Background(), cfg, &staticResolver{""})
	if err != nil {
		t.Fatalf("unexpected error for opaque nil: %v", err)
	}
	if b != nil {
		t.Errorf("expected nil bytes for nil RawConfig, got %s", b)
	}
}
