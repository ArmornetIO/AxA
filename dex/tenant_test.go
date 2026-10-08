package dex

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ArmornetIO/identity"
	"github.com/ArmornetIO/identity/internal/dex/connector/saml"
)

func testCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "idp"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func samlTenantConfig(t *testing.T, extra map[string]any) json.RawMessage {
	t.Helper()
	cfg := map[string]any{
		"ssoURL":       "https://idp.example.com/sso",
		"caData":       base64.StdEncoding.EncodeToString([]byte(testCertPEM(t))),
		"usernameAttr": "name",
		"emailAttr":    "email",
		"groupsAttr":   "groups",
	}
	for k, v := range extra {
		cfg[k] = v
	}
	raw, _ := json.Marshal(cfg)
	return raw
}

func TestPrepareTenantConnector_Refuses(t *testing.T) {
	cases := map[string]struct {
		typ string
		raw json.RawMessage
	}{
		"mock connector":          {"mockCallback", json.RawMessage(`{}`)},
		"authproxy":               {"authproxy", json.RawMessage(`{}`)},
		"ldap":                    {"ldap", json.RawMessage(`{"host":"dc.corp:636"}`)},
		"unknown field":           {"saml", samlTenantConfig(t, map[string]any{"caURL": "https://x"})},
		"server file path":        {"saml", samlTenantConfig(t, map[string]any{"ca": "/etc/passwd"})},
		"signature validation":    {"saml", samlTenantConfig(t, map[string]any{"insecureSkipSignatureValidation": true})},
		"saml no username attr":   {"saml", samlTenantConfig(t, map[string]any{"usernameAttr": ""})},
		"saml unknown field":      {"saml", samlTenantConfig(t, map[string]any{"usernameAttrz": []string{"upn"}})},
		"saml PEM not base64":     {"saml", samlTenantConfig(t, map[string]any{"caData": testCertPEM(t)})},
		"oidc missing secret":     {"oidc", json.RawMessage(`{"issuer":"https://idp.example.com","clientID":"c"}`)},
		"oidc rootCAs":            {"oidc", json.RawMessage(`{"issuer":"https://i","clientID":"c","clientSecret":"s","rootCAs":["/etc/ssl/key.pem"]}`)},
		"oidc skip verify":        {"oidc", json.RawMessage(`{"issuer":"https://i","clientID":"c","clientSecret":"s","insecureSkipVerify":true}`)},
		"oidc plain http":         {"oidc", json.RawMessage(`{"issuer":"http://idp.example.com","clientID":"c","clientSecret":"s"}`)},
		"oidc query swallows":     {"oidc", json.RawMessage(`{"issuer":"https://idp.example.com/x?","clientID":"c","clientSecret":"s"}`)},
		"oidc no host":            {"oidc", json.RawMessage(`{"issuer":"https:///path","clientID":"c","clientSecret":"s"}`)},
		"saml plain http":         {"saml", samlTenantConfig(t, map[string]any{"ssoURL": "http://idp.example.com/sso"})},
		"not an object":           {"oidc", json.RawMessage(`[]`)},
		"microsoft no tenant":     {"microsoft", json.RawMessage(`{"clientID":"c","clientSecret":"s"}`)},
		"microsoft common":        {"microsoft", json.RawMessage(`{"clientID":"c","clientSecret":"s","tenant":"common"}`)},
		"microsoft organizations": {"microsoft", json.RawMessage(`{"clientID":"c","clientSecret":"s","tenant":"organizations"}`)},
		"microsoft consumers id":  {"microsoft", json.RawMessage(`{"clientID":"c","clientSecret":"s","tenant":"9188040d-6c67-4c5b-b112-36a304b66dad"}`)},
		"microsoft path escape":   {"microsoft", json.RawMessage(`{"clientID":"c","clientSecret":"s","tenant":"acme.com/../common"}`)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := PrepareTenantConnector(tc.typ, tc.raw, "https://auth.example.com/dex")
			if !errors.Is(err, ErrInvalidTenantConnector) {
				t.Fatalf("want ErrInvalidTenantConnector, got %v", err)
			}
		})
	}
}

func TestPrepareTenantConnector_SAMLOpensWithDerivedRedirect(t *testing.T) {
	raw := samlTenantConfig(t, map[string]any{"redirectURI": "https://attacker.example/acs"})
	out, err := PrepareTenantConnector("saml", raw, "https://auth.example.com/dex/")
	if err != nil {
		t.Fatalf("PrepareTenantConnector: %v", err)
	}
	var cfg saml.Config
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.RedirectURI != "https://auth.example.com/dex/callback" {
		t.Errorf("redirectURI = %q, want the issuer's callback", cfg.RedirectURI)
	}
	if _, err := cfg.Open("acme", slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Errorf("stored config does not open: %v", err)
	}
}

// The exact shapes a host's connector wizard sends. One
// once sent issuerURL and caCert, which strict decoding refused, so neither OIDC
// nor SAML could be created; a key renamed on either side fails here.
func TestPrepareTenantConnector_WizardPayloads(t *testing.T) {
	samlRaw, _ := json.Marshal(map[string]any{
		"ssoURL":              "https://idp.example.com/sso",
		"caData":              base64.StdEncoding.EncodeToString([]byte(testCertPEM(t))),
		"usernameAttrs":       []string{"name", "upn"},
		"emailAttrs":          []string{"email", "mail"},
		"userIDAttr":          "",
		"stripUsernameDomain": true,
		"groupsAttr":          "",
		"allowedDomains":      []string{"acme.com"},
		"entityIssuer":        "urn:armornet:org-1",
	})
	for typ, raw := range map[string]json.RawMessage{
		"oidc":      json.RawMessage(`{"issuer":"https://idp.example.com","clientID":"c","clientSecret":"s","scopes":["openid","email","profile"]}`),
		"microsoft": json.RawMessage(`{"clientID":"c","clientSecret":"s","tenant":"contoso.onmicrosoft.com","groups":[]}`),
		"saml":      samlRaw,
	} {
		if _, err := PrepareTenantConnector(typ, raw, "https://id.example.com"); err != nil {
			t.Errorf("%s wizard payload refused: %v", typ, err)
		}
	}
}

func TestPrepareTenantConnector_MicrosoftSingleTenant(t *testing.T) {
	for _, tenant := range []string{"72f988bf-86f1-41af-91ab-2d7cd011db47", "contoso.onmicrosoft.com", "Contoso.com"} {
		raw := json.RawMessage(`{"clientID":"c","clientSecret":"s","tenant":"` + tenant + `"}`)
		if _, err := PrepareTenantConnector("microsoft", raw, "https://id.example.com"); err != nil {
			t.Errorf("tenant %q refused: %v", tenant, err)
		}
	}
}

func TestPrepareTenantConnector_OIDC(t *testing.T) {
	raw := json.RawMessage(`{"issuer":"https://idp.example.com","clientID":"c","clientSecret":"s"}`)
	out, err := PrepareTenantConnector("oidc", raw, "https://auth.example.com/dex")
	if err != nil {
		t.Fatalf("PrepareTenantConnector: %v", err)
	}
	if !strings.Contains(string(out), `"redirectURI":"https://auth.example.com/dex/callback"`) {
		t.Errorf("redirectURI not derived: %s", out)
	}
}

// The typed path must produce a config Dex actually opens; before the fix it
// never could (missing required fields, PEM where Dex decodes base64).
func TestMarshalConnectorConfig_SAMLOpens(t *testing.T) {
	cfg := identity.SAMLConnectorConfig{
		SSOURL:       "https://idp.example.com/sso",
		CARef:        identity.SecretRef{Namespace: "ns", Name: "idp", Key: "ca.pem"},
		UsernameAttr: "name",
		EmailAttr:    "email",
		RedirectURI:  "https://auth.example.com/dex/callback",
	}
	out, err := marshalConnectorConfig(context.Background(), cfg, &staticResolver{value: testCertPEM(t)})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var dc saml.Config
	if err := json.Unmarshal(out, &dc); err != nil {
		t.Fatalf("Dex cannot decode stored config: %v", err)
	}
	if _, err := dc.Open("acme", slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Errorf("Dex refuses to open typed SAML config: %v", err)
	}
}
