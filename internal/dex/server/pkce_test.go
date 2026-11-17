package server

import (
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ArmornetIO/axa/internal/dex/storage"
)

func TestRequirePKCE_RejectsMissingChallenge(t *testing.T) {
	httpSrv, server := newTestServer(t, func(c *Config) {
		c.RequirePKCE = true
		c.Storage = storage.WithStaticClients(c.Storage, []storage.Client{
			{ID: "foo", RedirectURIs: []string{"https://example.com/foo"}},
		})
	})
	defer httpSrv.Close()

	params := url.Values{
		"client_id":     {"foo"},
		"redirect_uri":  {"https://example.com/foo"},
		"response_type": {"code"},
		"scope":         {"openid email profile"},
	}
	req := httptest.NewRequest("GET", "http://localhost/auth?"+params.Encode(), nil)
	_, err := server.parseAuthorizationRequest(req)
	require.Error(t, err)
	rErr, ok := err.(*redirectedAuthErr)
	require.True(t, ok, "expected *redirectedAuthErr, got: %T", err)
	require.Equal(t, errInvalidRequest, rErr.Type)
}

func TestRequirePKCE_RejectsPlainMethod(t *testing.T) {
	httpSrv, server := newTestServer(t, func(c *Config) {
		c.RequirePKCE = true
		c.Storage = storage.WithStaticClients(c.Storage, []storage.Client{
			{ID: "foo", RedirectURIs: []string{"https://example.com/foo"}},
		})
	})
	defer httpSrv.Close()

	params := url.Values{
		"client_id":             {"foo"},
		"redirect_uri":          {"https://example.com/foo"},
		"response_type":         {"code"},
		"scope":                 {"openid email profile"},
		"code_challenge":        {"somechallenge"},
		"code_challenge_method": {"plain"},
	}
	req := httptest.NewRequest("GET", "http://localhost/auth?"+params.Encode(), nil)
	_, err := server.parseAuthorizationRequest(req)
	require.Error(t, err)
	rErr, ok := err.(*redirectedAuthErr)
	require.True(t, ok, "expected *redirectedAuthErr, got: %T", err)
	require.Equal(t, errInvalidRequest, rErr.Type)
}

func TestRequirePKCE_AllowsS256(t *testing.T) {
	httpSrv, server := newTestServer(t, func(c *Config) {
		c.RequirePKCE = true
		c.Storage = storage.WithStaticClients(c.Storage, []storage.Client{
			{ID: "foo", RedirectURIs: []string{"https://example.com/foo"}},
		})
	})
	defer httpSrv.Close()

	params := url.Values{
		"client_id":             {"foo"},
		"redirect_uri":          {"https://example.com/foo"},
		"response_type":         {"code"},
		"scope":                 {"openid email profile"},
		"code_challenge":        {"somechallengehash"},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest("GET", "http://localhost/auth?"+params.Encode(), nil)
	_, err := server.parseAuthorizationRequest(req)
	require.NoError(t, err)
}

func TestRequirePKCE_Disabled(t *testing.T) {
	httpSrv, server := newTestServer(t, func(c *Config) {
		// RequirePKCE defaults to false — backwards compat
		c.Storage = storage.WithStaticClients(c.Storage, []storage.Client{
			{ID: "foo", RedirectURIs: []string{"https://example.com/foo"}},
		})
	})
	defer httpSrv.Close()

	params := url.Values{
		"client_id":     {"foo"},
		"redirect_uri":  {"https://example.com/foo"},
		"response_type": {"code"},
		"scope":         {"openid email profile"},
	}
	req := httptest.NewRequest("GET", "http://localhost/auth?"+params.Encode(), nil)
	_, err := server.parseAuthorizationRequest(req)
	require.NoError(t, err)
}
