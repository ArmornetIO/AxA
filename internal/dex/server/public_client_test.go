package server

// ARMORNET PATCH tests for withPKCEOrSecretClient: a public client exchanges an
// authorization code with its PKCE verifier and no secret, and gains nothing
// on any other grant.

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ArmornetIO/identity/internal/dex/storage"
)

const (
	publicClientID = "public-spa"
	publicRedirect = "http://localhost:5555/callback"
	pkceVerifier   = "a-sufficiently-long-code-verifier-0123456789-abcdefghijk"
)

func newPublicClientServer(t *testing.T) (tokenURL string, srv *Server) {
	t.Helper()
	ts, srv := newTestServer(t, func(c *Config) {
		c.EnableClientCredentials = true
		c.AllowedGrantTypes = append(c.AllowedGrantTypes, grantTypeClientCredentials)
	})
	require.NoError(t, srv.storage.CreateClient(t.Context(), storage.Client{
		ID:           publicClientID,
		Secret:       "stored-but-never-presented",
		Name:         "Public SPA",
		Public:       true,
		RedirectURIs: []string{publicRedirect},
	}))
	return ts.URL + "/token", srv
}

func seedCode(t *testing.T, srv *Server, id string, pkce storage.PKCE) {
	t.Helper()
	require.NoError(t, srv.storage.CreateAuthCode(t.Context(), storage.AuthCode{
		ID:          id,
		ClientID:    publicClientID,
		RedirectURI: publicRedirect,
		Nonce:       "nonce",
		Scopes:      []string{"openid"},
		ConnectorID: "mock",
		Claims:      storage.Claims{UserID: "u1", Username: "u1", Email: "u1@example.com", EmailVerified: true},
		Expiry:      time.Now().Add(time.Minute),
		PKCE:        pkce,
	}))
}

func TestPublicClient_ExchangesCodeWithPKCEAndNoSecret(t *testing.T) {
	tokenURL, srv := newPublicClientServer(t)
	seedCode(t, srv, "code-pkce", storage.PKCE{
		CodeChallenge:       pkceChallengeS256(pkceVerifier),
		CodeChallengeMethod: codeChallengeMethodS256,
	})

	resp := postToken(t, tokenURL, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {publicClientID},
		"code":          {"code-pkce"},
		"redirect_uri":  {publicRedirect},
		"code_verifier": {pkceVerifier},
	})
	body := readTokenResponse(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body: %v", body)
	require.NotEmpty(t, body["id_token"])
}

func TestPublicClient_WrongVerifierRefused(t *testing.T) {
	tokenURL, srv := newPublicClientServer(t)
	seedCode(t, srv, "code-pkce", storage.PKCE{
		CodeChallenge:       pkceChallengeS256(pkceVerifier),
		CodeChallengeMethod: codeChallengeMethodS256,
	})

	resp := postToken(t, tokenURL, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {publicClientID},
		"code":          {"code-pkce"},
		"redirect_uri":  {publicRedirect},
		"code_verifier": {"someone-elses-verifier-0123456789-abcdefghijklmnopqrst"},
	})
	body := readTokenResponse(t, resp)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Equal(t, "invalid_grant", body["error"])
}

// With no challenge there is nothing standing in for the secret.
func TestPublicClient_CodeWithoutPKCERefused(t *testing.T) {
	tokenURL, srv := newPublicClientServer(t)
	seedCode(t, srv, "code-plain", storage.PKCE{})

	resp := postToken(t, tokenURL, url.Values{
		"grant_type":   {"authorization_code"},
		"client_id":    {publicClientID},
		"code":         {"code-plain"},
		"redirect_uri": {publicRedirect},
	})
	body := readTokenResponse(t, resp)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Equal(t, "invalid_grant", body["error"])
}

// The exemption is the authorization_code grant's alone: a public client must
// not be able to mint machine tokens.
func TestPublicClient_ClientCredentialsStillNeedsSecret(t *testing.T) {
	tokenURL, _ := newPublicClientServer(t)

	resp := postToken(t, tokenURL, url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {publicClientID},
		"scope":      {"openid"},
	})
	body := readTokenResponse(t, resp)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	require.Equal(t, "invalid_client", body["error"])
}

// A confidential client gains nothing: its code exchange still needs the secret.
func TestConfidentialClient_CodeExchangeStillNeedsSecret(t *testing.T) {
	ts, srv := newTestServer(t, nil)
	require.NoError(t, srv.storage.CreateClient(t.Context(), storage.Client{
		ID: "confidential", Secret: "real-secret", Name: "Confidential", RedirectURIs: []string{publicRedirect},
	}))
	require.NoError(t, srv.storage.CreateAuthCode(t.Context(), storage.AuthCode{
		ID: "code-conf", ClientID: "confidential", RedirectURI: publicRedirect, Nonce: "n",
		Scopes: []string{"openid"}, ConnectorID: "mock", Expiry: time.Now().Add(time.Minute),
		Claims: storage.Claims{UserID: "u1", Username: "u1"},
		PKCE:   storage.PKCE{CodeChallenge: pkceChallengeS256(pkceVerifier), CodeChallengeMethod: codeChallengeMethodS256},
	}))

	resp := postToken(t, ts.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"confidential"},
		"code":          {"code-conf"},
		"redirect_uri":  {publicRedirect},
		"code_verifier": {pkceVerifier},
	})
	body := readTokenResponse(t, resp)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	require.Equal(t, "invalid_client", body["error"])
}

func pkceChallengeS256(verifier string) string {
	s := &Server{}
	c, _ := s.calculateCodeChallenge(verifier, codeChallengeMethodS256)
	return c
}
