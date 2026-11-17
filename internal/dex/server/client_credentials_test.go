package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/require"

	"github.com/ArmornetIO/axa/internal/dex/storage"
)

// newCCServer builds a test server with client_credentials enabled and a
// pre-seeded client whose secret is known. Returns the httptest.Server URL
// and the client record.
func newCCServer(t *testing.T) (serverURL, tokenURL string, client storage.Client, secret string) {
	t.Helper()

	const (
		testClientID     = "agent:test-org:00000000-0000-0000-0000-000000000001"
		testClientSecret = "test-agent-secret"
	)

	ts, srv := newTestServer(t, func(c *Config) {
		c.EnableClientCredentials = true
		c.AllowedGrantTypes = append(c.AllowedGrantTypes, grantTypeClientCredentials)
	})

	ctx := t.Context()
	cl := storage.Client{
		ID:     testClientID,
		Secret: testClientSecret,
		Name:   "Test Agent",
		Public: false,
	}
	require.NoError(t, srv.storage.CreateClient(ctx, cl))

	return ts.URL, ts.URL + "/token", cl, testClientSecret
}

func postToken(t *testing.T, tokenURL string, vals url.Values) *http.Response {
	t.Helper()
	resp, err := http.PostForm(tokenURL, vals)
	require.NoError(t, err)
	return resp
}

func readTokenResponse(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(body, &out))
	return out
}

// decodeJWTPayload base64-decodes the payload segment of a JWT without verifying
// the signature. Used only to inspect claims in unit tests.
func decodeJWTPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.SplitN(token, ".", 3)
	require.Len(t, parts, 3, "not a JWT")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}

// ── Happy path ─────────────────────────────────────────────────────────────────

func TestClientCredentials_IssuesToken(t *testing.T) {
	_, tokenURL, cl, secret := newCCServer(t)

	resp := postToken(t, tokenURL, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {cl.ID},
		"client_secret": {secret},
		"scope":         {"openid"},
	})
	body := readTokenResponse(t, resp)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	require.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	require.Equal(t, "no-cache", resp.Header.Get("Pragma"))
	require.NotEmpty(t, body["access_token"], "access_token must be present")
	require.Equal(t, "bearer", body["token_type"])
	expiresIn, ok := body["expires_in"].(float64)
	require.True(t, ok && expiresIn > 0, "expires_in must be positive")
	require.Empty(t, body["refresh_token"], "no refresh token for client_credentials")
}

func TestClientCredentials_TokenHasCorrectSub(t *testing.T) {
	_, tokenURL, cl, secret := newCCServer(t)

	resp := postToken(t, tokenURL, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {cl.ID},
		"client_secret": {secret},
		"scope":         {"openid"},
	})
	body := readTokenResponse(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	rawToken, ok := body["access_token"].(string)
	require.True(t, ok)

	claims := decodeJWTPayload(t, rawToken)
	// sub must be the plain client ID — not a protobuf-encoded Dex subject.
	require.Equal(t, cl.ID, claims["sub"], "sub must equal client_id verbatim")
}

func TestClientCredentials_TokenVerifiesAgainstJWKS(t *testing.T) {
	serverURL, tokenURL, cl, secret := newCCServer(t)
	ctx := t.Context()

	resp := postToken(t, tokenURL, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {cl.ID},
		"client_secret": {secret},
		"scope":         {"openid"},
	})
	body := readTokenResponse(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	rawToken, ok := body["access_token"].(string)
	require.True(t, ok)

	provider, err := oidc.NewProvider(ctx, serverURL)
	require.NoError(t, err)

	verifier := provider.Verifier(&oidc.Config{SkipClientIDCheck: true})
	idToken, err := verifier.Verify(ctx, rawToken)
	require.NoError(t, err)
	require.Equal(t, cl.ID, idToken.Subject)
}

// ── Adversarial / unhappy paths ───────────────────────────────────────────────

func TestClientCredentials_WrongSecret(t *testing.T) {
	_, tokenURL, cl, _ := newCCServer(t)

	resp := postToken(t, tokenURL, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {cl.ID},
		"client_secret": {"totally-wrong-secret"},
		"scope":         {"openid"},
	})
	body := readTokenResponse(t, resp)

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	require.Equal(t, "invalid_client", body["error"])
}

func TestClientCredentials_EmptySecret(t *testing.T) {
	_, tokenURL, cl, _ := newCCServer(t)

	resp := postToken(t, tokenURL, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {cl.ID},
		"client_secret": {""},
		"scope":         {"openid"},
	})
	body := readTokenResponse(t, resp)

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	require.Equal(t, "invalid_client", body["error"])
}

func TestClientCredentials_UnknownClientID(t *testing.T) {
	_, tokenURL, _, secret := newCCServer(t)

	resp := postToken(t, tokenURL, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"agent:ghost:00000000-0000-0000-0000-000000000099"},
		"client_secret": {secret},
		"scope":         {"openid"},
	})
	body := readTokenResponse(t, resp)

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	require.Equal(t, "invalid_client", body["error"])
}

func TestClientCredentials_EmptyClientID(t *testing.T) {
	_, tokenURL, _, secret := newCCServer(t)

	resp := postToken(t, tokenURL, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {""},
		"client_secret": {secret},
		"scope":         {"openid"},
	})
	body := readTokenResponse(t, resp)

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	require.Equal(t, "invalid_client", body["error"])
}

func TestClientCredentials_MissingOpenIDScope(t *testing.T) {
	_, tokenURL, cl, secret := newCCServer(t)

	resp := postToken(t, tokenURL, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {cl.ID},
		"client_secret": {secret},
		// intentionally no scope=openid
	})
	body := readTokenResponse(t, resp)

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Equal(t, "invalid_request", body["error"])
}

func TestClientCredentials_GrantDisabled(t *testing.T) {
	// Build a server with EnableClientCredentials: false (default).
	ts, srv := newTestServer(t, func(c *Config) {
		// do NOT set EnableClientCredentials or add grantTypeClientCredentials
	})
	ctx := t.Context()
	cl := storage.Client{
		ID:     "agent:org:abc",
		Secret: "s3cr3t",
		Name:   "Disabled test",
	}
	require.NoError(t, srv.storage.CreateClient(ctx, cl))

	resp := postToken(t, ts.URL+"/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {cl.ID},
		"client_secret": {cl.Secret},
		"scope":         {"openid"},
	})
	body := readTokenResponse(t, resp)

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Equal(t, "unsupported_grant_type", body["error"])
}

func TestClientCredentials_ScopeStripping(t *testing.T) {
	_, tokenURL, cl, secret := newCCServer(t)

	// Request user-context scopes that should be silently dropped.
	resp := postToken(t, tokenURL, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {cl.ID},
		"client_secret": {secret},
		"scope":         {"openid profile email groups offline_access"},
	})
	body := readTokenResponse(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	rawToken, ok := body["access_token"].(string)
	require.True(t, ok)

	claims := decodeJWTPayload(t, rawToken)
	require.Empty(t, claims["email"], "email must not appear in client_credentials token")
	require.Empty(t, claims["name"], "name must not appear in client_credentials token")
	require.Empty(t, claims["groups"], "groups must not appear in client_credentials token")
	require.Empty(t, body["refresh_token"], "no refresh_token for client_credentials")
}

func TestClientCredentials_OfflineAccessIgnored(t *testing.T) {
	_, tokenURL, cl, secret := newCCServer(t)

	resp := postToken(t, tokenURL, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {cl.ID},
		"client_secret": {secret},
		"scope":         {"openid offline_access"},
	})
	body := readTokenResponse(t, resp)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Empty(t, body["refresh_token"], "offline_access must be silently ignored")
}

func TestClientCredentials_GETMethodRejected(t *testing.T) {
	_, tokenURL, cl, secret := newCCServer(t)

	req, err := http.NewRequest(http.MethodGet, tokenURL+"?grant_type=client_credentials&client_id="+cl.ID+"&client_secret="+secret+"&scope=openid", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// handleToken rejects non-POST before checking grant type.
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestClientCredentials_SecretTimingSafe(t *testing.T) {
	// Verify that a wrong secret and an unknown client both return invalid_client
	// with the same HTTP status — not leaking whether the client_id exists.
	_, tokenURL, cl, _ := newCCServer(t)

	wrongSecretResp := postToken(t, tokenURL, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {cl.ID},
		"client_secret": {"wrong"},
		"scope":         {"openid"},
	})
	wrongSecretBody := readTokenResponse(t, wrongSecretResp)

	unknownClientResp := postToken(t, tokenURL, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"agent:ghost:99999999-9999-9999-9999-999999999999"},
		"client_secret": {"also-wrong"},
		"scope":         {"openid"},
	})
	unknownClientBody := readTokenResponse(t, unknownClientResp)

	// Both must return 401 invalid_client — same error, same status.
	require.Equal(t, http.StatusUnauthorized, wrongSecretResp.StatusCode)
	require.Equal(t, http.StatusUnauthorized, unknownClientResp.StatusCode)
	require.Equal(t, "invalid_client", wrongSecretBody["error"])
	require.Equal(t, "invalid_client", unknownClientBody["error"])
}

func TestClientCredentials_IssuedTokenRejectsRefreshAttempt(t *testing.T) {
	_, tokenURL, cl, secret := newCCServer(t)

	// Get a valid access_token.
	resp := postToken(t, tokenURL, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {cl.ID},
		"client_secret": {secret},
		"scope":         {"openid"},
	})
	body := readTokenResponse(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	accessToken := body["access_token"].(string)

	// Attempt to redeem it as a refresh_token — must fail.
	refreshResp := postToken(t, tokenURL, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {cl.ID},
		"client_secret": {secret},
		"refresh_token": {accessToken},
	})
	refreshBody := readTokenResponse(t, refreshResp)

	require.NotEqual(t, http.StatusOK, refreshResp.StatusCode)
	require.NotEmpty(t, refreshBody["error"])
}

func TestClientCredentials_NonAgentSubRejectedByAgentProvider(t *testing.T) {
	// A regular (non-agent) client can get a token via client_credentials,
	// but the AgentTokenProvider must reject it because sub doesn't start with "agent:".
	ts, srv := newTestServer(t, func(c *Config) {
		c.EnableClientCredentials = true
		c.AllowedGrantTypes = append(c.AllowedGrantTypes, grantTypeClientCredentials)
	})
	ctx := t.Context()

	regularClient := storage.Client{
		ID:     "myapp",
		Secret: "myapp-secret",
		Name:   "Regular App",
	}
	require.NoError(t, srv.storage.CreateClient(ctx, regularClient))

	resp := postToken(t, ts.URL+"/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {regularClient.ID},
		"client_secret": {regularClient.Secret},
		"scope":         {"openid"},
	})
	body := readTokenResponse(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	rawToken := body["access_token"].(string)
	claims := decodeJWTPayload(t, rawToken)
	// sub is "myapp" — no "agent:" prefix, so the armornet AgentTokenProvider
	// would reject this token when parsing the subject convention.
	require.Equal(t, "myapp", claims["sub"])
	require.False(t, strings.HasPrefix(claims["sub"].(string), "agent:"),
		"non-agent client must not produce an agent-prefixed sub")
}
