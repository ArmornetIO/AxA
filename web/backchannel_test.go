package web_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ArmornetIO/identity/web"
)

// ---- test OIDC server -------------------------------------------------------

const testBCKid = "test-rsa-key"

type testBCOIDCServer struct {
	server   *httptest.Server
	key      *rsa.PrivateKey
	clientID string
}

func newTestBCOIDCServer(t *testing.T, clientID string) *testBCOIDCServer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ts := &testBCOIDCServer{key: key, clientID: clientID}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", ts.handleDiscovery)
	mux.HandleFunc("/keys", ts.handleJWKS)
	ts.server = httptest.NewServer(mux)
	t.Cleanup(ts.server.Close)
	return ts
}

func (ts *testBCOIDCServer) issuerURL() string { return ts.server.URL }

func (ts *testBCOIDCServer) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"issuer":                                ts.issuerURL(),
		"jwks_uri":                              ts.issuerURL() + "/keys",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (ts *testBCOIDCServer) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	n := base64.RawURLEncoding.EncodeToString(ts.key.PublicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(ts.key.PublicKey.E)).Bytes())
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "alg": "RS256",
			"kid": testBCKid, "n": n, "e": e,
		}},
	})
}

func (ts *testBCOIDCServer) provider(t *testing.T) *oidc.Provider {
	t.Helper()
	p, err := oidc.NewProvider(context.Background(), ts.issuerURL())
	require.NoError(t, err)
	return p
}

func (ts *testBCOIDCServer) verifier(t *testing.T) web.LogoutTokenVerifier {
	t.Helper()
	v, err := web.NewLogoutTokenVerifierFromProvider(ts.provider(t), ts.clientID)
	require.NoError(t, err)
	return v
}

// sign builds and signs a logout_token. Pass nil values to delete a key from the base set.
func (ts *testBCOIDCServer) sign(t *testing.T, overrides jwtv5.MapClaims) string {
	t.Helper()
	now := time.Now()
	base := jwtv5.MapClaims{
		"iss": ts.issuerURL(),
		"sub": "google:user-abc-123",
		"aud": jwtv5.ClaimStrings{ts.clientID},
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"jti": "jti-unique-001",
		"events": map[string]any{
			web.BackchannelLogoutEventURI: map[string]any{},
		},
	}
	for k, v := range overrides {
		if v == nil {
			delete(base, k)
		} else {
			base[k] = v
		}
	}
	tok := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, base)
	tok.Header["kid"] = testBCKid
	raw, err := tok.SignedString(ts.key)
	require.NoError(t, err)
	return raw
}

// ---- ValidateLogoutToken verifier tests ------------------------------------

func TestValidateLogoutToken_HappyPath(t *testing.T) {
	ts := newTestBCOIDCServer(t, "armornet-bff")
	v := ts.verifier(t)

	raw := ts.sign(t, nil)
	claims, err := v.ValidateLogoutToken(context.Background(), raw)

	require.NoError(t, err)
	assert.Equal(t, "google:user-abc-123", claims.Subject)
	assert.Equal(t, "jti-unique-001", claims.JTI)
	assert.Empty(t, claims.SID)
}

func TestValidateLogoutToken_WithSID(t *testing.T) {
	ts := newTestBCOIDCServer(t, "armornet-bff")
	raw := ts.sign(t, jwtv5.MapClaims{"sid": "session-abc-456"})
	claims, err := ts.verifier(t).ValidateLogoutToken(context.Background(), raw)
	require.NoError(t, err)
	assert.Equal(t, "session-abc-456", claims.SID)
}

// Trap 1: passing an empty clientID means go-oidc skips audience validation entirely,
// allowing a token issued for any client through. The constructor must guard against this.
func TestNewLogoutTokenVerifierFromProvider_Trap1_EmptyClientIDRejected(t *testing.T) {
	ts := newTestBCOIDCServer(t, "armornet-bff")
	_, err := web.NewLogoutTokenVerifierFromProvider(ts.provider(t), "")
	assert.ErrorContains(t, err, "clientID must not be empty",
		"empty clientID would bypass audience validation (Trap 1)")
}

// Trap 1: a token whose aud does not match the registered clientID must be rejected.
func TestValidateLogoutToken_Trap1_WrongAudience(t *testing.T) {
	ts := newTestBCOIDCServer(t, "armornet-bff")
	raw := ts.sign(t, jwtv5.MapClaims{"aud": jwtv5.ClaimStrings{"other-client"}})
	_, err := ts.verifier(t).ValidateLogoutToken(context.Background(), raw)
	assert.Error(t, err, "wrong audience must be rejected (Trap 1)")
}

// Trap 2: the spec (§4.1) explicitly forbids a nonce claim in logout_tokens.
// Its presence indicates the token may be an ID token reused by an attacker.
func TestValidateLogoutToken_Trap2_NonceForbidden(t *testing.T) {
	ts := newTestBCOIDCServer(t, "armornet-bff")
	raw := ts.sign(t, jwtv5.MapClaims{"nonce": "a-nonce-value"})
	_, err := ts.verifier(t).ValidateLogoutToken(context.Background(), raw)
	assert.ErrorContains(t, err, "nonce",
		"nonce claim is forbidden in logout_token (Trap 2)")
}

// Trap 3: events must be a JSON object, not a string or any scalar.
func TestValidateLogoutToken_Trap3_EventsNotAnObject(t *testing.T) {
	ts := newTestBCOIDCServer(t, "armornet-bff")
	raw := ts.sign(t, jwtv5.MapClaims{"events": "not-an-object"})
	_, err := ts.verifier(t).ValidateLogoutToken(context.Background(), raw)
	assert.Error(t, err, "events as string must be rejected (Trap 3)")
}

// Trap 3: events is a valid object but lacks the required event URI key.
func TestValidateLogoutToken_Trap3_EventsWrongKey(t *testing.T) {
	ts := newTestBCOIDCServer(t, "armornet-bff")
	raw := ts.sign(t, jwtv5.MapClaims{
		"events": map[string]any{
			"http://openid.net/events/wrong-event-type": map[string]any{},
		},
	})
	_, err := ts.verifier(t).ValidateLogoutToken(context.Background(), raw)
	assert.ErrorContains(t, err, web.BackchannelLogoutEventURI,
		"wrong event URI key must be rejected (Trap 3)")
}

// Trap 3: events claim is entirely absent.
func TestValidateLogoutToken_Trap3_EventsMissing(t *testing.T) {
	ts := newTestBCOIDCServer(t, "armornet-bff")
	raw := ts.sign(t, jwtv5.MapClaims{"events": nil}) // nil = delete key
	_, err := ts.verifier(t).ValidateLogoutToken(context.Background(), raw)
	assert.ErrorContains(t, err, "events",
		"missing events claim must be rejected (Trap 3)")
}

// Missing jti makes replay prevention impossible — reject.
func TestValidateLogoutToken_MissingJTI(t *testing.T) {
	ts := newTestBCOIDCServer(t, "armornet-bff")
	raw := ts.sign(t, jwtv5.MapClaims{"jti": nil})
	_, err := ts.verifier(t).ValidateLogoutToken(context.Background(), raw)
	assert.ErrorContains(t, err, "jti")
}

// Expired token is rejected by go-oidc before our validation logic runs.
func TestValidateLogoutToken_Expired(t *testing.T) {
	ts := newTestBCOIDCServer(t, "armornet-bff")
	raw := ts.sign(t, jwtv5.MapClaims{"exp": time.Now().Add(-time.Minute).Unix()})
	_, err := ts.verifier(t).ValidateLogoutToken(context.Background(), raw)
	assert.Error(t, err)
}

// ---- MemJTIStore tests -------------------------------------------------------

func TestMemJTIStore_UnseenJTI_ReturnsFalse(t *testing.T) {
	s := web.NewMemJTIStore()
	seen, err := s.HasSeen(context.Background(), "jti-never-seen")
	require.NoError(t, err)
	assert.False(t, seen)
}

func TestMemJTIStore_SeenAfterRecord(t *testing.T) {
	s := web.NewMemJTIStore()
	exp := time.Now().Add(time.Hour)
	require.NoError(t, s.Record(context.Background(), "jti-x", exp))
	seen, err := s.HasSeen(context.Background(), "jti-x")
	require.NoError(t, err)
	assert.True(t, seen)
}

// Expired JTI entries should be treated as unseen (replay window closed).
func TestMemJTIStore_ExpiredEntry_NotSeen(t *testing.T) {
	s := web.NewMemJTIStore()
	past := time.Now().Add(-time.Second)
	require.NoError(t, s.Record(context.Background(), "jti-old", past))
	seen, err := s.HasSeen(context.Background(), "jti-old")
	require.NoError(t, err)
	assert.False(t, seen)
}

func TestMemJTIStore_DifferentJTIsAreIndependent(t *testing.T) {
	s := web.NewMemJTIStore()
	exp := time.Now().Add(time.Hour)
	require.NoError(t, s.Record(context.Background(), "jti-1", exp))
	seen2, _ := s.HasSeen(context.Background(), "jti-2")
	assert.False(t, seen2)
}

func TestMemJTIStore_ConcurrentAccess(t *testing.T) {
	s := web.NewMemJTIStore()
	exp := time.Now().Add(time.Hour)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		jti := fmt.Sprintf("jti-%d", i)
		wg.Add(1)
		go func(j string) {
			defer wg.Done()
			_ = s.Record(context.Background(), j, exp)
			_, _ = s.HasSeen(context.Background(), j)
		}(jti)
	}
	wg.Wait()
}
