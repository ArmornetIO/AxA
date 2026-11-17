package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ArmornetIO/axa/internal/dex/storage"
)

// parseLogoutTokenClaimsUnverified extracts JWT claims from a compact token without
// verifying the signature. Sufficient for unit-testing logout_token claim contents.
func parseLogoutTokenClaimsUnverified(t *testing.T, raw string) map[string]any {
	t.Helper()
	parts := strings.SplitN(raw, ".", 3)
	require.Len(t, parts, 3, "not a compact JWT")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err, "decode JWT payload")
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims), "unmarshal claims")
	return claims
}

// captureServer creates a test HTTP server that collects all logout_token form values
// from inbound backchannel logout POSTs. It increments wg.Done() once per request.
func captureServer(t *testing.T, wg *sync.WaitGroup) (srv *httptest.Server, tokens func() []string) {
	t.Helper()
	var mu sync.Mutex
	var received []string
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer wg.Done()
		require.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		mu.Lock()
		received = append(received, form.Get("logout_token"))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		cp := make([]string, len(received))
		copy(cp, received)
		return cp
	}
}

// seedClientAndSession creates a Dex client (with optional BackchannelLogoutURI) and an
// offline session with one refresh token entry pointing to that client.
func seedClientAndSession(t *testing.T, s *Server, userID, connID, clientID, backchannelURI string) {
	t.Helper()
	ctx := context.Background()

	c := storage.Client{
		ID:                   clientID,
		Secret:               "secret",
		RedirectURIs:         []string{"http://client.local/callback"},
		BackchannelLogoutURI: backchannelURI, // empty = Trap 7 test
	}
	require.NoError(t, s.storage.CreateClient(ctx, c))

	rt := storage.RefreshToken{
		ID:          "refresh-" + clientID,
		ClientID:    clientID,
		ConnectorID: connID,
		Claims:      storage.Claims{UserID: userID},
	}
	require.NoError(t, s.storage.CreateRefresh(ctx, rt))

	ref := &storage.RefreshTokenRef{ID: rt.ID, ClientID: clientID}
	sess := storage.OfflineSessions{
		UserID:  userID,
		ConnID:  connID,
		Refresh: map[string]*storage.RefreshTokenRef{clientID: ref},
	}
	// A second client for the same (userID, connID) shares one offline session —
	// creating it twice is ErrAlreadyExists, so add the ref to the existing row.
	if err := s.storage.CreateOfflineSessions(ctx, sess); errors.Is(err, storage.ErrAlreadyExists) {
		require.NoError(t, s.storage.UpdateOfflineSessions(ctx, userID, connID,
			func(old storage.OfflineSessions) (storage.OfflineSessions, error) {
				old.Refresh[clientID] = ref
				return old, nil
			}))
	} else {
		require.NoError(t, err)
	}
}

// waitWithTimeout blocks until wg is done or the deadline passes.
func waitWithTimeout(t *testing.T, wg *sync.WaitGroup, d time.Duration, msg string) {
	t.Helper()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("timeout after %v: %s", d, msg)
	}
}

// Trap 5: the sub claim in the logout_token must equal the userID as stored in
// armornet sessions (compound connector_id:remote_subject format used by Dex).
func TestTerminateUserSession_Trap5_SubjectEncodingInLogoutToken(t *testing.T) {
	_, s := newTestServer(t, nil)

	const (
		userID   = "google:user-abc-123" // compound format Dex sets as ID token sub
		connID   = "google"
		clientID = "armornet-bff"
	)

	var wg sync.WaitGroup
	wg.Add(1)
	rcvr, getTokens := captureServer(t, &wg)
	seedClientAndSession(t, s, userID, connID, clientID, rcvr.URL)

	s.terminateUserSession(context.Background(), userID, connID)
	waitWithTimeout(t, &wg, 5*time.Second, "logout_token POST not received")

	tokens := getTokens()
	require.Len(t, tokens, 1)
	claims := parseLogoutTokenClaimsUnverified(t, tokens[0])
	assert.Equal(t, userID, claims["sub"],
		"Trap 5: sub must use Dex compound subject, matching armornet session.Subject")
}

// Fan-out fires for every client that has a BackchannelLogoutURI.
func TestTerminateUserSession_FansOutToAllRegisteredClients(t *testing.T) {
	_, s := newTestServer(t, nil)

	const (
		userID = "google:user-multi"
		connID = "google"
	)

	var wg sync.WaitGroup
	wg.Add(2)
	rcvr, getTokens := captureServer(t, &wg)

	// Two clients, same receiver URL (simulates two separate RPs) sharing one
	// offline session — seedClientAndSession merges the second client's ref in.
	for _, clientID := range []string{"client-a", "client-b"} {
		seedClientAndSession(t, s, userID, connID, clientID, rcvr.URL)
	}

	s.terminateUserSession(context.Background(), userID, connID)
	waitWithTimeout(t, &wg, 5*time.Second, "expected 2 logout_token POSTs")
	assert.Len(t, getTokens(), 2, "each client must receive one logout_token")
}

// Trap 7: clients without a BackchannelLogoutURI must be silently skipped — no HTTP call.
func TestTerminateUserSession_Trap7_SkipsClientsWithoutBackchannelURI(t *testing.T) {
	_, s := newTestServer(t, nil)

	const (
		userID   = "google:user-skip"
		connID   = "google"
		clientID = "no-uri-client"
	)

	// Seed a client with NO BackchannelLogoutURI.
	seedClientAndSession(t, s, userID, connID, clientID, "" /* no URI */)

	// Track any unexpected HTTP calls.
	unexpectedCalls := 0
	spy := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		unexpectedCalls++
	}))
	defer spy.Close()

	s.terminateUserSession(context.Background(), userID, connID)

	// Brief pause to ensure any goroutines complete.
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, 0, unexpectedCalls, "Trap 7: no POST for client without BackchannelLogoutURI")
}

// Trap 4: a slow backchannel_logout_uri must not block terminateUserSession indefinitely.
// The implementation must apply a per-request timeout.
func TestTerminateUserSession_Trap4_FanOutDoesNotBlockOnSlowServer(t *testing.T) {
	_, s := newTestServer(t, nil)

	const (
		userID   = "google:user-slow"
		connID   = "google"
		clientID = "slow-client"
	)

	// Simulate a hung RP that never responds. It hangs until the test releases
	// it rather than for a fixed 60s: httptest.Server.Close waits for in-flight
	// handlers, so a sleeping one adds its whole duration to the package's
	// runtime after the assertion has already passed.
	release := make(chan struct{})
	hangingSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); hangingSrv.Close() })

	seedClientAndSession(t, s, userID, connID, clientID, hangingSrv.URL)

	start := time.Now()

	done := make(chan struct{})
	go func() {
		s.terminateUserSession(context.Background(), userID, connID)
		close(done)
	}()

	select {
	case <-done:
		elapsed := time.Since(start)
		// Must complete well within 20 seconds, not after the 60s hang.
		assert.Less(t, elapsed, 20*time.Second,
			"Trap 4: terminateUserSession must not block indefinitely on slow backchannel URIs")
	case <-time.After(25 * time.Second):
		t.Fatal("Trap 4: terminateUserSession blocked longer than 25 seconds")
	}
}

// discovery document must advertise back-channel logout support to RPs.
func TestDiscovery_AdvertisesBackchannelLogoutSupport(t *testing.T) {
	httpSrv, server := newTestServer(t, nil)
	_ = server

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	httpSrv.Config.Handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var doc map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&doc))
	assert.Equal(t, true, doc["backchannel_logout_supported"],
		"discovery must advertise backchannel_logout_supported: true")
}
