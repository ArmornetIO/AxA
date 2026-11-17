package dex

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	dexstorage "github.com/ArmornetIO/axa/internal/dex/storage"
)

const (
	verifyPath   = "/dex/device/auth/verify_code"
	callbackPath = "/dex/device/callback"
)

func testGate(signedIn string, now time.Time) deviceGate {
	return deviceGate{
		approver: func(*http.Request) string { return signedIn },
		sealer:   reversibleSealer{},
		spa:      true,
		now:      func() time.Time { return now },
	}
}

// seen records what the wrapped Dex handler was handed, if it ran at all.
type seen struct {
	ran     bool
	subject string
}

func (s *seen) handler() http.Handler {
	return http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		s.ran = true
		s.subject, _ = r.Context().Value(approverKey{}).(string)
	})
}

func enterCode(t *testing.T, g deviceGate, userCode string) (*seen, *httptest.ResponseRecorder) {
	t.Helper()
	form := url.Values{"user_code": {userCode}}
	r := httptest.NewRequest(http.MethodPost, verifyPath, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var s seen
	w := httptest.NewRecorder()
	g.wrap(s.handler()).ServeHTTP(w, r)
	return &s, w
}

func callback(g deviceGate, state string, cookies ...*http.Cookie) (*seen, *httptest.ResponseRecorder) {
	r := httptest.NewRequest(http.MethodGet, callbackPath+"?code=c&state="+url.QueryEscape(state), nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	var s seen
	w := httptest.NewRecorder()
	g.wrap(s.handler()).ServeHTTP(w, r)
	return &s, w
}

func approvalFrom(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == approvalCookie && c.MaxAge > 0 {
			return c
		}
	}
	t.Fatal("no approval cookie set")
	return nil
}

func TestDeviceGateRefusesCodeWithoutSession(t *testing.T) {
	s, w := enterCode(t, testGate("", time.Now()), "ABCD-EFGH")
	if s.ran {
		t.Fatal("Dex saw a code entered with no host session")
	}
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "/dex-error?") {
		t.Fatalf("Location = %q, want the error page", loc)
	}
}

func TestDeviceGateCarriesApproverToCallback(t *testing.T) {
	now := time.Now()
	g := testGate("alice", now)
	s, w := enterCode(t, g, "abcd-efgh")
	if !s.ran {
		t.Fatal("Dex never saw an approved code")
	}
	ck := approvalFrom(t, w)
	if ck.Path != callbackPath || ck.SameSite != http.SameSiteLaxMode || !ck.HttpOnly {
		t.Fatalf("approval cookie = %+v, want HttpOnly Lax on %s", ck, callbackPath)
	}

	s, w = callback(g, "ABCD-EFGH", ck)
	if !s.ran || s.subject != "alice" {
		t.Fatalf("callback ran=%v subject=%q, want alice", s.ran, s.subject)
	}
	cleared := false
	for _, c := range w.Result().Cookies() {
		cleared = cleared || (c.Name == approvalCookie && c.MaxAge < 0)
	}
	if !cleared {
		t.Error("approval cookie left behind after the callback")
	}
}

func TestDeviceGateRefusesCallback(t *testing.T) {
	now := time.Now()
	_, w := enterCode(t, testGate("alice", now), "ABCD-EFGH")
	ck := approvalFrom(t, w)

	for name, tc := range map[string]struct {
		gate    deviceGate
		state   string
		cookies []*http.Cookie
	}{
		"no approval":    {testGate("alice", now), "ABCD-EFGH", nil},
		"another code":   {testGate("alice", now), "WXYZ-WXYZ", []*http.Cookie{ck}},
		"expired":        {testGate("alice", now.Add(approvalTTL+time.Second)), "ABCD-EFGH", []*http.Cookie{ck}},
		"not our sealer": {deviceGate{approver: testGate("", now).approver, now: time.Now}, "ABCD-EFGH", []*http.Cookie{ck}},
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := callback(tc.gate, tc.state, tc.cookies...)
			if s.ran {
				t.Fatal("Dex completed a callback with no valid approval")
			}
		})
	}
}

func idTokenFor(sub string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(`{"sub":"`+sub+`"}`)) + ".sig"
}

func TestGatedStoreGrantsOnlyTheApprover(t *testing.T) {
	complete := func(sub string) func(dexstorage.DeviceToken) (dexstorage.DeviceToken, error) {
		return func(old dexstorage.DeviceToken) (dexstorage.DeviceToken, error) {
			old.Status = deviceTokenComplete
			old.Token = `{"access_token":"a","id_token":"` + idTokenFor(sub) + `"}`
			return old, nil
		}
	}
	approvedBy := func(sub string) context.Context {
		return context.WithValue(context.Background(), approverKey{}, sub)
	}

	for name, tc := range map[string]struct {
		ctx     context.Context
		signsIn string
		granted bool
	}{
		"approver signs in":     {approvedBy("alice"), "alice", true},
		"someone else signs in": {approvedBy("alice"), "bob", false},
		"never approved":        {context.Background(), "alice", false},
	} {
		t.Run(name, func(t *testing.T) {
			store, inner := newTestDeviceStore()
			store.gated = true
			if err := store.CreateDeviceToken(context.Background(), dexstorage.DeviceToken{DeviceCode: testDeviceCode, Status: "pending"}); err != nil {
				t.Fatal(err)
			}
			err := store.UpdateDeviceToken(tc.ctx, testDeviceCode, complete(tc.signsIn))
			if (err == nil) != tc.granted {
				t.Fatalf("err = %v, want granted=%v", err, tc.granted)
			}
			got := inner.tokens[hashDeviceCode(testDeviceCode)]
			if (got.Status == deviceTokenComplete) != tc.granted {
				t.Fatalf("stored status %q, want granted=%v", got.Status, tc.granted)
			}
		})
	}
}

// The CLI's polling updates the same row with no browser, so no approver.
func TestGatedStoreLetsPollingThrough(t *testing.T) {
	store, _ := newTestDeviceStore()
	store.gated = true
	ctx := context.Background()
	if err := store.CreateDeviceToken(ctx, dexstorage.DeviceToken{DeviceCode: testDeviceCode, Status: "pending"}); err != nil {
		t.Fatal(err)
	}
	err := store.UpdateDeviceToken(ctx, testDeviceCode, func(old dexstorage.DeviceToken) (dexstorage.DeviceToken, error) {
		old.PollIntervalSeconds = 10
		return old, nil
	})
	if err != nil {
		t.Fatalf("poll update refused: %v", err)
	}
}
