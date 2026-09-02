package deviceauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func newClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	// A tiny base interval keeps the timing assertions real (a slow_down still
	// has to double the wait) without the suite sleeping for RFC-scale seconds.
	return &Client{
		IssuerURL:    srv.URL,
		ClientID:     "armornet-cli",
		HTTPClient:   srv.Client(),
		baseInterval: 20 * time.Millisecond,
	}
}

func TestAuthorizeReturnsCodes(t *testing.T) {
	var gotForm string
	c := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.Form.Encode()
		fmt.Fprint(w, `{"device_code":"dc","user_code":"ABCD-EFGH",
			"verification_uri":"https://a/device","verification_uri_complete":"https://a/device?c=ABCD-EFGH",
			"expires_in":600,"interval":5}`)
	})

	auth, err := c.Authorize(context.Background())
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if auth.UserCode != "ABCD-EFGH" || auth.DeviceCode != "dc" {
		t.Errorf("auth = %+v", auth)
	}
	if auth.VerificationURI == "" {
		t.Error("no verification_uri — the user would have nowhere to go")
	}
	// A public client must not send a secret, and scope must be requested.
	if want := "client_id=armornet-cli"; !contains(gotForm, want) {
		t.Errorf("form %q missing %q", gotForm, want)
	}
	if contains(gotForm, "client_secret") {
		t.Error("a public client must not send a client_secret")
	}
	if !contains(gotForm, "scope=") {
		t.Errorf("form %q requests no scope", gotForm)
	}
}

// An issuer that returns 200 but no device code is broken; treat it as an error
// rather than proceeding to poll with an empty credential.
func TestAuthorizeRejectsEmptyDeviceCode(t *testing.T) {
	c := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"user_code":"ABCD"}`)
	})
	if _, err := c.Authorize(context.Background()); err == nil {
		t.Error("want error when the issuer returns no device code")
	}
}

// The normal path: pending a few times, then success.
func TestWaitPollsUntilApproved(t *testing.T) {
	var calls atomic.Int32
	c := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"authorization_pending"}`)
			return
		}
		fmt.Fprint(w, `{"access_token":"at","refresh_token":"rt","token_type":"Bearer","expires_in":3600}`)
	})

	tok, err := c.Wait(context.Background(), Authorization{DeviceCode: "dc", Interval: 0, ExpiresIn: 60})
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if tok.AccessToken != "at" || tok.RefreshToken != "rt" {
		t.Errorf("token = %+v", tok)
	}
	if calls.Load() < 3 {
		t.Errorf("polled %d times, expected to keep polling while pending", calls.Load())
	}
}

// Refusal and expiry are final states — distinct from each other and from a
// generic failure, because the user needs different advice for each.
func TestWaitTerminalStates(t *testing.T) {
	for _, tc := range []struct {
		oauthErr string
		want     error
	}{
		{"access_denied", ErrAccessDenied},
		{"expired_token", ErrExpired},
	} {
		c := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"error":%q}`, tc.oauthErr)
		})
		_, err := c.Wait(context.Background(), Authorization{DeviceCode: "dc", ExpiresIn: 60})
		if !errors.Is(err, tc.want) {
			t.Errorf("%s → err = %v, want %v", tc.oauthErr, err, tc.want)
		}
	}
}

// slow_down means back off. Polling faster than told gets a client blocked.
func TestWaitBacksOffOnSlowDown(t *testing.T) {
	var calls atomic.Int32
	c := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"slow_down"}`)
			return
		}
		fmt.Fprint(w, `{"access_token":"at"}`)
	})

	start := time.Now()
	if _, err := c.Wait(context.Background(), Authorization{DeviceCode: "dc", Interval: 0, ExpiresIn: 60}); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	// The cadence starts at baseInterval and slow_down adds another, so the
	// retry must be at least twice the base away.
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Errorf("retried after %v — slow_down was ignored", elapsed)
	}
}

// A lapsed code must surface as ErrExpired, not a bare context deadline: the
// user's next step is "run login again", which a generic timeout does not say.
func TestWaitExpiresWithCode(t *testing.T) {
	c := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"authorization_pending"}`)
	})
	_, err := c.Wait(context.Background(), Authorization{DeviceCode: "dc", Interval: 1, ExpiresIn: 1})
	if !errors.Is(err, ErrExpired) {
		t.Errorf("err = %v, want ErrExpired", err)
	}
}

func TestWaitHonoursCancellation(t *testing.T) {
	c := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"authorization_pending"}`)
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()

	_, err := c.Wait(ctx, Authorization{DeviceCode: "dc", Interval: 1, ExpiresIn: 600})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestRefresh(t *testing.T) {
	var gotForm string
	c := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.Form.Encode()
		if r.Form.Get("refresh_token") == "revoked" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid_grant"}`)
			return
		}
		fmt.Fprint(w, `{"access_token":"at2","id_token":"idt2","refresh_token":"rt2","expires_in":300}`)
	})
	tok, err := c.Refresh(context.Background(), "rt1")
	if err != nil || tok.IDToken != "idt2" || tok.RefreshToken != "rt2" {
		t.Fatalf("Refresh = %+v, %v", tok, err)
	}
	if !contains(gotForm, "grant_type=refresh_token") {
		t.Fatalf("form = %q", gotForm)
	}
	if _, err := c.Refresh(context.Background(), "revoked"); !errors.Is(err, ErrRefreshRejected) {
		t.Fatalf("revoked refresh: err = %v, want ErrRefreshRejected", err)
	}
	if _, err := c.Refresh(context.Background(), ""); !errors.Is(err, ErrRefreshRejected) {
		t.Fatalf("empty refresh: err = %v", err)
	}
}

func TestEnvStoreLoad(t *testing.T) {
	t.Setenv(TokenEnvVar, "")
	if _, ok := (EnvStore{}).Load(); ok {
		t.Error("reported a session with no token set")
	}
	t.Setenv(TokenEnvVar, "at")
	t.Setenv(RefreshEnvVar, "rt")
	s, ok := (EnvStore{}).Load()
	if !ok || s.AccessToken != "at" || s.RefreshToken != "rt" {
		t.Errorf("Load = %+v, ok=%v", s, ok)
	}
}

// Save must not silently claim success it cannot deliver — it returns the
// exports for the user to apply.
func TestEnvStoreSaveIsHonestlyReadOnly(t *testing.T) {
	err := EnvStore{}.Save(Session{AccessToken: "at", RefreshToken: "rt"})
	var ro ErrEnvStoreReadOnly
	if !errors.As(err, &ro) {
		t.Fatalf("err = %v, want ErrEnvStoreReadOnly", err)
	}
	if !contains(ro.Exports, TokenEnvVar) || !contains(ro.Exports, "at") {
		t.Errorf("exports %q do not carry the token", ro.Exports)
	}
}

// The ID token is what a host's break-glass access check takes,
// so it must survive the export → env → Load round trip.
func TestEnvStoreCarriesIDToken(t *testing.T) {
	var ro ErrEnvStoreReadOnly
	errors.As(EnvStore{}.Save(Session{AccessToken: "at", IDToken: "idt"}), &ro)
	if !contains(ro.Exports, IDTokenEnvVar+"=idt") {
		t.Fatalf("exports %q omit the ID token", ro.Exports)
	}
	t.Setenv(TokenEnvVar, "at")
	t.Setenv(IDTokenEnvVar, "idt")
	if s, _ := (EnvStore{}).Load(); s.IDToken != "idt" {
		t.Fatalf("Load lost the ID token: %+v", s)
	}
}

func TestSubjectFromToken(t *testing.T) {
	claims, _ := json.Marshal(map[string]string{"sub": "user-1", "email": "a@b.c", "name": "Ada"})
	jwt := "h." + base64.RawURLEncoding.EncodeToString(claims) + ".sig"

	got, err := SubjectFromToken(jwt)
	if err != nil {
		t.Fatalf("SubjectFromToken: %v", err)
	}
	// The subject is what the platform keys on, so it must always be shown.
	if !contains(got, "user-1") {
		t.Errorf("got %q, want the subject included", got)
	}

	for _, bad := range []string{"", "not-a-jwt", "a.b"} {
		if _, err := SubjectFromToken(bad); err == nil {
			t.Errorf("SubjectFromToken(%q) succeeded, want error", bad)
		}
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
