package access

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeVerifier map[string]string // token -> subject

func (f fakeVerifier) VerifySubject(_ context.Context, tok string) (string, error) {
	if s, ok := f[tok]; ok {
		return s, nil
	}
	return "", errors.New("bad token")
}

func newDecider(t *testing.T) *AssertionMinter {
	s, _ := newKey(t, "k1")
	return &AssertionMinter{
		Verify:   fakeVerifier{"god-token": "dex|god", "mortal-token": "dex|mortal"},
		Allow:    func(s string) bool { return s == "dex|god" },
		Keys:     mustKeys(t, s, ""),
		Audience: "god.dev",
	}
}

func post(h http.Handler, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/access/v1/check", strings.NewReader(body)))
	return w
}

func TestCheckHandlerContract(t *testing.T) {
	d := newDecider(t)
	var audited []Decision
	h := CheckHandler(d, func(_ *http.Request, dn Decision) { audited = append(audited, dn) })

	cases := []struct {
		name, body string
		status     int
		errCode    string
	}{
		{"god", `{"subject_token":"god-token","audience":"god.dev","source_agent":"agent:ops:1"}`, 200, ""},
		{"missing token", `{"audience":"god.dev"}`, 401, ReasonInvalidToken},
		{"forged token", `{"subject_token":"forged","audience":"god.dev"}`, 401, ReasonInvalidToken},
		{"not god", `{"subject_token":"mortal-token","audience":"god.dev"}`, 403, ReasonNotAllowed},
		{"wrong audience", `{"subject_token":"god-token","audience":"god.prod"}`, 403, ReasonWrongAudience},
		{"unknown field", `{"subject_token":"god-token","audience":"god.dev","admin":true}`, 400, "bad_request"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := post(h, c.body)
			if w.Code != c.status {
				t.Fatalf("status = %d, want %d (%s)", w.Code, c.status, w.Body)
			}
			var resp checkResponse
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			if resp.Error != c.errCode {
				t.Fatalf("error = %q, want %q", resp.Error, c.errCode)
			}
			for _, sent := range []string{"god-token", "mortal-token", "forged"} {
				if strings.Contains(w.Body.String(), sent) {
					t.Fatalf("response echoes the submitted token: %s", w.Body)
				}
			}
			if c.status == 200 {
				if _, err := d.Keys.Verify(resp.Assertion, "god.dev", time.Now()); err != nil {
					t.Fatalf("minted assertion does not verify: %v", err)
				}
			}
		})
	}
	// Every decided request is audited exactly once; a malformed body never
	// reaches a decision.
	if len(audited) != len(cases)-1 {
		t.Fatalf("audited %d decisions, want %d", len(audited), len(cases)-1)
	}
}

func TestCheckHandlerRefusesOversizeBody(t *testing.T) {
	w := post(CheckHandler(newDecider(t), nil), `{"subject_token":"`+strings.Repeat("a", maxCheckBody)+`"}`)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", w.Code)
	}
}

func TestDecideWithoutSigningKeyIsDisabled(t *testing.T) {
	d := newDecider(t)
	d.Keys = mustKeys(t, "", "")
	if dn := d.Mint(context.Background(), "god-token", "god.dev", ""); dn.Allowed || dn.Reason != ReasonDisabled {
		t.Fatalf("decision = %+v", dn)
	}
}

func TestMiddleware(t *testing.T) {
	d := newDecider(t)
	good := d.Mint(context.Background(), "god-token", "god.dev", "").Assertion
	s2, _ := newKey(t, "k1") // same kid, different key: a forgery
	forged, _, _ := mustKeys(t, s2, "").Mint("dex|god", "god.dev", "", MaxTTL, time.Now())
	stale, _, _ := d.Keys.Mint("dex|god", "god.dev", "", time.Minute, time.Now().Add(-time.Hour))

	var seen string
	h := Middleware(d.Keys, "god.dev", "/healthz")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := ClaimsFrom(r.Context())
		seen = c.Subject
	}))
	for _, c := range []struct {
		name, path, assertion string
		want                  int
	}{
		{"valid", "/api/admin/ping", good, 200},
		{"missing", "/api/admin/ping", "", 401},
		{"forged", "/api/admin/ping", forged, 401},
		{"expired", "/api/admin/ping", stale, 401},
		{"probe exempt", "/healthz", "", 200},
		{"exempt is exact", "/healthz/../api/admin/ping", "", 401},
	} {
		t.Run(c.name, func(t *testing.T) {
			seen = ""
			r := httptest.NewRequest(http.MethodGet, c.path, nil)
			if c.assertion != "" {
				r.Header.Set(Header, c.assertion)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != c.want {
				t.Fatalf("status = %d, want %d", w.Code, c.want)
			}
			if c.name == "valid" && seen != "dex|god" {
				t.Fatalf("claims not on context: %q", seen)
			}
			if w.Code == 401 && w.Body.Len() != 0 {
				t.Fatalf("401 carries a body: %q", w.Body)
			}
		})
	}
}

func TestKeysHandlerPublishesVerifySet(t *testing.T) {
	d := newDecider(t)
	w := httptest.NewRecorder()
	KeysHandler(d.Keys).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/access/v1/keys", nil))
	if !strings.Contains(w.Body.String(), `"kid":"k1"`) || strings.Contains(w.Body.String(), `"d"`) {
		t.Fatalf("jwks = %s", w.Body)
	}
}
