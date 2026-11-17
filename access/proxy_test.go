package access

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ArmornetIO/axa/authn"
)

type memPreAuth struct {
	mu   sync.Mutex
	rows map[string]authn.PreAuthSession
}

func newMemPreAuth() *memPreAuth {
	return &memPreAuth{rows: map[string]authn.PreAuthSession{}}
}

func (m *memPreAuth) Create(_ context.Context, p authn.PreAuthSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[p.ID] = p
	return nil
}

func (m *memPreAuth) Get(_ context.Context, id string) (authn.PreAuthSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.rows[id]
	if !ok {
		return authn.PreAuthSession{}, authn.ErrNoPreAuthSession
	}
	return p, nil
}

func (m *memPreAuth) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.rows, id)
	return nil
}

func (m *memPreAuth) Purge(context.Context) error { return nil }

type fakeBroker struct {
	target string
	who    Identity
	finish error
	sawPre authn.PreAuthSession
}

func (f *fakeBroker) Start(_ context.Context, pre authn.PreAuthSession) (string, error) {
	f.sawPre = pre
	return f.target, nil
}

func (f *fakeBroker) Finish(context.Context, authn.PreAuthSession, *http.Request) (Identity, error) {
	if f.finish != nil {
		return Identity{}, f.finish
	}
	return f.who, nil
}

type fakeSessions struct {
	subject  Subject
	authed   bool
	issued   *Identity
	issueErr error
}

func (f *fakeSessions) Issue(_ context.Context, id Identity) ([]*http.Cookie, error) {
	if f.issueErr != nil {
		return nil, f.issueErr
	}
	f.issued = &id
	return []*http.Cookie{{Name: "sess", Value: "t"}}, nil
}

func (f *fakeSessions) Read(context.Context, *http.Request) (Subject, bool) {
	return f.subject, f.authed
}

func proxyFor(sess *fakeSessions, broker *fakeBroker) (*Proxy, *memPreAuth) {
	pre := newMemPreAuth()
	return &Proxy{
		Rule: Rule{Declared: true},
		Pipeline: &Pipeline{Evaluators: StandardEvaluators(
			stubGate{deployed: true, accepted: true},
			stubTiers{includes: true},
			stubMeter{},
			stubGraph{},
		)},
		Broker:        broker,
		Sessions:      sess,
		PreAuth:       pre,
		CallbackPath:  "/auth/callback",
		PreAuthCookie: func(id string) *http.Cookie { return &http.Cookie{Name: "pre", Value: id} },
		ReadPreAuth:   func(*http.Request) string { return "pre-1" },
		ClearPreAuth:  func() *http.Cookie { return &http.Cookie{Name: "pre", MaxAge: -1} },
		NewID:         func() string { return "pre-1" },
	}, pre
}

func navigate(path string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	return r
}

func served(p *Proxy, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	p.Guard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("upstream"))
	})).ServeHTTP(w, r)
	return w
}

func TestUnauthenticatedNavigationIsSentToTheProvider(t *testing.T) {
	broker := &fakeBroker{target: "https://idp.example/authorize?x=1"}
	p, pre := proxyFor(&fakeSessions{}, broker)

	w := served(p, navigate("/wiki/page?q=1"))

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	if got := w.Header().Get("Location"); got != broker.target {
		t.Fatalf("Location = %q, want the provider", got)
	}

	row, err := pre.Get(context.Background(), "pre-1")
	if err != nil {
		t.Fatalf("no pre-auth row was written: %v", err)
	}
	if row.State == "" || row.Nonce == "" || row.CodeVerifier == "" {
		t.Fatal("state, nonce and verifier must be generated server-side")
	}
	if row.State == row.Nonce || row.State == row.CodeVerifier {
		t.Fatal("state, nonce and verifier must be independent")
	}
	if row.ReturnTo != "/wiki/page?q=1" {
		t.Fatalf("ReturnTo = %q, want the path the browser was on", row.ReturnTo)
	}
}

// A redirect only helps a top-level navigation: a fetch gets a CORS error that
// reads as an outage, and a POST loses its body.
func TestNonNavigationIsAnsweredNotRedirected(t *testing.T) {
	cases := map[string]func() *http.Request{
		"fetch": func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/wiki/page", nil)
			r.Header.Set("Sec-Fetch-Mode", "cors")
			return r
		},
		"POST claiming navigation": func() *http.Request {
			r := httptest.NewRequest(http.MethodPost, "/wiki/page", strings.NewReader("x=1"))
			r.Header.Set("Sec-Fetch-Mode", "navigate")
			return r
		},
		"no metadata, no Accept": func() *http.Request {
			return httptest.NewRequest(http.MethodGet, "/wiki/page", nil)
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			p, _ := proxyFor(&fakeSessions{}, &fakeBroker{target: "https://idp.example/x"})
			if got := served(p, build()).Code; got != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", got)
			}
		})
	}
}

func TestAuthenticatedCallerGoesThroughThePipeline(t *testing.T) {
	sess := &fakeSessions{subject: Person("11111111-2222-3333-4444-555555555555", "org-a"), authed: true}

	t.Run("permitted reaches what is behind", func(t *testing.T) {
		p, _ := proxyFor(sess, &fakeBroker{})
		w := served(p, navigate("/wiki/page"))
		if w.Code != http.StatusOK || w.Body.String() != "upstream" {
			t.Fatalf("status = %d body = %q", w.Code, w.Body.String())
		}
	})

	// The refusal carries the shared vocabulary, so the proxy is not a second
	// way to be refused.
	t.Run("refused names its condition", func(t *testing.T) {
		p, _ := proxyFor(sess, &fakeBroker{})
		p.Rule = Rule{Declared: true, Relation: "viewer"}
		p.Resource = Resource{Type: "wiki", ID: "w1"}
		p.Pipeline = &Pipeline{Evaluators: StandardEvaluators(
			stubGate{deployed: true, accepted: true}, stubTiers{includes: true}, stubMeter{},
			stubGraph{err: ErrRelationAbsent},
		)}
		w := served(p, navigate("/wiki/page"))
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", w.Code)
		}
		if !strings.Contains(w.Body.String(), ReasonRelationAbsent) {
			t.Fatalf("body = %q, want the reason code", w.Body.String())
		}
	})

	// An undeclared rule denies rather than letting everything through.
	t.Run("no rule declared denies", func(t *testing.T) {
		p, _ := proxyFor(sess, &fakeBroker{})
		p.Rule = Rule{}
		w := served(p, navigate("/wiki/page"))
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", w.Code)
		}
		if !strings.Contains(w.Body.String(), ReasonNoPolicyForRoute) {
			t.Fatalf("body = %q, want %s", w.Body.String(), ReasonNoPolicyForRoute)
		}
	})
}

func TestCallbackIssuesASessionAndReturnsTheBrowser(t *testing.T) {
	sess := &fakeSessions{}
	p, pre := proxyFor(sess, &fakeBroker{who: Identity{Subject: "dex|alice", ConnectorID: "google"}})
	_ = pre.Create(context.Background(), authn.PreAuthSession{ID: "pre-1", ReturnTo: "/wiki/page?q=1"})

	w := httptest.NewRecorder()
	p.CallbackHandler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc", nil))

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/wiki/page?q=1" {
		t.Fatalf("Location = %q, want where the browser was", got)
	}
	if sess.issued == nil || sess.issued.Subject != "dex|alice" {
		t.Fatalf("issued = %+v", sess.issued)
	}
}

// The row is consumed before the exchange, so a replay finds nothing.
func TestReplayedCallbackIsRefused(t *testing.T) {
	p, pre := proxyFor(&fakeSessions{}, &fakeBroker{who: Identity{Subject: "dex|alice"}})
	_ = pre.Create(context.Background(), authn.PreAuthSession{ID: "pre-1", ReturnTo: "/wiki"})

	first := httptest.NewRecorder()
	p.CallbackHandler().ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc", nil))
	if first.Code != http.StatusSeeOther {
		t.Fatalf("first = %d, want 303", first.Code)
	}

	second := httptest.NewRecorder()
	p.CallbackHandler().ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc", nil))
	if second.Code != http.StatusUnauthorized {
		t.Fatalf("replay = %d, want 401", second.Code)
	}
}

func TestCallbackThatFailsVerificationIssuesNoSession(t *testing.T) {
	sess := &fakeSessions{}
	p, pre := proxyFor(sess, &fakeBroker{finish: errors.New("state mismatch")})
	_ = pre.Create(context.Background(), authn.PreAuthSession{ID: "pre-1", ReturnTo: "/wiki"})

	w := httptest.NewRecorder()
	p.CallbackHandler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc", nil))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if sess.issued != nil {
		t.Fatal("a session was issued for a callback that did not verify")
	}
}

// Only the path and query survive the round trip, so a recorded value that
// names an origin cannot send the browser to it.
func TestReturnKeepsOnlyThePath(t *testing.T) {
	p, _ := proxyFor(&fakeSessions{}, &fakeBroker{})

	kept := map[string]string{
		"/":               "/",
		"/wiki/page":      "/wiki/page",
		"/wiki/page?q=1":  "/wiki/page?q=1",
		"/wiki/page#frag": "/wiki/page",
	}
	for in, want := range kept {
		if got := p.returnPath(in); got != want {
			t.Errorf("returnPath(%q) = %q, want %q", in, got, want)
		}
	}

	// Whatever is recorded, the result must be a path on this host: it starts
	// with one slash and not two, since a browser reads "//host" as an origin.
	for _, in := range []string{
		"https://evil.example/steal",
		"//evil.example/steal",
		"/\\evil.example/steal",
		"javascript:alert(1)",
		"wiki/page",
		"",
		"/auth/callback?code=old",
	} {
		got := p.returnPath(in)
		if !strings.HasPrefix(got, "/") || strings.HasPrefix(got, "//") {
			t.Errorf("returnPath(%q) = %q, which is not a path on this host", in, got)
		}
		if strings.HasPrefix(got, p.CallbackPath) {
			t.Errorf("returnPath(%q) = %q, which loops back into the callback", in, got)
		}
	}
}

// Check and Callback must return, not write, or ext_authz and wasm break unseen.
func TestDecisionsAreValuesNotWrites(t *testing.T) {
	p, pre := proxyFor(&fakeSessions{}, &fakeBroker{target: "https://idp.example/authorize"})

	out := p.Check(context.Background(), navigate("/wiki/page"))
	if out.Location != "https://idp.example/authorize" || out.Status != http.StatusSeeOther {
		t.Fatalf("Check = %+v", out)
	}
	if len(out.SetCookies) != 1 || out.SetCookies[0].Name != "pre" {
		t.Fatalf("SetCookies = %+v, want the pre-auth cookie", out.SetCookies)
	}

	_ = pre.Create(context.Background(), authn.PreAuthSession{ID: "pre-1", ReturnTo: "/wiki/page"})
	back := p.Callback(context.Background(), httptest.NewRequest(http.MethodGet, "/auth/callback?code=a", nil))
	if back.Location != "/wiki/page" {
		t.Fatalf("Callback location = %q", back.Location)
	}
	// Expire the pre-auth cookie and set the session, in that order.
	if len(back.SetCookies) != 2 || back.SetCookies[0].MaxAge != -1 || back.SetCookies[1].Name != "sess" {
		t.Fatalf("SetCookies = %+v", back.SetCookies)
	}
}

// The record holds the declared name, never the attacker-influenced path.
func TestRecordCarriesTheDeclaredNameNotThePath(t *testing.T) {
	sink := &countingSink{}
	p, _ := proxyFor(&fakeSessions{subject: Person("u1", "org-a"), authed: true}, &fakeBroker{})
	p.Name = "internal-wiki"
	p.Pipeline.Sink = sink

	served(p, navigate("/wiki/page?token=secret"))

	if len(sink.emitted) != 1 {
		t.Fatalf("emitted %d records", len(sink.emitted))
	}
	got := sink.emitted[0].Action.Pattern
	if got != "internal-wiki" {
		t.Fatalf("Action.Pattern = %q, want the declared name", got)
	}
}

// An unset CallbackPath must not prefix-match every path and send all logins
// back to the root.
func TestUnsetCallbackPathDoesNotSwallowEveryReturn(t *testing.T) {
	p, _ := proxyFor(&fakeSessions{}, &fakeBroker{})
	p.CallbackPath = ""
	if got := p.returnPath("/wiki/page"); got != "/wiki/page" {
		t.Fatalf("returnPath = %q, want the recorded path", got)
	}
}
