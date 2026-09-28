package access

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ArmornetIO/identity/authn"
)

// The identity-aware proxy sends a token-less browser to sign in (a 401 leaves
// it nowhere). Check and Callback RETURN, so every adapter shares one decision.

// Result is what a transport must do with a request.
type Result struct {
	Allow bool
	// Status and Location apply when Allow is false. Location is set only for
	// a redirect status.
	Status   int
	Location string
	// Reason is from the shared vocabulary, for the body and the record.
	Reason string
	// SetCookies must be written as Set-Cookie regardless of Allow: the
	// callback allows AND issues a session.
	SetCookies []*http.Cookie
}

// Identity is who the upstream says this is. The subject and nothing else —
// this module stores no PII, and an email is neither stable nor needed.
type Identity struct {
	Subject     string
	ConnectorID string
}

// Broker runs the round trip against the upstream provider.
type Broker interface {
	// Start returns where to send the browser. State, nonce and the PKCE
	// verifier come from the row, never from the client.
	Start(ctx context.Context, pre authn.PreAuthSession) (string, error)
	// Finish exchanges the callback, checking it against the row this server
	// wrote before the redirect.
	Finish(ctx context.Context, pre authn.PreAuthSession, r *http.Request) (Identity, error)
}

// Sessions is the browser credential. Issue returns the cookie rather than
// writing it, so a transport with no ResponseWriter can still carry it.
type Sessions interface {
	Issue(ctx context.Context, id Identity) ([]*http.Cookie, error)
	Read(ctx context.Context, r *http.Request) (Subject, bool)
}

// PreAuthTTL bounds a round trip: long enough for a password manager and an MFA
// prompt, short enough that an abandoned flow is not a row sitting around.
const PreAuthTTL = 10 * time.Minute

// Proxy guards one hostname, so no return-target validation: only a path, which
// cannot name an origin, crosses the round trip.
type Proxy struct {
	// Name is what the record carries, never the raw path.
	Name string
	// Rule is what must be true once the caller is authenticated. The zero
	// value is undeclared, which denies.
	Rule     Rule
	Resource Resource

	Pipeline *Pipeline
	Broker   Broker
	Sessions Sessions
	PreAuth  authn.PreAuthStore

	// CallbackPath must be reachable unauthenticated, or the flow deadlocks on
	// its own front door.
	CallbackPath string
	// Connector skips the provider's picker. Empty lets it ask.
	Connector string

	// Cookie framing is the host's: name, flags and domain are deployment facts.
	PreAuthCookie func(id string) *http.Cookie
	ClearPreAuth  func() *http.Cookie
	ReadPreAuth   func(r *http.Request) string

	Now   func() time.Time
	NewID func() string
}

// Check decides one request bound for whatever is behind the proxy.
func (p *Proxy) Check(ctx context.Context, r *http.Request) Result {
	subject, authed := p.Sessions.Read(ctx, r)
	if !authed {
		return p.start(ctx, r)
	}
	d := p.Pipeline.Authorize(ctx, Request{
		Subject:  subject,
		Action:   Action{Method: r.Method, Pattern: p.Name},
		Resource: p.Resource,
		Rule:     p.Rule,
		Origin:   originOf(r),
	})
	if d.Outcome == Permit {
		return Result{Allow: true, Reason: d.Reason}
	}
	status := http.StatusForbidden
	if d.Outcome == Unavailable {
		status = http.StatusServiceUnavailable
	}
	return Result{Status: status, Reason: d.Reason}
}

func (p *Proxy) start(ctx context.Context, r *http.Request) Result {
	// Only navigations redirect: a fetch gets a CORS error, a POST loses its body.
	if !isNavigation(r) {
		return Result{Status: http.StatusUnauthorized, Reason: ReasonInvalidToken}
	}

	pre := authn.PreAuthSession{
		ID:          p.newID(),
		ConnectorID: p.Connector,
		ExpiresAt:   p.now().Add(PreAuthTTL),
		ReturnTo:    r.URL.RequestURI(),
	}

	var err error
	if pre.State, err = authn.RandomToken(); err != nil {
		return unavailable()
	}
	if pre.Nonce, err = authn.RandomToken(); err != nil {
		return unavailable()
	}
	if pre.CodeVerifier, err = authn.RandomToken(); err != nil {
		return unavailable()
	}
	if err := p.PreAuth.Create(ctx, pre); err != nil {
		return unavailable()
	}
	target, err := p.Broker.Start(ctx, pre)
	if err != nil {
		return unavailable()
	}

	return Result{
		Status:     http.StatusSeeOther,
		Location:   target,
		Reason:     ReasonInvalidToken,
		SetCookies: []*http.Cookie{p.PreAuthCookie(pre.ID)},
	}
}

// Callback finishes the round trip.
func (p *Proxy) Callback(ctx context.Context, r *http.Request) Result {
	id := p.ReadPreAuth(r)
	if id == "" {
		return Result{Status: http.StatusUnauthorized, Reason: ReasonInvalidToken}
	}
	pre, err := p.PreAuth.Get(ctx, id)
	if err != nil {
		// Unknown and expired answer the same, so neither can be probed for.
		return Result{Status: http.StatusUnauthorized, Reason: ReasonInvalidToken}
	}
	// Consumed before the exchange, so a replay still in flight finds nothing.
	_ = p.PreAuth.Delete(ctx, pre.ID)
	cleared := p.ClearPreAuth()

	who, err := p.Broker.Finish(ctx, pre, r)
	if err != nil {
		return Result{
			Status: http.StatusUnauthorized, Reason: ReasonInvalidToken,
			SetCookies: []*http.Cookie{cleared},
		}
	}
	session, err := p.Sessions.Issue(ctx, who)
	if err != nil {
		return Result{
			Status: http.StatusForbidden, Reason: ReasonSubjectNotRepresentable,
			SetCookies: []*http.Cookie{cleared},
		}
	}
	return Result{
		Status:     http.StatusSeeOther,
		Location:   p.returnPath(pre.ReturnTo),
		Reason:     ReasonOK,
		SetCookies: append([]*http.Cookie{cleared}, session...),
	}
}

// returnPath keeps only the path and query, so what comes back is always a
// place on this host. Returning to the callback itself would loop.
func (p *Proxy) returnPath(recorded string) string {
	u, err := url.Parse(recorded)
	if err != nil || !strings.HasPrefix(u.Path, "/") {
		return "/"
	}
	// Guarded: an unset CallbackPath would otherwise prefix-match everything
	// and send every login back to the root.
	if p.CallbackPath != "" && strings.HasPrefix(u.Path, p.CallbackPath) {
		return "/"
	}
	out := url.URL{Path: u.Path, RawQuery: u.RawQuery}
	return out.String()
}

func isNavigation(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" {
		return mode == "navigate"
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

func unavailable() Result {
	return Result{Status: http.StatusServiceUnavailable, Reason: ReasonDisabled}
}

func (p *Proxy) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now().UTC()
}

func (p *Proxy) newID() string {
	if p.NewID != nil {
		return p.NewID()
	}
	id, _ := authn.RandomToken()
	return id
}

func originOf(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
