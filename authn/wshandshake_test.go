package authn

import (
	"net/http"
	"testing"
)

func handshake(t *testing.T, host string, headers map[string][]string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, "http://"+host+"/v1/line", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	r.Host = host
	for k, vs := range headers {
		for _, v := range vs {
			r.Header.Add(k, v)
		}
	}
	return r
}

func TestBearerFromAuthorizationHeader(t *testing.T) {
	r := handshake(t, "armornet.test", map[string][]string{
		"Authorization": {"Bearer service-agent-token"},
	})
	if got := BearerFromHandshake(r); got != "service-agent-token" {
		t.Fatalf("BearerFromHandshake = %q", got)
	}
}

func TestBearerFromSubprotocol(t *testing.T) {
	r := handshake(t, "armornet.test", map[string][]string{
		"Sec-WebSocket-Protocol": {TokenSubprotocolPrefix + "browser-token, armornet.line.v1"},
	})
	if got := BearerFromHandshake(r); got != "browser-token" {
		t.Fatalf("BearerFromHandshake = %q", got)
	}
}

// The header wins, so a service client that sets both keeps the credential it
// meant to use rather than one a proxy or a library added.
func TestBearerPrefersAuthorizationHeader(t *testing.T) {
	r := handshake(t, "armornet.test", map[string][]string{
		"Authorization":          {"Bearer from-header"},
		"Sec-WebSocket-Protocol": {TokenSubprotocolPrefix + "from-subprotocol"},
	})
	if got := BearerFromHandshake(r); got != "from-header" {
		t.Fatalf("BearerFromHandshake = %q, want the header", got)
	}
}

func TestBearerAbsentIsEmptyNotError(t *testing.T) {
	r := handshake(t, "armornet.test", nil)
	if got := BearerFromHandshake(r); got != "" {
		t.Fatalf("BearerFromHandshake = %q, want empty", got)
	}
}

// An Authorization header that is present but not a Bearer must not be read as
// one, and must fall through rather than shadowing a subprotocol token.
func TestBearerIgnoresNonBearerAuthorization(t *testing.T) {
	r := handshake(t, "armornet.test", map[string][]string{
		"Authorization":          {"Basic dXNlcjpwYXNz"},
		"Sec-WebSocket-Protocol": {TokenSubprotocolPrefix + "real-token"},
	})
	if got := BearerFromHandshake(r); got != "real-token" {
		t.Fatalf("BearerFromHandshake = %q", got)
	}
}

// The prefix with nothing after it is not a token.
func TestBearerIgnoresEmptySubprotocolToken(t *testing.T) {
	r := handshake(t, "armornet.test", map[string][]string{
		"Sec-WebSocket-Protocol": {TokenSubprotocolPrefix + ", armornet.line.v1"},
	})
	if got := BearerFromHandshake(r); got != "" {
		t.Fatalf("BearerFromHandshake = %q, want empty", got)
	}
}

func TestSubprotocolsFlattensRepeatedHeaders(t *testing.T) {
	r := handshake(t, "armornet.test", map[string][]string{
		"Sec-WebSocket-Protocol": {"a, b", "c"},
	})
	got := Subprotocols(r)
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("Subprotocols = %v", got)
	}
}

func TestBearerFromNilRequest(t *testing.T) {
	if got := BearerFromHandshake(nil); got != "" {
		t.Fatalf("BearerFromHandshake(nil) = %q", got)
	}
}

func TestCheckOriginAllowsSameHost(t *testing.T) {
	r := handshake(t, "armornet.test", map[string][]string{
		"Origin": {"https://armornet.test"},
	})
	if !SameHostOrigin(r) {
		t.Fatal("same-host origin was refused")
	}
}

// The attack this exists for: a valid session cookie, sent by a page the user
// did not mean to visit. SameSite=Strict already stops it in a modern browser;
// this stops it on the server, where it does not depend on the client.
func TestCheckOriginRefusesCrossSite(t *testing.T) {
	r := handshake(t, "armornet.test", map[string][]string{
		"Origin": {"https://evil.example"},
	})
	if SameHostOrigin(r) {
		t.Fatal("a cross-site origin was allowed — this is the CSRF hole")
	}
}

// A deployment terminating TLS at a proxy sees http:// origins for an https://
// page. A check that failed on that would be switched off rather than fixed.
func TestCheckOriginIgnoresScheme(t *testing.T) {
	r := handshake(t, "armornet.test", map[string][]string{
		"Origin": {"http://armornet.test"},
	})
	if !SameHostOrigin(r) {
		t.Fatal("scheme mismatch refused a same-host origin")
	}
}

// Cookies are not port-scoped, so refusing on port would imply a boundary the
// cookie does not actually have.
func TestCheckOriginIgnoresPort(t *testing.T) {
	r := handshake(t, "armornet.test:8080", map[string][]string{
		"Origin": {"https://armornet.test:5173"},
	})
	if !SameHostOrigin(r) {
		t.Fatal("port mismatch refused a same-host origin")
	}
}

// A service agent sends no Origin. Refusing it would break every non-browser
// client to defend against a page that is not there.
func TestCheckOriginAllowsAbsentOrigin(t *testing.T) {
	r := handshake(t, "armornet.test", nil)
	if !SameHostOrigin(r) {
		t.Fatal("a headerless (non-browser) handshake was refused")
	}
}

// "null" is what a sandboxed iframe or a file:// page sends. It is an opaque
// origin and matches nothing — treating it as absent would let a sandboxed
// frame through on the non-browser exemption.
func TestCheckOriginRefusesNullOrigin(t *testing.T) {
	r := handshake(t, "armornet.test", map[string][]string{"Origin": {"null"}})
	if SameHostOrigin(r) {
		t.Fatal("an opaque (null) origin was allowed")
	}
}

func TestCheckOriginAllowlist(t *testing.T) {
	r := handshake(t, "internal.svc", map[string][]string{
		"Origin": {"https://console.armornet.test"},
	})
	if !CheckOrigin(r, []string{"app.armornet.test", "console.armornet.test"}) {
		t.Fatal("an allowlisted origin was refused")
	}
	if CheckOrigin(r, []string{"app.armornet.test"}) {
		t.Fatal("a non-allowlisted origin was accepted")
	}
}

func TestCheckOriginCaseInsensitiveHost(t *testing.T) {
	r := handshake(t, "armornet.test", map[string][]string{
		"Origin": {"https://ARMORNET.TEST"},
	})
	if !SameHostOrigin(r) {
		t.Fatal("host comparison was case-sensitive; DNS is not")
	}
}

func TestCheckOriginIPv6(t *testing.T) {
	r := handshake(t, "[::1]:8080", map[string][]string{
		"Origin": {"http://[::1]:5173"},
	})
	if !SameHostOrigin(r) {
		t.Fatal("an IPv6 literal host was mishandled")
	}
}

// A malformed Origin is not a browser being helpful.
func TestCheckOriginRefusesGarbage(t *testing.T) {
	for _, o := range []string{"not-a-url", "://missing-scheme", " "} {
		r := handshake(t, "armornet.test", map[string][]string{"Origin": {o}})
		if SameHostOrigin(r) {
			t.Fatalf("garbage origin %q was allowed", o)
		}
	}
}

func TestCheckOriginNilRequest(t *testing.T) {
	if CheckOrigin(nil, []string{"armornet.test"}) {
		t.Fatal("a nil request was allowed")
	}
}

// An empty allowlist allows nothing — a misconfiguration must fail closed.
func TestCheckOriginEmptyAllowlistFailsClosed(t *testing.T) {
	r := handshake(t, "armornet.test", map[string][]string{
		"Origin": {"https://armornet.test"},
	})
	if CheckOrigin(r, nil) {
		t.Fatal("an empty allowlist allowed a browser origin")
	}
	if CheckOrigin(r, []string{""}) {
		t.Fatal("an allowlist of empty strings allowed a browser origin")
	}
}
