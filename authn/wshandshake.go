package authn

import (
	"net/http"
	"strings"
)

// WebSocket auth happens at the GET: tokens ride the subprotocol, never a logged
// query string, and Origin is checked since CORS doesn't gate WebSockets.

// TokenSubprotocolPrefix carries a browser's bearer token, read as Authorization.
const TokenSubprotocolPrefix = "armornet.token." // #nosec G101 -- a prefix name; the token follows it, this is not one

// BearerFromHandshake prefers the Authorization header. "" is not an error:
// anonymous or cookie upgrades are the caller's call.
func BearerFromHandshake(r *http.Request) string {
	if r == nil {
		return ""
	}
	if tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && tok != "" {
		return tok
	}
	for _, proto := range Subprotocols(r) {
		if tok, ok := strings.CutPrefix(proto, TokenSubprotocolPrefix); ok && tok != "" {
			return tok
		}
	}
	return ""
}

// Subprotocols flattens repeated and comma-separated headers, dropping empties
// (a browser never sends one).
func Subprotocols(r *http.Request) []string {
	if r == nil {
		return nil
	}
	var out []string
	for _, header := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, part := range strings.Split(header, ",") {
			if p := strings.TrimSpace(part); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

// HandshakeBearerToken reads the subprotocol ONLY on an upgrade, the one place
// a header is impossible; elsewhere it is BearerToken.
func HandshakeBearerToken(r *http.Request) string {
	if r == nil {
		return ""
	}
	if tok := BearerToken(r); tok != "" {
		return tok
	}
	if !IsWebSocketUpgrade(r) {
		return ""
	}
	return BearerFromHandshake(r)
}

// IsWebSocketUpgrade parses both headers as RFC 9110 lists: proxies append to
// Connection, so equality fails behind them.
func IsWebSocketUpgrade(r *http.Request) bool {
	if r == nil {
		return false
	}
	return headerListContains(r, "Connection", "upgrade") &&
		headerListContains(r, "Upgrade", "websocket")
}

func headerListContains(r *http.Request, header, want string) bool {
	for _, v := range r.Header.Values(header) {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), want) {
				return true
			}
		}
	}
	return false
}

// CheckOrigin refuses foreign Origins whatever the credential; absent passes
// (non-browser). Host only, not scheme: TLS proxies show http:// origins.
func CheckOrigin(r *http.Request, allowed []string) bool {
	if r == nil {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}

	host := originHost(origin)
	if host == "" {
		// An Origin header that will not parse is not a browser being helpful.
		return false
	}
	for _, a := range allowed {
		if a == "" {
			continue
		}
		if strings.EqualFold(host, hostOnly(a)) {
			return true
		}
	}
	return false
}

// SameHostOrigin is the common case: page and socket from one binary, nothing
// to configure.
func SameHostOrigin(r *http.Request) bool {
	if r == nil {
		return false
	}
	return CheckOrigin(r, []string{r.Host})
}

// originHost strips the scheme and any port from an Origin header value.
func originHost(origin string) string {
	s := origin
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	} else {
		// "null" (sandboxed iframe, file://) is opaque and matches nothing.
		return ""
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return hostOnly(s)
}

// hostOnly ignores ports (IPv6 intact): cookies aren't port-scoped, so a port
// check would fake a boundary.
func hostOnly(hostport string) string {
	if strings.HasPrefix(hostport, "[") {
		if i := strings.Index(hostport, "]"); i >= 0 {
			return hostport[:i+1]
		}
		return hostport
	}
	if i := strings.LastIndex(hostport, ":"); i >= 0 {
		return hostport[:i]
	}
	return hostport
}
