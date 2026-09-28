package access

import "net/http"

// The in-process adapter, one of three (with ext_authz and proxy-wasm) applying
// the same Result. Nothing below decides anything.

// Guard forces upstream authentication before a request reaches next.
func (p *Proxy) Guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if Apply(w, p.Check(r.Context(), r)) {
			next.ServeHTTP(w, r)
		}
	})
}

// CallbackHandler serves CallbackPath.
func (p *Proxy) CallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Apply(w, p.Callback(r.Context(), r))
	})
}

// Apply writes a Result and reports whether the request may proceed.
func Apply(w http.ResponseWriter, res Result) bool {
	for _, c := range res.SetCookies {
		if c != nil {
			http.SetCookie(w, c)
		}
	}
	if res.Allow {
		return true
	}
	w.Header().Set("Cache-Control", "no-store")
	if res.Location != "" {
		w.Header().Set("Location", res.Location)
	}
	w.WriteHeader(res.Status)
	// The reason code, not prose: a client branches on it, and the three
	// transports would otherwise each invent their own wording.
	_, _ = w.Write([]byte(res.Reason))
	return false
}
