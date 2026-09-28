package web

import (
	"net/http"
	"time"
)

// Cookies lets the host pick names, never attributes: Secure, HttpOnly and
// SameSite=Strict are what make a bearer cookie safe at all.
type Cookies struct {
	// Session carries the opaque session token. Use a __Host- prefix: the
	// browser then forces Secure and Path=/ and forbids Domain.
	Session string
	// PreAuth carries the pre-auth row id for the ten minutes a sign-in is in
	// flight.
	PreAuth string
	// DevMirror names a non-Secure, readable copy of the session cookie set
	// only when Dev is true, for plain-HTTP tooling in local development.
	DevMirror string
	// Dev enables the mirror and the DevSessionHeader fallback. Never in
	// production.
	Dev bool
}

// DefaultCookies is used when Handlers.Cookies is nil.
var DefaultCookies = &Cookies{
	Session:   "__Host-session",
	PreAuth:   "__Host-preauth",
	DevMirror: "session_dev",
}

// DevSessionHeader carries the session token for cross-origin dev clients that
// cannot send the Strict/Secure cookie. Honoured only when Cookies.Dev is true.
const DevSessionHeader = "X-Session-Cookie"

const sessionCookieTTL = 12 * time.Hour

// SessionCookies builds the session cookies without writing them, for callers
// that have no ResponseWriter — an ext_authz filter returns headers instead.
func (c *Cookies) SessionCookies(token string) []*http.Cookie {
	out := []*http.Cookie{{
		Name:     c.Session,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionCookieTTL.Seconds()),
	}}
	if c.Dev {
		// #nosec G124 -- dev-only mirror behind c.Dev; the real session cookie above is HttpOnly+Secure+Strict
		out = append(out, &http.Cookie{
			Name:     c.DevMirror,
			Value:    token,
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(sessionCookieTTL.Seconds()),
		})
	}
	return out
}

// SetSession writes the session cookie (and the dev mirror when enabled).
func (c *Cookies) SetSession(w http.ResponseWriter, token string) {
	for _, ck := range c.SessionCookies(token) {
		http.SetCookie(w, ck)
	}
}

// ClearSession expires the session cookie.
func (c *Cookies) ClearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     c.Session,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	if c.Dev {
		// #nosec G124 -- dev-only mirror behind c.Dev; the real session cookie above is HttpOnly+Secure+Strict
		http.SetCookie(w, &http.Cookie{
			Name:     c.DevMirror,
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
		})
	}
}

// Token also takes DevSessionHeader and the mirror cookie in dev: an extension
// panel on chrome-extension:// never carries the real cookie.
func (c *Cookies) Token(r *http.Request) string {
	if ck, err := r.Cookie(c.Session); err == nil {
		return ck.Value
	}
	if c.Dev {
		if h := r.Header.Get(DevSessionHeader); h != "" {
			return h
		}
		if ck, err := r.Cookie(c.DevMirror); err == nil {
			return ck.Value
		}
	}
	return ""
}

// PreAuthCookie builds the pre-auth cookie without writing it.
func (c *Cookies) PreAuthCookie(id string) *http.Cookie {
	return &http.Cookie{
		Name:     c.PreAuth,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(preAuthTTL.Seconds()),
	}
}

// ExpiredPreAuthCookie builds the pre-auth cookie's expiry without writing it.
func (c *Cookies) ExpiredPreAuthCookie() *http.Cookie {
	return &http.Cookie{
		Name:     c.PreAuth,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	}
}

// SetPreAuth writes the pre-auth cookie.
func (c *Cookies) SetPreAuth(w http.ResponseWriter, id string) {
	http.SetCookie(w, c.PreAuthCookie(id))
}

// ClearPreAuth expires the pre-auth cookie.
func (c *Cookies) ClearPreAuth(w http.ResponseWriter) { http.SetCookie(w, c.ExpiredPreAuthCookie()) }
