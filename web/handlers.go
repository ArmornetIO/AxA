// Package web is browser sign-in on net/http: /api/auth/* from issuer bounce to
// session cookie, plus MFA. axa/ts is its client; pgstore fills its stores.
package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"time"

	"github.com/ArmornetIO/axa/authn"
)

const preAuthTTL = 10 * time.Minute

// DefaultCSRFHeader matches axa/ts's default. A custom header forces a
// CORS preflight, which is the whole defence: a cross-site form cannot set it.
const DefaultCSRFHeader = "x-armornet-csrf"

// MFAConfig carries the feature flags and WebAuthn relying-party settings. The
// zero value disables MFA.
type MFAConfig struct {
	Enabled         bool
	TOTP            bool
	WebAuthn        bool
	WebAuthnRPID    string
	WebAuthnRPName  string
	WebAuthnOrigins []string
}

// IntentFunc runs in the callback, the only moment the verified email exists:
// identity stores none.
type IntentFunc func(ctx context.Context, subject, email string) error

// SessionView is what DecorateSession is told about the caller.
type SessionView struct {
	Subject string
	OrgID   string
	// ViaAccess is true when the caller arrived with a verified access
	// assertion rather than a cookie (axa/access).
	ViaAccess bool
}

// MFAMethod is a kind of second factor a subject can bind or remove. Not
// webauthnlib.Authenticator, which is one device's attestation data.
type MFAMethod string

const (
	MFATOTP     MFAMethod = "totp"
	MFAWebAuthn MFAMethod = "webauthn"
)

// Label is the method as its holder knows it, for notices.
func (m MFAMethod) Label() string {
	switch m {
	case MFATOTP:
		return "authenticator app"
	case MFAWebAuthn:
		return "passkey"
	}
	return string(m)
}

// Handlers serves the browser sign-in endpoints. Stores and Dex are required;
// everything else is optional.
type Handlers struct {
	PreAuth          authn.PreAuthStore
	Sessions         authn.SessionStore
	MFAChallenges    authn.MFAChallengeStore
	TOTP             authn.TOTPStore
	WebAuthnCreds    authn.WebAuthnCredentialStore
	WebAuthnSessions authn.WebAuthnSessionStore
	MFA              MFAConfig
	Dex              DexClient
	Orgs             authn.OrgStore
	Users            authn.UserStore
	Invites          authn.InviteStore
	DomainAllowlist  authn.DomainAllowlistStore

	IssuerURL   string // base URL of the issuer (e.g. http://127.0.0.1:5556/dex)
	ClientID    string // OIDC client registered with the issuer for this flow
	RedirectURI string // exact callback URI registered with the issuer

	// SelfRegister joins a first sign-in to the login's org. Single-tenant only:
	// multi-tenant, anyone joins any org they name.
	SelfRegister bool
	// SelfRegisterOn, when set, is asked at each first sign-in instead of
	// SelfRegister, so a host can switch self-registration without rebuilding
	// the handlers.
	SelfRegisterOn   func(context.Context) bool
	SelfRegisterRole string // defaults to "member"

	// SignupDomains restricts authentication to these email domains. Empty is
	// unrestricted.
	SignupDomains []string

	// LogoutVerifier validates back-channel logout_token JWTs. Nil answers 501.
	LogoutVerifier LogoutTokenVerifier
	// JTIs guards against logout_token replay. Nil disables replay prevention.
	JTIs JTIStore

	Cookies    *Cookies // nil uses DefaultCookies
	CSRFHeader string   // "" uses DefaultCSRFHeader
	// TOTPIssuer and the WebAuthn RP name are what an authenticator app shows.
	TOTPIssuer string

	// Intents are the sign-in intents the flow accepts besides "". The
	// callback answers each under its own name: "queued" or "failed".
	Intents map[string]IntentFunc

	// StepUp proves an upstream account for a live session and issues none.
	// connectorID is the only one allowed to answer, never the client's choice.
	StepUp func(intent string) (consumer authn.StepUpConsumer, connectorID string, ok bool)

	// IsOperator reports platform-operator standing: such a subject signs into
	// any org without a membership row, and its session reports RoleGodAdmin.
	IsOperator func(subject string) bool

	// OnOrgCreated runs after signup creates an org, before the user is linked
	// — typically the authorization grant. An error fails the sign-in.
	OnOrgCreated func(ctx context.Context, orgID string) error

	// OnSignupCompleted runs once the signing-up user owns the org signup made.
	// An error is logged, never fatal: the account and org already exist.
	OnSignupCompleted func(ctx context.Context, subject, orgID string) error

	// OnSignIn runs after a session is issued to anyone but a first-time
	// signup. The host logs its own failures.
	OnSignIn func(ctx context.Context, subject, orgID string)

	// OnVerifiedEmail runs at every sign-in whose provider vouched for the
	// email, the only moment it is in hand. An error is logged, never fatal.
	OnVerifiedEmail func(ctx context.Context, subject, email string) error

	// OnAuthenticatorChange runs after a second factor is bound to or removed
	// from the subject, so the host can tell the holder (NIST SP 800-63B
	// §4.1.2.1, §4.5). The host logs its own failures.
	OnAuthenticatorChange func(ctx context.Context, subject string, method MFAMethod, added bool)

	// DecorateSession returns the product's own facts, a struct whose JSON
	// fields join the /session payload at the top level.
	DecorateSession func(r *http.Request, s SessionView) any

	// DecorateOrgs returns the product's own facts per org for /orgs, keyed by
	// org id: a struct whose JSON fields join that org's entry. Called once
	// with every org the caller is a member of, so the host can batch.
	DecorateOrgs func(r *http.Request, s SessionView, orgIDs []string) map[string]any
}

// Route is one endpoint. Path uses net/http pattern syntax ({name}); a router
// with other syntax converts it and sets r.SetPathValue for each parameter.
type Route struct {
	Method  string
	Path    string
	Handler http.Handler
	// OperationID keeps the old armornet handler names, so the published spec's
	// ids did not change.
	OperationID string

	// Request is a zero body value for doc generators; its binding:"required"
	// tags are the ones readJSON enforces, so docs and validation agree.
	Request   any
	Responses []Response
}

// Response is one success answer. Body is nil for none, a map for a
// free-form object, or a zero value of a struct type.
type Response struct {
	Status int
	Body   any
}

// object marks a free-form JSON object response.
var object = map[string]any{}

// Routes lists the endpoints this configuration serves, each already wrapped in
// its CSRF and session guards.
func (h *Handlers) Routes() []Route {
	csrf, session := h.requireCSRF, h.requireSession
	ok := func(body any) []Response { return []Response{{Status: http.StatusOK, Body: body}} }
	noContent := []Response{{Status: http.StatusNoContent}}

	type row struct {
		method, path, op string
		fn               http.HandlerFunc
		req              any
		resp             []Response
		guards           []func(http.Handler) http.Handler
	}
	rows := []row{
		{http.MethodPost, "/authorize", "handleAuthorize", h.handleAuthorize, authorizeRequest{}, ok(object), nil},
		{http.MethodPost, "/signup", "handleSignupAuthorize", h.handleSignupAuthorize, signupRequest{}, ok(object), nil},
		// Accepting an invite is this round trip: the callback redeems it with
		// the email the provider just verified, which is never stored for later.
		{http.MethodPost, "/invite-authorize", "handleInviteAuthorize", h.handleInviteAuthorize, inviteAuthorizeRequest{}, ok(object), nil},
		{http.MethodPost, "/callback", "handleCallback", h.handleCallback, callbackRequest{},
			[]Response{{http.StatusOK, object}, {http.StatusAccepted, object}}, g(csrf)},
		{http.MethodGet, "/session", "handleGetSession", h.handleGetSession, nil, ok(object), nil},
		{http.MethodGet, "/orgs", "handleListMyOrgs", h.handleListMyOrgs, nil, ok(object), g(session)},
		{http.MethodPost, "/logout", "handleLogout", h.handleLogout, nil, noContent, g(csrf)},
		// No CSRF guard — back-channel requests come from the issuer, not a browser.
		{http.MethodPost, "/backchannel-logout", "handleBackchannelLogout", h.handleBackchannelLogout, nil, ok(nil), nil},
	}
	if h.MFA.TOTP || h.MFA.WebAuthn {
		rows = append(rows, row{http.MethodGet, "/mfa/status", "handleMFAStatus", h.handleMFAStatus, nil, ok(object), g(session)})
	}
	if h.MFA.TOTP {
		rows = append(rows,
			row{http.MethodPost, "/mfa/totp/setup", "handleTOTPSetup", h.handleTOTPSetup, nil, ok(object), g(csrf, session)},
			row{http.MethodPost, "/mfa/totp/enroll", "handleTOTPEnroll", h.handleTOTPEnroll, totpEnrollRequest{}, noContent, g(csrf, session)},
			row{http.MethodPost, "/mfa/totp/verify", "handleTOTPVerify", h.handleTOTPVerify, totpVerifyRequest{}, ok(object), g(csrf)},
			row{http.MethodDelete, "/mfa/totp", "handleTOTPDelete", h.handleTOTPDelete, nil, noContent, g(csrf, session)},
		)
	}
	if h.MFA.WebAuthn {
		rows = append(rows,
			// The begin steps answer with the WebAuthn library's own option
			// objects, which are the browser API's shape, not ours to document.
			row{http.MethodPost, "/mfa/webauthn/register/begin", "handleWebAuthnRegisterBegin", h.handleWebAuthnRegisterBegin, nil, ok(nil), g(csrf, session)},
			row{http.MethodPost, "/mfa/webauthn/register/finish", "handleWebAuthnRegisterFinish", h.handleWebAuthnRegisterFinish, nil, noContent, g(csrf, session)},
			row{http.MethodPost, "/mfa/webauthn/login/begin", "handleWebAuthnLoginBegin", h.handleWebAuthnLoginBegin, webAuthnLoginBeginRequest{}, ok(nil), g(csrf)},
			row{http.MethodPost, "/mfa/webauthn/login/finish", "handleWebAuthnLoginFinish", h.handleWebAuthnLoginFinish, webAuthnLoginFinishRequest{}, ok(object), g(csrf)},
			row{http.MethodDelete, "/mfa/webauthn/{credential_id}", "handleWebAuthnDelete", h.handleWebAuthnDelete, nil, noContent, g(csrf, session)},
		)
	}

	out := make([]Route, 0, len(rows))
	for _, rw := range rows {
		var hd http.Handler = rw.fn
		for i := len(rw.guards) - 1; i >= 0; i-- {
			hd = rw.guards[i](hd)
		}
		out = append(out, Route{
			Method: rw.method, Path: "/api/auth" + rw.path, Handler: hd,
			OperationID: rw.op, Request: rw.req, Responses: rw.resp,
		})
	}
	return out
}

// Handler serves Routes from one mux, for a host on plain net/http.
func (h *Handlers) Handler() http.Handler {
	mux := http.NewServeMux()
	for _, rt := range h.Routes() {
		mux.Handle(rt.Method+" "+rt.Path, rt.Handler)
	}
	return mux
}

func (h *Handlers) cookies() *Cookies {
	if h.Cookies != nil {
		return h.Cookies
	}
	return DefaultCookies
}

func (h *Handlers) isOperator(subject string) bool {
	return h.IsOperator != nil && h.IsOperator(subject)
}

func (h *Handlers) requireCSRF(next http.Handler) http.Handler {
	name := h.CSRFHeader
	if name == "" {
		name = DefaultCSRFHeader
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(name) != "1" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type sessionKey struct{}

// requireSession resolves the session cookie and stashes the record for
// sessionOf.
func (h *Handlers) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie(h.cookies().Session); err != nil {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		sess, ok := h.SessionFrom(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "session expired")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, sess)))
	})
}

func sessionOf(r *http.Request) authn.SessionRecord {
	s, _ := r.Context().Value(sessionKey{}).(authn.SessionRecord)
	return s
}

// SessionFrom resolves the request's session cookie to a live session.
func (h *Handlers) SessionFrom(r *http.Request) (authn.SessionRecord, bool) {
	ck, err := r.Cookie(h.cookies().Session)
	if err != nil {
		return authn.SessionRecord{}, false
	}
	sess, err := h.Sessions.ByTokenHash(r.Context(), authn.HashSessionToken(ck.Value))
	if err != nil || time.Now().After(sess.ExpiresAt) {
		return authn.SessionRecord{}, false
	}
	return sess, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Error: msg})
}

func g(guards ...func(http.Handler) http.Handler) []func(http.Handler) http.Handler { return guards }

// errMissingField is what readJSON reports when a required field is empty.
var errMissingField = errors.New("missing required field")

// readJSON reads at most 1 MiB and refuses a zero binding:"required" field,
// the contract gin's binding used to give.
func readJSON(r *http.Request, v any) error {
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v); err != nil {
		return err
	}
	rv := reflect.ValueOf(v).Elem()
	for i := range rv.NumField() {
		if rv.Type().Field(i).Tag.Get("binding") == "required" && rv.Field(i).IsZero() {
			return errMissingField
		}
	}
	return nil
}

// Request bodies. Named, because a documentation generator names the schema
// after the type.
type (
	authorizeRequest struct {
		OrgID       string `json:"org_id" binding:"required"`
		ConnectorID string `json:"connector_id" binding:"required"`
		Intent      string `json:"intent"`
	}
	signupRequest struct {
		ConnectorID string `json:"connector_id" binding:"required"`
		Intent      string `json:"intent"`
	}
	inviteAuthorizeRequest struct {
		InviteToken string `json:"invite_token" binding:"required"`
		ConnectorID string `json:"connector_id" binding:"required"`
		Intent      string `json:"intent"`
	}
	callbackRequest struct {
		Code  string `json:"code" binding:"required"`
		State string `json:"state" binding:"required"`
	}
	totpEnrollRequest struct {
		Code string `json:"code" binding:"required"`
	}
	totpVerifyRequest struct {
		ChallengeID string `json:"challenge_id" binding:"required"`
		Code        string `json:"code" binding:"required"`
	}
	webAuthnLoginBeginRequest struct {
		ChallengeID string `json:"challenge_id" binding:"required"`
	}
	webAuthnLoginFinishRequest struct {
		ChallengeID string `json:"challenge_id" binding:"required"`
	}
)

// selfRegister reports whether a first sign-in may join the login's org now.
func (h *Handlers) selfRegister(ctx context.Context) bool {
	if h.SelfRegisterOn != nil {
		return h.SelfRegisterOn(ctx)
	}
	return h.SelfRegister
}
