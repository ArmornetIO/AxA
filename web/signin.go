package web

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/ArmornetIO/axa/access"
	"github.com/ArmornetIO/axa/authn"
)

// errUnableToAuthenticate hides the real reason, which would enable account or
// membership enumeration; the cause is only logged.
const errUnableToAuthenticate = "unable to authenticate"

func (h *Handlers) validIntent(s string) bool {
	if s == "" {
		return true
	}
	_, ok := h.Intents[s]
	return ok
}

func (h *Handlers) stepUp(intent string) (authn.StepUpConsumer, string, bool) {
	if h.StepUp == nil {
		return nil, "", false
	}
	return h.StepUp(intent)
}

// rejectUnknownIntent answers 400 for an intent outside the allowlist and
// reports whether it did.
func (h *Handlers) rejectUnknownIntent(w http.ResponseWriter, intent string) bool {
	if h.validIntent(intent) {
		return false
	}
	writeError(w, http.StatusBadRequest, "unknown intent")
	return true
}

func (h *Handlers) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	var req authorizeRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "org_id and connector_id required")
		return
	}
	if h.rejectUnknownIntent(w, req.Intent) {
		return
	}
	ctx := r.Context()

	exists, err := h.Orgs.OrgExists(ctx, req.OrgID)
	if err != nil || !exists {
		writeError(w, http.StatusBadRequest, "unknown org_id")
		return
	}
	connectors, err := h.Orgs.ListConnectorIDs(ctx, req.OrgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list connectors")
		return
	}
	if !slices.Contains(connectors, req.ConnectorID) {
		writeError(w, http.StatusBadRequest, "unknown connector_id")
		return
	}
	if u, ok := h.startFlow(w, r, authn.PreAuthSession{
		OrgID: req.OrgID, ConnectorID: req.ConnectorID, Intent: req.Intent,
	}, BrowserScopeParam()); ok {
		writeJSON(w, http.StatusOK, redirectResponse{RedirectURL: u})
	}
}

func (h *Handlers) handleSignupAuthorize(w http.ResponseWriter, r *http.Request) {
	var req signupRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "connector_id required")
		return
	}
	if h.rejectUnknownIntent(w, req.Intent) {
		return
	}
	global, err := h.Orgs.IsGlobalConnector(r.Context(), req.ConnectorID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to check connector")
		return
	}
	if !global {
		writeError(w, http.StatusBadRequest, "connector_id is not available for self-service signup")
		return
	}
	if u, ok := h.startFlow(w, r, authn.PreAuthSession{
		ConnectorID: req.ConnectorID, IsSignup: true, Intent: req.Intent,
	}, BrowserScopeParam()); ok {
		writeJSON(w, http.StatusOK, redirectResponse{RedirectURL: u})
	}
}

func (h *Handlers) handleInviteAuthorize(w http.ResponseWriter, r *http.Request) {
	if h.Invites == nil {
		writeError(w, http.StatusServiceUnavailable, "invite store not configured")
		return
	}
	var req inviteAuthorizeRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invite_token and connector_id required")
		return
	}
	if h.rejectUnknownIntent(w, req.Intent) {
		return
	}
	ctx := r.Context()

	inv, err := h.Invites.ByToken(ctx, req.InviteToken)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invite not found")
		return
	}
	if inv.RevokedAt != nil {
		writeError(w, http.StatusForbidden, "invite has been revoked")
		return
	}
	if time.Now().After(inv.ExpiresAt) {
		writeError(w, http.StatusForbidden, "invite has expired")
		return
	}
	if inv.Kind == "user" && inv.AcceptedAt != nil {
		writeError(w, http.StatusForbidden, "invite has already been used")
		return
	}

	connectors, err := h.Orgs.ListConnectorIDs(ctx, inv.OrgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list connectors")
		return
	}
	// The globals are already in the list unless the org turned one off, and
	// then an invitee may not use it either.
	if !slices.Contains(connectors, req.ConnectorID) {
		writeError(w, http.StatusBadRequest, "unknown connector_id")
		return
	}
	if u, ok := h.startFlow(w, r, authn.PreAuthSession{
		OrgID: inv.OrgID, ConnectorID: req.ConnectorID, InviteID: inv.ID, Intent: req.Intent,
	}, BrowserScopeParam()); ok {
		writeJSON(w, http.StatusOK, redirectResponse{RedirectURL: u})
	}
}

// StartStepUp returns the issuer URL; the host mounts it on an AUTHENTICATED
// route its policy guards. On failure it has already answered.
func (h *Handlers) StartStepUp(w http.ResponseWriter, r *http.Request, orgID, connectorID, intent string) (string, bool) {
	consumer, pinned, ok := h.stepUp(intent)
	if !ok {
		writeError(w, http.StatusBadRequest, "unknown intent")
		return "", false
	}
	if consumer == nil {
		writeError(w, http.StatusServiceUnavailable, "not_configured")
		return "", false
	}
	if connectorID != pinned {
		writeError(w, http.StatusBadRequest, "unknown connector")
		return "", false
	}
	connectors, err := h.Orgs.ListConnectorIDs(r.Context(), orgID)
	if err != nil || !slices.Contains(connectors, pinned) {
		writeError(w, http.StatusServiceUnavailable, "not_configured")
		return "", false
	}
	return h.startFlow(w, r, authn.PreAuthSession{
		OrgID: orgID, ConnectorID: pinned, Intent: intent,
	}, StepUpScopeParam())
}

// startFlow mints state, nonce and PKCE, sets the pre-auth cookie and returns
// the authorize URL. On failure it has already answered.
func (h *Handlers) startFlow(w http.ResponseWriter, r *http.Request, pre authn.PreAuthSession, scope string) (string, bool) {
	var err error
	for _, p := range []*string{&pre.State, &pre.Nonce, &pre.CodeVerifier} {
		if *p, err = RandBase64URL(32); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to start sign-in")
			return "", false
		}
	}
	pre.ID = uuid.New().String()
	pre.CreatedAt = time.Now()
	pre.ExpiresAt = pre.CreatedAt.Add(preAuthTTL)
	if err := h.PreAuth.Create(r.Context(), pre); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create pre-auth session")
		return "", false
	}
	h.cookies().SetPreAuth(w, pre.ID)

	params := url.Values{
		"client_id":             {h.ClientID},
		"redirect_uri":          {h.RedirectURI},
		"response_type":         {"code"},
		"scope":                 {scope},
		"state":                 {pre.State},
		"nonce":                 {pre.Nonce},
		"code_challenge":        {S256Challenge(pre.CodeVerifier)},
		"code_challenge_method": {"S256"},
		"connector_id":          {pre.ConnectorID},
	}
	return h.IssuerURL + "/auth?" + params.Encode(), true
}

func constEqual(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func (h *Handlers) handleCallback(w http.ResponseWriter, r *http.Request) {
	ck, err := r.Cookie(h.cookies().PreAuth)
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing pre-auth cookie")
		return
	}
	preAuthID := ck.Value
	defer h.PreAuth.Delete(r.Context(), preAuthID) //nolint:errcheck

	var req callbackRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "code and state required")
		return
	}
	ctx := r.Context()

	preauth, err := h.PreAuth.Get(ctx, preAuthID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid pre-auth session")
		return
	}
	if !constEqual(req.State, preauth.State) {
		writeError(w, http.StatusBadRequest, "state mismatch")
		return
	}

	tokens, err := h.Dex.Exchange(ctx, req.Code, preauth.CodeVerifier)
	if err != nil {
		// The response says nothing; the log names invalid_grant, invalid_client
		// or PKCE, or this is undebuggable.
		slog.ErrorContext(ctx, "auth: code exchange failed", "err", err, "client_id", h.ClientID)
		writeError(w, http.StatusBadGateway, "token exchange failed")
		return
	}
	claims, err := h.Dex.ValidateIDToken(ctx, tokens.IDToken)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid ID token")
		return
	}
	if !constEqual(claims.Nonce, preauth.Nonce) {
		writeError(w, http.StatusBadRequest, "nonce mismatch")
		return
	}

	// Before the signup gate, MFA and session issue: a step-up proves an
	// upstream account for a session that already exists, and must not touch it.
	if _, _, isStepUp := h.stepUp(preauth.Intent); isStepUp {
		h.finishStepUp(w, r, preauth, claims)
		return
	}

	// The browser picks the connector, so without this another org's connector
	// could answer for this one. Missing means refused.
	if claims.ConnectorID == "" || !constEqual(claims.ConnectorID, preauth.ConnectorID) {
		slog.WarnContext(ctx, "auth: token from unexpected connector",
			"requested", preauth.ConnectorID, "answered", claims.ConnectorID, "org_id", preauth.OrgID)
		writeError(w, http.StatusForbidden, errUnableToAuthenticate)
		return
	}

	// Gate before ANY row is written: past this point the handler creates an
	// org and upserts a user, so rejecting later would leave the account behind.
	if !SignupDomainAllowed(h.SignupDomains, claims.Email) {
		slog.WarnContext(ctx, "auth: rejected by single-domain mode",
			"subject", claims.Subject, "domain", ExtractDomain(claims.Email))
		writeError(w, http.StatusForbidden, errUnableToAuthenticate)
		return
	}

	resolvedOrgID := preauth.OrgID
	// Signup is also sign-in (/login uses it): an existing member is signed in,
	// to their only org or org-less for /workspaces, not given another org.
	returning := false
	if preauth.IsSignup {
		scope, err := h.Users.ResolveOrgScope(ctx, claims.Subject)
		if err != nil {
			slog.ErrorContext(ctx, "signup: resolve org scope", "err", err, "subject", claims.Subject)
			writeError(w, http.StatusInternalServerError, errUnableToAuthenticate)
			return
		}
		returning = len(scope.Memberships) > 0
		if len(scope.Memberships) == 1 {
			resolvedOrgID = scope.Memberships[0].OrgID
		}
	}
	if preauth.IsSignup && !returning {
		orgID := uuid.New().String()
		if err := h.Orgs.CreateOrg(ctx, authn.Organization{ID: orgID, Name: "My Workspace", Slug: orgID}); err != nil {
			slog.ErrorContext(ctx, "create org", "err", err, "org_id", orgID)
			writeError(w, http.StatusInternalServerError, "failed to create org")
			return
		}
		if h.OnOrgCreated != nil {
			if err := h.OnOrgCreated(ctx, orgID); err != nil {
				writeError(w, http.StatusInternalServerError, "resource created but authorization grant failed; contact support")
				return
			}
		}
		resolvedOrgID = orgID
	}

	userID, err := h.Users.UpsertUser(ctx, authn.UserRecord{Subject: claims.Subject, Email: claims.Email})
	if err != nil {
		slog.ErrorContext(ctx, "upsert user", "err", err, "subject", claims.Subject)
		writeError(w, http.StatusInternalServerError, "failed to upsert user")
		return
	}
	if claims.EmailVerified && claims.Email != "" && h.OnVerifiedEmail != nil {
		if err := h.OnVerifiedEmail(ctx, claims.Subject, claims.Email); err != nil {
			slog.WarnContext(ctx, "auth: verified-email hook failed", "subject", claims.Subject, "err", err)
		}
	}

	switch {
	case returning:
		slog.InfoContext(ctx, "auth: signup resolved to sign-in",
			"subject", claims.Subject, "org_id", resolvedOrgID, "connector_id", preauth.ConnectorID)
	case preauth.IsSignup:
		if err := h.Users.LinkOrgUser(ctx, resolvedOrgID, userID, "owner"); err != nil {
			slog.ErrorContext(ctx, "link org user on signup", "err", err, "org_id", resolvedOrgID)
			writeError(w, http.StatusInternalServerError, "failed to link org")
			return
		}
		// Counted here, not at /signup: that only starts the round trip, and
		// anyone who bounces off the provider's consent screen would inflate it.
		RecordSignup(ctx, preauth.ConnectorID)
		if h.OnSignupCompleted != nil {
			if err := h.OnSignupCompleted(ctx, claims.Subject, resolvedOrgID); err != nil {
				slog.WarnContext(ctx, "auth: signup-completed hook failed", "subject", claims.Subject, "org_id", resolvedOrgID, "err", err)
			}
		}
		slog.InfoContext(ctx, "auth: signup completed",
			"subject", claims.Subject, "org_id", resolvedOrgID, "connector_id", preauth.ConnectorID)
	case preauth.InviteID != "":
		orgID, err := RedeemInvite(ctx, h.Invites, h.Users, claims.Email, claims.EmailVerified, userID, preauth.InviteID)
		if err != nil {
			slog.WarnContext(ctx, "invite redemption failed", "err", err, "invite_id", preauth.InviteID)
			writeError(w, inviteHTTPStatus(err), err.Error())
			return
		}
		resolvedOrgID = orgID
	default:
		if h.isOperator(claims.Subject) {
			break
		}
		_, err := h.Users.GetOrgRole(ctx, claims.Subject, resolvedOrgID)
		// Both mean "no membership row"; matching only one made the join
		// fallbacks unreachable for a first-time invitee.
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, authn.ErrNoMembership) {
			if TryDomainAutoJoin(ctx, h.DomainAllowlist, h.Users, claims.Email, claims.EmailVerified, resolvedOrgID, userID) != nil &&
				TrySelfRegister(ctx, h.Users, h.selfRegister(ctx), resolvedOrgID, userID, h.SelfRegisterRole) != nil {
				// An invitee needs a session before a membership; an org-less one
				// is inert, since every org-scoped route refuses it.
				slog.InfoContext(ctx, "auth: org-less session — no membership yet",
					"org_id", resolvedOrgID, "subject", claims.Subject)
				resolvedOrgID = ""
			}
		} else if err != nil {
			slog.WarnContext(ctx, "org membership check", "err", err, "org_id", resolvedOrgID)
			writeError(w, http.StatusForbidden, errUnableToAuthenticate)
			return
		}
	}

	// Before the MFA challenge, like invite redemption: the verified email
	// exists only in this request.
	intentKey, intentResult := h.runIntent(ctx, preauth.Intent, claims.Subject, claims.Email)

	if h.MFA.Enabled && h.MFAChallenges != nil {
		enrolled, err := h.isMFAEnrolled(ctx, claims.Subject)
		if err != nil {
			slog.ErrorContext(ctx, "mfa: enrollment check failed", "err", err, "subject", claims.Subject)
			writeError(w, http.StatusInternalServerError, "mfa check failed")
			return
		}
		if enrolled {
			challengeID, methods, err := h.issueMFAChallenge(ctx, claims.Subject, resolvedOrgID, tokens.Expiry)
			if err != nil {
				slog.ErrorContext(ctx, "mfa: challenge issue failed", "err", err, "subject", claims.Subject)
				writeError(w, http.StatusInternalServerError, "mfa challenge failed")
				return
			}
			slog.InfoContext(ctx, "mfa: challenge issued", "subject", claims.Subject, "org_id", resolvedOrgID)
			resp := map[string]any{"mfa_required": true, "challenge_id": challengeID, "methods": methods}
			if intentKey != "" {
				resp[intentKey] = intentResult
			}
			writeJSON(w, http.StatusAccepted, resp)
			return
		}
	}

	// The cookie carries sessToken, never the id; only its digest is stored.
	sessToken := uuid.New().String()
	sess := authn.SessionRecord{
		ID:          uuid.New().String(),
		Subject:     claims.Subject,
		OrgID:       resolvedOrgID,
		ConnectorID: claims.ConnectorID, // who answered; equal to preauth's only because of the check above
		ExpiresAt:   tokens.Expiry,
	}
	if err := h.Sessions.Create(ctx, sess, sessToken); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	// Retire the prior session (anti-fixation). After Create, so a failed
	// sign-in never costs someone the session they had.
	if old, err := r.Cookie(h.cookies().Session); err == nil && old.Value != sessToken {
		h.recordRotation(ctx, old.Value, claims.Subject)
		_ = h.Sessions.Delete(ctx, old.Value)
	}

	h.cookies().SetSession(w, sessToken)
	h.cookies().ClearPreAuth(w)

	firstLogin := preauth.IsSignup && !returning
	if !firstLogin && h.OnSignIn != nil {
		h.OnSignIn(ctx, claims.Subject, resolvedOrgID)
	}

	resp := map[string]any{
		"subject":       claims.Subject,
		"org_id":        resolvedOrgID,
		"authenticated": true,
		"first_login":   firstLogin,
	}
	if intentKey != "" {
		resp[intentKey] = intentResult
	}
	writeJSON(w, http.StatusOK, resp)
}

// runIntent reports failure but never fails the sign-in over it. Never logs
// the email.
func (h *Handlers) runIntent(ctx context.Context, intent, subject, email string) (key, result string) {
	if intent == "" {
		return "", ""
	}
	fn := h.Intents[intent]
	if fn == nil {
		slog.WarnContext(ctx, "auth: intent with no handler", "intent", intent, "subject", subject)
		return intent, "failed"
	}
	if err := fn(ctx, subject, email); err != nil {
		slog.WarnContext(ctx, "auth: intent from callback failed", "intent", intent, "subject", subject, "err", err)
		return intent, "failed"
	}
	return intent, "queued"
}

// finishStepUp requires the session's org to match the flow's, binding the
// proof to the browser and org that asked.
func (h *Handlers) finishStepUp(w http.ResponseWriter, r *http.Request, pre authn.PreAuthSession, claims *IDTokenClaims) {
	ctx := r.Context()
	h.cookies().ClearPreAuth(w)

	sess, ok := h.SessionFrom(r)
	if !ok || sess.OrgID != pre.OrgID {
		writeError(w, http.StatusUnauthorized, "proof_expired")
		return
	}
	consumer, connector, _ := h.stepUp(pre.Intent)
	// Both the row and the token must name the pinned connector: the row says
	// what we asked for, the token says who actually answered.
	if consumer != nil && (pre.ConnectorID != connector || claims.ConnectorID != connector) {
		slog.WarnContext(ctx, "auth: step-up from unexpected connector",
			"intent", pre.Intent, "requested", pre.ConnectorID, "answered", claims.ConnectorID)
		writeError(w, http.StatusUnauthorized, "proof_expired")
		return
	}
	if consumer == nil || claims.UpstreamUserID == "" {
		slog.WarnContext(ctx, "auth: step-up without consumer or upstream id", "intent", pre.Intent)
		writeError(w, http.StatusServiceUnavailable, "not_configured")
		return
	}
	returnTo := consumer(ctx, w, authn.UpstreamProof{
		ConnectorID:    claims.ConnectorID,
		UpstreamUserID: claims.UpstreamUserID,
		Username:       claims.Username,
		SessionSubject: sess.Subject,
		OrgID:          sess.OrgID,
	})
	writeJSON(w, http.StatusOK, stepUpResponse{StepUp: true, ReturnTo: returnTo})
}

type redirectResponse struct {
	RedirectURL string `json:"redirect_url"`
}

type stepUpResponse struct {
	StepUp   bool   `json:"step_up"`
	ReturnTo string `json:"return_to"`
}

// Orgs holds an orgEntry each, flattened with the host's facts for that org
// when DecorateOrgs is set.
type orgsResponse struct {
	Orgs        []any  `json:"orgs"`
	ActiveOrgID string `json:"active_org_id"`
}

// Name and Slug are omitted when the org lookup failed; the id alone is enough
// to switch.
type orgEntry struct {
	OrgID string `json:"org_id"`
	Role  string `json:"role"`
	Name  string `json:"name,omitempty"`
	Slug  string `json:"slug,omitempty"`
}

// recordRotation logs the discarded session; otherwise a fixation attempt and a
// workspace switch both leave no trace.
func (h *Handlers) recordRotation(ctx context.Context, priorToken, newSubject string) {
	prior, err := h.Sessions.ByTokenHash(ctx, authn.HashSessionToken(priorToken))
	outcome := ClassifyRotation(prior, err, newSubject, time.Now())
	RecordSessionRotation(ctx, outcome)
	switch outcome {
	case RotationUnknown:
		slog.InfoContext(ctx, "auth: sign-in displaced a cookie naming no live session",
			"outcome", outcome, "subject", newSubject)
	case RotationSubjectMismatch:
		// A shared machine does this too, so it warns rather than refusing.
		slog.WarnContext(ctx, "auth: sign-in displaced a live session belonging to a different subject",
			"outcome", outcome, "subject", newSubject,
			"displaced_subject", prior.Subject, "displaced_session_id", prior.ID)
	}
}

// ClassifyRotation treats an expired row as unknown: ByTokenHash ignores
// expiry, and a stale cookie on a shared machine must not page as an attack.
func ClassifyRotation(prior authn.SessionRecord, lookupErr error, newSubject string, now time.Time) string {
	if lookupErr != nil || now.After(prior.ExpiresAt) {
		return RotationUnknown
	}
	if prior.Subject == newSubject {
		return RotationSelf
	}
	return RotationSubjectMismatch
}

// orgsGetter is optional on Handlers.Orgs, so a host's own OrgStore keeps
// compiling: one that reads many orgs at once lists /orgs in one query
// instead of one per membership. pgstore.OrgStore has it.
type orgsGetter interface {
	GetOrgs(ctx context.Context, ids []string) ([]authn.Organization, error)
}

// orgsByID reads the orgs in ids; one that cannot be read is absent, and its
// entry lists without a name.
func (h *Handlers) orgsByID(ctx context.Context, ids []string) map[string]authn.Organization {
	out := make(map[string]authn.Organization, len(ids))
	if h.Orgs == nil {
		return out
	}
	if g, ok := h.Orgs.(orgsGetter); ok {
		orgs, err := g.GetOrgs(ctx, ids)
		if err != nil {
			slog.WarnContext(ctx, "list orgs: names unavailable", "err", err)
		}
		for _, org := range orgs {
			out[org.ID] = org
		}
		return out
	}
	for _, id := range ids {
		if org, err := h.Orgs.GetOrg(ctx, id); err == nil {
			out[id] = org
		}
	}
	return out
}

// handleListMyOrgs reads memberships: its caller is the one with no session org.
func (h *Handlers) handleListMyOrgs(w http.ResponseWriter, r *http.Request) {
	sess := sessionOf(r)
	ctx := r.Context()
	scope, err := h.Users.ResolveOrgScope(ctx, sess.Subject)
	if err != nil {
		slog.WarnContext(ctx, "list orgs: resolve scope failed", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to resolve memberships")
		return
	}
	ids := make([]string, len(scope.Memberships))
	for i, m := range scope.Memberships {
		ids[i] = m.OrgID
	}
	var facts map[string]any
	if h.DecorateOrgs != nil {
		facts = h.DecorateOrgs(r, SessionView{Subject: sess.Subject, OrgID: sess.OrgID}, ids)
	}
	names := h.orgsByID(ctx, ids)
	orgs := make([]any, 0, len(scope.Memberships))
	for _, m := range scope.Memberships {
		entry := orgEntry{OrgID: m.OrgID, Role: m.Role}
		if org, ok := names[m.OrgID]; ok {
			entry.Name, entry.Slug = org.Name, org.Slug
		}
		fact, ok := facts[m.OrgID]
		if !ok {
			orgs = append(orgs, entry)
			continue
		}
		// A row whose facts fail to encode still switches, so it goes out bare.
		merged, err := flatten(entry, fact)
		if err != nil {
			slog.ErrorContext(ctx, "list orgs: decorate failed", "org_id", m.OrgID, "err", err)
			orgs = append(orgs, entry)
			continue
		}
		orgs = append(orgs, merged)
	}
	writeJSON(w, http.StatusOK, orgsResponse{Orgs: orgs, ActiveOrgID: sess.OrgID})
}

// flatten joins the JSON fields of each part into one object, later parts
// winning.
func flatten(parts ...any) (map[string]json.RawMessage, error) {
	merged := map[string]json.RawMessage{}
	for _, part := range parts {
		raw, err := json.Marshal(part)
		if err == nil {
			err = json.Unmarshal(raw, &merged)
		}
		if err != nil {
			return nil, err
		}
	}
	return merged, nil
}

func (h *Handlers) handleGetSession(w http.ResponseWriter, r *http.Request) {
	// Behind the proxy the access assertion IS the session; a minted cookie would
	// be honoured by every deployment sharing the session table.
	if ac, ok := access.ClaimsFrom(r.Context()); ok {
		role := ""
		if h.isOperator(ac.Subject) {
			role = authn.RoleGodAdmin
		}
		h.writeSession(w, r, SessionView{Subject: ac.Subject, ViaAccess: true},
			sessionBody{Subject: ac.Subject, Authenticated: true, OrgRole: role})
		return
	}

	sess, ok := h.SessionFrom(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, struct {
			Authenticated bool `json:"authenticated"`
		}{})
		return
	}
	orgRole, _ := h.Users.GetOrgRole(r.Context(), sess.Subject, sess.OrgID)
	if h.isOperator(sess.Subject) {
		orgRole = authn.RoleGodAdmin
	}
	// Best-effort, so a host can label the workspace without a second call.
	var orgName string
	if h.Orgs != nil && sess.OrgID != "" {
		if org, err := h.Orgs.GetOrg(r.Context(), sess.OrgID); err == nil {
			orgName = org.Name
		}
	}
	h.writeSession(w, r, SessionView{Subject: sess.Subject, OrgID: sess.OrgID}, sessionBody{
		Subject:       sess.Subject,
		ConnectorID:   sess.ConnectorID,
		OrgID:         sess.OrgID,
		OrgName:       orgName,
		Authenticated: true,
		OrgRole:       orgRole,
	})
}

type sessionBody struct {
	Subject       string `json:"subject"`
	ConnectorID   string `json:"connector_id,omitempty"`
	OrgID         string `json:"org_id"`
	OrgName       string `json:"org_name,omitempty"`
	Authenticated bool   `json:"authenticated"`
	OrgRole       string `json:"org_role"`
}

// writeSession flattens the host's facts into body, so a client reads one
// object however much the host adds. A fact that fails to encode is dropped,
// never the session.
func (h *Handlers) writeSession(w http.ResponseWriter, r *http.Request, view SessionView, body sessionBody) {
	if h.DecorateSession == nil {
		writeJSON(w, http.StatusOK, body)
		return
	}
	merged, err := flatten(body, h.DecorateSession(r, view))
	if err != nil {
		slog.ErrorContext(r.Context(), "session: decorate failed", "err", err)
		writeJSON(w, http.StatusOK, body)
		return
	}
	writeJSON(w, http.StatusOK, merged)
}

func (h *Handlers) handleLogout(w http.ResponseWriter, r *http.Request) {
	ck, err := r.Cookie(h.cookies().Session)
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// Local only: with no offline_access there is no refresh state at the
	// issuer to revoke. The cookie, not a session id — rows key on its digest.
	_ = h.Sessions.Delete(r.Context(), ck.Value)
	h.cookies().ClearSession(w)
	w.WriteHeader(http.StatusNoContent)
}

// inviteHTTPStatus maps invite redemption failures to HTTP status codes.
func inviteHTTPStatus(err error) int {
	switch {
	case errors.Is(err, authn.ErrNoInvite):
		return http.StatusBadRequest
	case errors.Is(err, ErrInviteRevoked),
		errors.Is(err, ErrInviteExpired),
		errors.Is(err, ErrInviteAlreadyUsed),
		errors.Is(err, ErrInviteEmailMismatch),
		errors.Is(err, ErrInviteDomainMismatch),
		errors.Is(err, ErrNotMember):
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}

// handleBackchannelLogout implements OIDC Back-Channel Logout 1.0.
func (h *Handlers) handleBackchannelLogout(w http.ResponseWriter, r *http.Request) {
	if h.LogoutVerifier == nil {
		w.WriteHeader(http.StatusNotImplemented)
		return
	}
	// Spec §2.5.
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/x-www-form-urlencoded" {
		writeError(w, http.StatusBadRequest, "content-type must be application/x-www-form-urlencoded")
		return
	}
	// A logout_token is a compact JWT, never large.
	body, err := io.ReadAll(io.LimitReader(r.Body, 16*1024))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	rawToken := form.Get("logout_token")
	if rawToken == "" {
		writeError(w, http.StatusBadRequest, "logout_token required")
		return
	}
	ctx := r.Context()

	claims, err := h.LogoutVerifier.ValidateLogoutToken(ctx, rawToken)
	if err != nil {
		slog.WarnContext(ctx, "backchannel-logout: invalid logout_token", "err", err)
		writeError(w, http.StatusBadRequest, "invalid logout_token")
		return
	}

	if h.JTIs != nil {
		seen, err := h.JTIs.HasSeen(ctx, claims.JTI)
		if err != nil {
			slog.ErrorContext(ctx, "backchannel-logout: jti store error", "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if seen {
			// Duplicate delivery is idempotent per spec §2.6.
			w.WriteHeader(http.StatusOK)
			return
		}
		if err := h.JTIs.Record(ctx, claims.JTI, claims.Expiry); err != nil {
			slog.WarnContext(ctx, "backchannel-logout: failed to record jti", "err", err)
		}
	}

	if h.Sessions == nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Fall through to subject-wide: the provider's sid and our sessions.id rarely
	// agree, and OK on a zero-row delete claims a logout that never happened.
	if claims.SID != "" {
		n, err := h.Sessions.DeleteBySubjectAndSID(ctx, claims.Subject, claims.SID)
		if err != nil {
			slog.ErrorContext(ctx, "backchannel-logout: delete by sid failed",
				"subject", claims.Subject, "sid", claims.SID, "err", err)
		}
		if err == nil && n > 0 {
			slog.InfoContext(ctx, "backchannel-logout: sid-scoped logout", "subject", claims.Subject, "sid", claims.SID)
			w.WriteHeader(http.StatusOK)
			return
		}
		slog.WarnContext(ctx, "backchannel-logout: sid matched no session, ending all for subject",
			"subject", claims.Subject, "sid", claims.SID)
	}

	if err := h.Sessions.DeleteBySubject(ctx, claims.Subject); err != nil {
		slog.ErrorContext(ctx, "backchannel-logout: delete by subject failed", "subject", claims.Subject, "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	slog.InfoContext(ctx, "backchannel-logout: subject-wide logout", "subject", claims.Subject)
	w.WriteHeader(http.StatusOK)
}
