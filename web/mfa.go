package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"github.com/ArmornetIO/identity/authn"
)

const (
	mfaChallengeTTL = 5 * time.Minute
	maxMFAAttempts  = 5
)

func (h *Handlers) totpIssuer() string {
	if h.TOTPIssuer != "" {
		return h.TOTPIssuer
	}
	return "Identity"
}

// isMFAEnrolled returns true if the user has at least one active MFA credential.
func (h *Handlers) isMFAEnrolled(ctx context.Context, subject string) (bool, error) {
	if h.MFA.TOTP && h.TOTP != nil {
		cred, err := h.TOTP.Get(ctx, subject)
		if err == nil && cred.Enrolled {
			return true, nil
		}
		if err != nil && !errors.Is(err, authn.ErrNoTOTPCredential) {
			return false, err
		}
	}
	if h.MFA.WebAuthn && h.WebAuthnCreds != nil {
		n, err := h.WebAuthnCreds.CountBySubject(ctx, subject)
		if err != nil {
			return false, err
		}
		if n > 0 {
			return true, nil
		}
	}
	return false, nil
}

func (h *Handlers) issueMFAChallenge(ctx context.Context, subject, orgID string, tokenExpiry time.Time) (string, []MFAMethod, error) {
	challengeID := uuid.New().String()
	if err := h.MFAChallenges.Create(ctx, authn.MFAChallenge{
		ID:          challengeID,
		Subject:     subject,
		OrgID:       orgID,
		TokenExpiry: tokenExpiry,
		ExpiresAt:   time.Now().Add(mfaChallengeTTL),
	}); err != nil {
		return "", nil, err
	}
	var methods []MFAMethod
	if h.MFA.TOTP {
		if cred, err := h.TOTP.Get(ctx, subject); err == nil && cred.Enrolled {
			methods = append(methods, MFATOTP)
		}
	}
	if h.MFA.WebAuthn {
		if n, _ := h.WebAuthnCreds.CountBySubject(ctx, subject); n > 0 {
			methods = append(methods, MFAWebAuthn)
		}
	}
	return challengeID, methods, nil
}

// createSessionFromChallenge atomically consumes the challenge and creates a
// session, returning the raw cookie token, which exists only here.
func (h *Handlers) createSessionFromChallenge(ctx context.Context, challengeID string) (authn.SessionRecord, string, error) {
	challenge, err := h.MFAChallenges.Consume(ctx, challengeID)
	if err != nil {
		return authn.SessionRecord{}, "", err
	}
	sessToken := uuid.New().String()
	sess := authn.SessionRecord{
		ID:        uuid.New().String(),
		Subject:   challenge.Subject,
		OrgID:     challenge.OrgID,
		ExpiresAt: challenge.TokenExpiry,
	}
	if err := h.Sessions.Create(ctx, sess, sessToken); err != nil {
		return authn.SessionRecord{}, "", err
	}
	return sess, sessToken, nil
}

func (h *Handlers) handleMFAStatus(w http.ResponseWriter, r *http.Request) {
	sess := sessionOf(r)
	ctx := r.Context()
	resp := mfaStatus{TOTPEnabled: h.MFA.TOTP, WebAuthnEnabled: h.MFA.WebAuthn}
	if h.MFA.TOTP {
		if cred, err := h.TOTP.Get(ctx, sess.Subject); err == nil {
			resp.TOTPEnrolled = cred.Enrolled
		}
	}
	if h.MFA.WebAuthn {
		resp.WebAuthnCount, _ = h.WebAuthnCreds.CountBySubject(ctx, sess.Subject)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handlers) handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	sess := sessionOf(r)
	ctx := r.Context()
	// Refuse to overwrite an enrolled credential: the upsert resets enrolled,
	// which would silently unenroll MFA on an active account.
	if existing, err := h.TOTP.Get(ctx, sess.Subject); err == nil && existing.Enrolled {
		writeError(w, http.StatusConflict, "TOTP already enrolled — delete it first to re-enroll")
		return
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: h.totpIssuer(), AccountName: sess.Subject})
	if err != nil {
		slog.ErrorContext(ctx, "mfa: totp generate key failed", "err", err, "subject", sess.Subject)
		writeError(w, http.StatusInternalServerError, "failed to generate TOTP key")
		return
	}
	if err := h.TOTP.Upsert(ctx, sess.Subject, []byte(key.Secret())); err != nil {
		slog.ErrorContext(ctx, "mfa: totp upsert failed", "err", err, "subject", sess.Subject)
		writeError(w, http.StatusInternalServerError, "failed to save TOTP credential")
		return
	}
	writeJSON(w, http.StatusOK, totpSetupResponse{ProvisioningURL: key.URL(), Secret: key.Secret()})
}

type mfaStatus struct {
	TOTPEnabled     bool `json:"totp_enabled"`
	WebAuthnEnabled bool `json:"webauthn_enabled"`
	TOTPEnrolled    bool `json:"totp_enrolled"`
	WebAuthnCount   int  `json:"webauthn_count"`
}

type totpSetupResponse struct {
	ProvisioningURL string `json:"provisioning_url"`
	Secret          string `json:"secret"`
}

// signedIn answers a completed MFA sign-in.
type signedIn struct {
	Subject       string `json:"subject"`
	OrgID         string `json:"org_id"`
	Authenticated bool   `json:"authenticated"`
}

func (h *Handlers) handleTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	sess := sessionOf(r)
	ctx := r.Context()
	var req totpEnrollRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "code required")
		return
	}
	cred, err := h.TOTP.Get(ctx, sess.Subject)
	if errors.Is(err, authn.ErrNoTOTPCredential) {
		writeError(w, http.StatusBadRequest, "no pending TOTP setup — call /mfa/totp/setup first")
		return
	}
	if err != nil {
		slog.ErrorContext(ctx, "mfa: totp get failed", "err", err, "subject", sess.Subject)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if cred.Enrolled {
		writeError(w, http.StatusConflict, "TOTP already enrolled — delete it first to re-enroll")
		return
	}
	if !totp.Validate(req.Code, string(cred.Secret)) {
		slog.WarnContext(ctx, "mfa: totp enroll code invalid", "subject", sess.Subject, "reason", "invalid_code")
		writeError(w, http.StatusUnprocessableEntity, "invalid code")
		return
	}
	if err := h.TOTP.SetEnrolled(ctx, sess.Subject); err != nil {
		slog.ErrorContext(ctx, "mfa: totp set enrolled failed", "err", err, "subject", sess.Subject)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	slog.InfoContext(ctx, "mfa: totp enrolled", "subject", sess.Subject, "org_id", sess.OrgID, "method", "totp")
	h.authenticatorChanged(ctx, sess.Subject, MFATOTP, true)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) authenticatorChanged(ctx context.Context, subject string, method MFAMethod, added bool) {
	if h.OnAuthenticatorChange != nil {
		h.OnAuthenticatorChange(ctx, subject, method, added)
	}
}

func (h *Handlers) handleTOTPVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req totpVerifyRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "challenge_id and code required")
		return
	}
	challenge, err := h.MFAChallenges.Get(ctx, req.ChallengeID)
	if errors.Is(err, authn.ErrNoChallenge) {
		slog.WarnContext(ctx, "mfa: totp verify challenge not found", "reason", "expired")
		writeError(w, http.StatusUnauthorized, "challenge expired or not found")
		return
	}
	if err != nil {
		slog.ErrorContext(ctx, "mfa: totp get challenge failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if challenge.AttemptCount >= maxMFAAttempts {
		slog.WarnContext(ctx, "mfa: totp verify locked out", "subject", challenge.Subject, "org_id", challenge.OrgID,
			"reason", "brute_force_lockout", "attempt_count", challenge.AttemptCount)
		writeError(w, http.StatusTooManyRequests, "too many attempts")
		return
	}
	cred, err := h.TOTP.Get(ctx, challenge.Subject)
	if err != nil {
		slog.ErrorContext(ctx, "mfa: totp get credential failed", "err", err, "subject", challenge.Subject)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !cred.Enrolled {
		writeError(w, http.StatusUnauthorized, "TOTP not enrolled")
		return
	}
	if !totp.Validate(req.Code, string(cred.Secret)) {
		n, _ := h.MFAChallenges.IncrAttemptCount(ctx, req.ChallengeID)
		slog.WarnContext(ctx, "mfa: totp verify failed", "subject", challenge.Subject, "org_id", challenge.OrgID,
			"reason", "invalid_code", "attempt_count", n)
		writeError(w, http.StatusUnauthorized, "invalid code")
		return
	}
	sess, sessToken, err := h.createSessionFromChallenge(ctx, req.ChallengeID)
	if errors.Is(err, authn.ErrNoChallenge) {
		slog.WarnContext(ctx, "mfa: totp verify replay detected", "subject", challenge.Subject, "reason", "replay_detected")
		writeError(w, http.StatusUnauthorized, "challenge already used")
		return
	}
	if err != nil {
		slog.ErrorContext(ctx, "mfa: session create failed", "err", err, "subject", challenge.Subject)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	_ = h.TOTP.UpdateLastUsed(ctx, challenge.Subject, time.Now())
	slog.InfoContext(ctx, "mfa: totp verify success", "subject", challenge.Subject, "org_id", challenge.OrgID, "method", "totp")
	h.cookies().SetSession(w, sessToken)
	writeJSON(w, http.StatusOK, signedIn{Subject: sess.Subject, OrgID: sess.OrgID, Authenticated: true})
}

func (h *Handlers) handleTOTPDelete(w http.ResponseWriter, r *http.Request) {
	sess := sessionOf(r)
	ctx := r.Context()
	err := h.TOTP.Delete(ctx, sess.Subject)
	if err != nil && !errors.Is(err, authn.ErrNoTOTPCredential) {
		slog.ErrorContext(ctx, "mfa: totp delete failed", "err", err, "subject", sess.Subject)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	slog.WarnContext(ctx, "mfa: totp credential deleted", "subject", sess.Subject, "org_id", sess.OrgID, "method", "totp")
	if err == nil {
		h.authenticatorChanged(ctx, sess.Subject, MFATOTP, false)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) newWebAuthn() (*webauthnlib.WebAuthn, error) {
	rpName := h.MFA.WebAuthnRPName
	if rpName == "" {
		rpName = h.totpIssuer()
	}
	return webauthnlib.New(&webauthnlib.Config{
		RPDisplayName: rpName,
		RPID:          h.MFA.WebAuthnRPID,
		RPOrigins:     h.MFA.WebAuthnOrigins,
	})
}

// webAuthnUser adapts a subject + credential list to the webauthn.User interface.
type webAuthnUser struct {
	subject string
	creds   []authn.WebAuthnCredential
}

func (u webAuthnUser) WebAuthnID() []byte          { return []byte(u.subject) }
func (u webAuthnUser) WebAuthnName() string        { return u.subject }
func (u webAuthnUser) WebAuthnDisplayName() string { return u.subject }
func (u webAuthnUser) WebAuthnCredentials() []webauthnlib.Credential {
	out := make([]webauthnlib.Credential, 0, len(u.creds))
	for _, c := range u.creds {
		transports := make([]protocol.AuthenticatorTransport, 0, len(c.Transport))
		for _, t := range c.Transport {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}
		out = append(out, webauthnlib.Credential{
			ID:              c.ID,
			PublicKey:       c.PublicKey,
			AttestationType: c.AttestationType,
			Transport:       transports,
			Flags: webauthnlib.CredentialFlags{
				UserPresent:    c.Flags.UserPresent,
				UserVerified:   c.Flags.UserVerified,
				BackupEligible: c.Flags.BackupEligible,
				BackupState:    c.Flags.BackupState,
			},
			Authenticator: webauthnlib.Authenticator{
				AAGUID:       c.AAGUID,
				SignCount:    c.SignCount,
				CloneWarning: c.CloneWarning,
			},
		})
	}
	return out
}

func credFlags(f webauthnlib.CredentialFlags) authn.WebAuthnCredentialFlags {
	return authn.WebAuthnCredentialFlags{
		UserPresent: f.UserPresent, UserVerified: f.UserVerified,
		BackupEligible: f.BackupEligible, BackupState: f.BackupState,
	}
}

func (h *Handlers) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	sess := sessionOf(r)
	ctx := r.Context()
	wa, err := h.newWebAuthn()
	if err != nil {
		slog.ErrorContext(ctx, "mfa: webauthn init failed", "err", err)
		writeError(w, http.StatusInternalServerError, "webauthn unavailable")
		return
	}
	existing, err := h.WebAuthnCreds.ListBySubject(ctx, sess.Subject)
	if err != nil {
		slog.ErrorContext(ctx, "mfa: webauthn list creds failed", "err", err, "subject", sess.Subject)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	creation, webSess, err := wa.BeginRegistration(webAuthnUser{subject: sess.Subject, creds: existing})
	if err != nil {
		slog.ErrorContext(ctx, "mfa: webauthn begin registration failed", "err", err, "subject", sess.Subject)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	sessData, err := json.Marshal(webSess)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := h.WebAuthnSessions.Upsert(ctx, sess.Subject, sessData, string(webSess.Challenge), time.Now().Add(5*time.Minute)); err != nil {
		slog.ErrorContext(ctx, "mfa: webauthn session upsert failed", "err", err, "subject", sess.Subject)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, creation)
}

func (h *Handlers) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	sess := sessionOf(r)
	ctx := r.Context()
	wa, err := h.newWebAuthn()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "webauthn unavailable")
		return
	}
	rec, err := h.WebAuthnSessions.Get(ctx, sess.Subject)
	if errors.Is(err, authn.ErrNoWebAuthnSession) {
		writeError(w, http.StatusBadRequest, "no active WebAuthn session — call register/begin first")
		return
	}
	if err != nil {
		slog.ErrorContext(ctx, "mfa: webauthn get session failed", "err", err, "subject", sess.Subject)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	var webSess webauthnlib.SessionData
	if err := json.Unmarshal(rec.SessionData, &webSess); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	existing, _ := h.WebAuthnCreds.ListBySubject(ctx, sess.Subject)
	cred, err := wa.FinishRegistration(webAuthnUser{subject: sess.Subject, creds: existing}, webSess, r)
	if err != nil {
		slog.WarnContext(ctx, "mfa: webauthn register finish failed", "subject", sess.Subject, "err", err, "reason", "invalid_attestation")
		writeError(w, http.StatusUnprocessableEntity, "registration failed")
		return
	}
	_ = h.WebAuthnSessions.Delete(ctx, sess.Subject)

	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	if err := h.WebAuthnCreds.Create(ctx, authn.WebAuthnCredential{
		ID:              cred.ID,
		Subject:         sess.Subject,
		PublicKey:       cred.PublicKey,
		AttestationType: cred.AttestationType,
		Transport:       transports,
		AAGUID:          cred.Authenticator.AAGUID,
		SignCount:       cred.Authenticator.SignCount,
		CloneWarning:    cred.Authenticator.CloneWarning,
		Flags:           credFlags(cred.Flags),
	}); err != nil {
		slog.ErrorContext(ctx, "mfa: webauthn store credential failed", "err", err, "subject", sess.Subject)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	slog.InfoContext(ctx, "mfa: webauthn credential enrolled", "subject", sess.Subject, "org_id", sess.OrgID, "method", "webauthn")
	h.authenticatorChanged(ctx, sess.Subject, MFAWebAuthn, true)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) handleWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req webAuthnLoginBeginRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "challenge_id required")
		return
	}
	challenge, err := h.MFAChallenges.Get(ctx, req.ChallengeID)
	if errors.Is(err, authn.ErrNoChallenge) {
		writeError(w, http.StatusUnauthorized, "challenge expired or not found")
		return
	}
	if err != nil {
		slog.ErrorContext(ctx, "mfa: webauthn login begin get challenge failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	wa, err := h.newWebAuthn()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "webauthn unavailable")
		return
	}
	creds, err := h.WebAuthnCreds.ListBySubject(ctx, challenge.Subject)
	if err != nil {
		slog.ErrorContext(ctx, "mfa: webauthn list creds failed", "err", err, "subject", challenge.Subject)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if len(creds) == 0 {
		slog.WarnContext(ctx, "mfa: webauthn login begin no credentials", "subject", challenge.Subject, "reason", "no_credentials")
		writeError(w, http.StatusUnprocessableEntity, "no WebAuthn credentials registered")
		return
	}
	assertion, webSess, err := wa.BeginLogin(webAuthnUser{subject: challenge.Subject, creds: creds})
	if err != nil {
		slog.ErrorContext(ctx, "mfa: webauthn begin login failed", "err", err, "subject", challenge.Subject)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	sessData, err := json.Marshal(webSess)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := h.WebAuthnSessions.Upsert(ctx, challenge.Subject, sessData, string(webSess.Challenge), challenge.ExpiresAt); err != nil {
		slog.ErrorContext(ctx, "mfa: webauthn session upsert failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, assertion)
}

func (h *Handlers) handleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// One body carries both the challenge id and the authenticator's assertion,
	// and FinishLogin reads the body itself — so it is buffered and replayed.
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "challenge_id required")
		return
	}
	var req webAuthnLoginFinishRequest
	if json.Unmarshal(body, &req) != nil || req.ChallengeID == "" {
		writeError(w, http.StatusBadRequest, "challenge_id required")
		return
	}
	challengeID := req.ChallengeID
	r.Body = io.NopCloser(bytes.NewReader(body))
	challenge, err := h.MFAChallenges.Get(ctx, challengeID)
	if errors.Is(err, authn.ErrNoChallenge) {
		writeError(w, http.StatusUnauthorized, "challenge expired or not found")
		return
	}
	if err != nil {
		slog.ErrorContext(ctx, "mfa: webauthn login finish get challenge failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if challenge.AttemptCount >= maxMFAAttempts {
		slog.WarnContext(ctx, "mfa: webauthn login locked out", "subject", challenge.Subject,
			"reason", "brute_force_lockout", "attempt_count", challenge.AttemptCount)
		writeError(w, http.StatusTooManyRequests, "too many attempts")
		return
	}
	rec, err := h.WebAuthnSessions.Get(ctx, challenge.Subject)
	if errors.Is(err, authn.ErrNoWebAuthnSession) {
		writeError(w, http.StatusBadRequest, "no active WebAuthn session")
		return
	}
	if err != nil {
		slog.ErrorContext(ctx, "mfa: webauthn get session failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	var webSess webauthnlib.SessionData
	if err := json.Unmarshal(rec.SessionData, &webSess); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	wa, err := h.newWebAuthn()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "webauthn unavailable")
		return
	}
	creds, _ := h.WebAuthnCreds.ListBySubject(ctx, challenge.Subject)
	cred, err := wa.FinishLogin(webAuthnUser{subject: challenge.Subject, creds: creds}, webSess, r)
	if err != nil {
		n, _ := h.MFAChallenges.IncrAttemptCount(ctx, challengeID)
		slog.WarnContext(ctx, "mfa: webauthn login finish failed", "subject", challenge.Subject, "org_id", challenge.OrgID,
			"reason", "invalid_attestation", "attempt_count", n, "err", err)
		writeError(w, http.StatusUnauthorized, "WebAuthn verification failed")
		return
	}
	// Clone warning: flag it but do NOT advance SignCount.
	if cred.Authenticator.CloneWarning {
		slog.ErrorContext(ctx, "mfa: clone warning detected", "subject", challenge.Subject, "org_id", challenge.OrgID,
			"reason", "clone_warning", "credential_id", base64.RawURLEncoding.EncodeToString(cred.ID))
		_ = h.WebAuthnCreds.UpdateSignCount(ctx, cred.ID, cred.Authenticator.SignCount, true, credFlags(cred.Flags))
		writeError(w, http.StatusUnauthorized, "authenticator security violation")
		return
	}
	_ = h.WebAuthnCreds.UpdateSignCount(ctx, cred.ID, cred.Authenticator.SignCount, false, credFlags(cred.Flags))
	_ = h.WebAuthnSessions.Delete(ctx, challenge.Subject)

	sess, sessToken, err := h.createSessionFromChallenge(ctx, challengeID)
	if errors.Is(err, authn.ErrNoChallenge) {
		slog.WarnContext(ctx, "mfa: webauthn login replay detected", "subject", challenge.Subject, "reason", "replay_detected")
		writeError(w, http.StatusUnauthorized, "challenge already used")
		return
	}
	if err != nil {
		slog.ErrorContext(ctx, "mfa: session create failed after webauthn", "err", err, "subject", challenge.Subject)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	slog.InfoContext(ctx, "mfa: webauthn login success", "subject", challenge.Subject, "org_id", challenge.OrgID, "method", "webauthn")
	h.cookies().SetSession(w, sessToken)
	writeJSON(w, http.StatusOK, signedIn{Subject: sess.Subject, OrgID: sess.OrgID, Authenticated: true})
}

func (h *Handlers) handleWebAuthnDelete(w http.ResponseWriter, r *http.Request) {
	sess := sessionOf(r)
	ctx := r.Context()
	rawID, err := base64.RawURLEncoding.DecodeString(r.PathValue("credential_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid credential_id")
		return
	}
	if err := h.WebAuthnCreds.Delete(ctx, rawID, sess.Subject); err != nil {
		slog.ErrorContext(ctx, "mfa: webauthn delete failed", "err", err, "subject", sess.Subject)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	slog.WarnContext(ctx, "mfa: webauthn credential deleted", "subject", sess.Subject, "org_id", sess.OrgID, "method", "webauthn")
	h.authenticatorChanged(ctx, sess.Subject, MFAWebAuthn, false)
	w.WriteHeader(http.StatusNoContent)
}
