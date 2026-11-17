package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/gorilla/mux"

	"github.com/ArmornetIO/axa/internal/dex/connector"
	"github.com/ArmornetIO/axa/internal/dex/server/internal"
	"github.com/ArmornetIO/axa/internal/dex/storage"
)

const (
	codeChallengeMethodPlain = "plain"
	codeChallengeMethodS256  = "S256"
)

func (s *Server) handlePublicKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// TODO(ericchiang): Cache this.
	keys, err := s.signer.ValidationKeys(ctx)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "failed to get keys", "err", err)
		s.renderError(r, w, http.StatusInternalServerError, "Internal server error.")
		return
	}

	if len(keys) == 0 {
		s.logger.ErrorContext(r.Context(), "no public keys found.")
		s.renderError(r, w, http.StatusInternalServerError, "Internal server error.")
		return
	}

	jwks := jose.JSONWebKeySet{
		Keys: make([]jose.JSONWebKey, len(keys)),
	}
	for i, key := range keys {
		jwks.Keys[i] = *key
	}

	data, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		s.logger.ErrorContext(r.Context(), "failed to marshal discovery data", "err", err)
		s.renderError(r, w, http.StatusInternalServerError, "Internal server error.")
		return
	}

	// We don't have NextRotation info from Signer interface easily,
	// so we'll just set a reasonable default cache time.
	maxAge := time.Minute * 10

	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d, must-revalidate", int(maxAge.Seconds())))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Write(data)
}

type discovery struct {
	Issuer         string `json:"issuer"`
	Auth           string `json:"authorization_endpoint"`
	Token          string `json:"token_endpoint"`
	Keys           string `json:"jwks_uri"`
	UserInfo       string `json:"userinfo_endpoint"`
	DeviceEndpoint string `json:"device_authorization_endpoint"`
	Introspect     string `json:"introspection_endpoint"`
	// ARMORNET FORK: RFC 7009 revocation, OIDC RP-Initiated Logout 1.0, and Back-Channel Logout 1.0
	Revocation                        string   `json:"revocation_endpoint,omitempty"`
	EndSession                        string   `json:"end_session_endpoint,omitempty"`
	BackchannelLogoutSupported        bool     `json:"backchannel_logout_supported,omitempty"`
	BackchannelLogoutSessionSupported bool     `json:"backchannel_logout_session_supported,omitempty"`
	GrantTypes                        []string `json:"grant_types_supported"`
	ResponseTypes                     []string `json:"response_types_supported"`
	Subjects                          []string `json:"subject_types_supported"`
	IDTokenAlgs                       []string `json:"id_token_signing_alg_values_supported"`
	CodeChallengeAlgs                 []string `json:"code_challenge_methods_supported"`
	RequirePKCE                       bool     `json:"require_pkce,omitempty"`
	Scopes                            []string `json:"scopes_supported"`
	AuthMethods                       []string `json:"token_endpoint_auth_methods_supported"`
	Claims                            []string `json:"claims_supported"`
}

func (s *Server) discoveryHandler(ctx context.Context) (http.HandlerFunc, error) {
	d := s.constructDiscovery(ctx)

	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal discovery data: %v", err)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Write(data)
	}), nil
}

func (s *Server) constructDiscovery(ctx context.Context) discovery {
	d := discovery{
		Issuer:                            s.issuerURL.String(),
		Auth:                              s.absURL("/auth"),
		Token:                             s.absURL("/token"),
		Keys:                              s.absURL("/keys"),
		UserInfo:                          s.absURL("/userinfo"),
		DeviceEndpoint:                    s.absURL("/device/code"),
		Introspect:                        s.absURL("/token/introspect"),
		Revocation:                        s.absURL("/revoke"),
		EndSession:                        s.absURL("/end_session"),
		BackchannelLogoutSupported:        true,
		BackchannelLogoutSessionSupported: false, // sid support is deferred
		Subjects:                          []string{"public"},
		IDTokenAlgs:                       []string{string(jose.RS256)},
		CodeChallengeAlgs:                 []string{codeChallengeMethodS256, codeChallengeMethodPlain},
		RequirePKCE:                       s.requirePKCE,
		Scopes:                            []string{"openid", "email", "groups", "profile", "offline_access"},
		AuthMethods:                       []string{"client_secret_basic", "client_secret_post"},
		Claims: []string{
			"iss", "sub", "aud", "iat", "exp", "email", "email_verified",
			"locale", "name", "preferred_username", "at_hash",
		},
	}

	if s.requirePKCE {
		d.CodeChallengeAlgs = []string{codeChallengeMethodS256}
	}

	// Determine signing algorithm from signer
	signingAlg, err := s.signer.Algorithm(ctx)
	if err != nil {
		s.logger.Error("failed to get signing algorithm", "err", err)
	} else {
		d.IDTokenAlgs = []string{string(signingAlg)}
	}

	for responseType := range s.supportedResponseTypes {
		d.ResponseTypes = append(d.ResponseTypes, responseType)
	}
	sort.Strings(d.ResponseTypes)

	d.GrantTypes = s.supportedGrantTypes
	return d
}

// handleAuthorization handles the OAuth2 auth endpoint.
func (s *Server) handleAuthorization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// Extract the arguments
	if err := r.ParseForm(); err != nil {
		s.logger.ErrorContext(r.Context(), "failed to parse arguments", "err", err)

		s.renderError(r, w, http.StatusBadRequest, ErrMsgInvalidRequest)
		return
	}

	connectorID := r.Form.Get("connector_id")
	connectors, err := s.listConnectors(ctx)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "failed to get list of connectors", "err", err)
		s.renderError(r, w, http.StatusInternalServerError, "Failed to retrieve connector list.")
		return
	}

	// We don't need connector_id any more
	r.Form.Del("connector_id")

	// Construct a URL with all of the arguments in its query
	connURL := url.URL{
		RawQuery: r.Form.Encode(),
	}

	// Redirect if a client chooses a specific connector_id
	if connectorID != "" {
		for _, c := range connectors {
			if c.ID == connectorID {
				connURL.Path = s.absPath("/auth", url.PathEscape(c.ID))
				http.Redirect(w, r, connURL.String(), http.StatusFound)
				return
			}
		}
		s.renderError(r, w, http.StatusBadRequest, "Connector ID does not match a valid Connector")
		return
	}

	if len(connectors) == 1 && !s.alwaysShowLogin {
		connURL.Path = s.absPath("/auth", url.PathEscape(connectors[0].ID))
		http.Redirect(w, r, connURL.String(), http.StatusFound)
	}

	connectorInfos := make([]connectorInfo, len(connectors))
	for index, conn := range connectors {
		connURL.Path = s.absPath("/auth", url.PathEscape(conn.ID))
		connectorInfos[index] = connectorInfo{
			ID:   conn.ID,
			Name: conn.Name,
			Type: conn.Type,
			URL:  template.URL(connURL.String()),
		}
	}

	if err := s.templates.login(r, w, connectorInfos); err != nil {
		s.logger.ErrorContext(r.Context(), "server template error", "err", err)
	}
}

func (s *Server) handleConnectorLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	authReq, err := s.parseAuthorizationRequest(r)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "failed to parse authorization request", "err", err)

		switch authErr := err.(type) {
		case *redirectedAuthErr:
			authErr.Handler().ServeHTTP(w, r)
		case *displayedAuthErr:
			s.renderError(r, w, authErr.Status, err.Error())
		default:
			panic("unsupported error type")
		}

		return
	}

	connID, err := url.PathUnescape(mux.Vars(r)["connector"])
	if err != nil {
		s.logger.ErrorContext(r.Context(), "failed to parse connector", "err", err)
		s.renderError(r, w, http.StatusBadRequest, "Requested resource does not exist")
		return
	}

	conn, err := s.getConnector(ctx, connID)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "Failed to get connector", "err", err)
		s.renderError(r, w, http.StatusBadRequest, "Connector failed to initialize")
		return
	}

	// Set the connector being used for the login.
	if authReq.ConnectorID != "" && authReq.ConnectorID != connID {
		s.logger.ErrorContext(r.Context(), "mismatched connector ID in auth request",
			"auth_request_connector_id", authReq.ConnectorID, "connector_id", connID)
		s.renderError(r, w, http.StatusBadRequest, "Bad connector ID")
		return
	}

	authReq.ConnectorID = connID

	// Actually create the auth request
	authReq.Expiry = s.now().Add(s.authRequestsValidFor)
	if err := s.storage.CreateAuthRequest(ctx, *authReq); err != nil {
		s.logger.ErrorContext(r.Context(), "failed to create authorization request", "err", err)
		s.renderError(r, w, http.StatusInternalServerError, "Failed to connect to the database.")
		return
	}

	scopes := parseScopes(authReq.Scopes)

	// Work out where the "Select another login method" link should go.
	backLink := ""
	if len(s.connectors) > 1 {
		backLinkURL := url.URL{
			Path:     s.absPath("/auth"),
			RawQuery: r.Form.Encode(),
		}
		backLink = backLinkURL.String()
	}

	switch r.Method {
	case http.MethodGet:
		switch conn := conn.Connector.(type) {
		case connector.CallbackConnector:
			// Use the auth request ID as the "state" token.
			//
			// TODO(ericchiang): Is this appropriate or should we also be using a nonce?
			callbackURL, connData, err := conn.LoginURL(scopes, s.absURL("/callback"), authReq.ID)
			if err != nil {
				s.logger.ErrorContext(r.Context(), "connector returned error when creating callback", "connector_id", connID, "err", err)
				s.renderError(r, w, http.StatusInternalServerError, "Login error.")
				return
			}
			if len(connData) > 0 {
				updater := func(a storage.AuthRequest) (storage.AuthRequest, error) {
					a.ConnectorData = connData
					return a, nil
				}
				err := s.storage.UpdateAuthRequest(ctx, authReq.ID, updater)
				if err != nil {
					s.logger.ErrorContext(r.Context(), "Failed to set connector data on auth request", "connector_id", connID, "err", err)
					s.renderError(r, w, http.StatusInternalServerError, "Database error.")
					return
				}
			}
			http.Redirect(w, r, callbackURL, http.StatusFound)
		case connector.PasswordConnector:
			loginURL := url.URL{
				Path: s.absPath("/auth", connID, "login"),
			}
			q := loginURL.Query()
			q.Set("state", authReq.ID)
			q.Set("back", backLink)
			loginURL.RawQuery = q.Encode()

			http.Redirect(w, r, loginURL.String(), http.StatusFound)
		case connector.SAMLConnector:
			action, value, err := conn.POSTData(scopes, authReq.ID)
			if err != nil {
				s.logger.ErrorContext(r.Context(), "creating SAML data", "err", err)
				s.renderError(r, w, http.StatusInternalServerError, "Connector Login Error")
				return
			}

			// TODO(ericchiang): Don't inline this.
			fmt.Fprintf(w, `<!DOCTYPE html>
			  <html lang="en">
			  <head>
			    <meta http-equiv="content-type" content="text/html; charset=utf-8">
			    <title>SAML login</title>
			  </head>
			  <body>
			    <form method="post" action="%s" >
				    <input type="hidden" name="SAMLRequest" value="%s" />
				    <input type="hidden" name="RelayState" value="%s" />
			    </form>
				<script>
				    document.forms[0].submit();
				</script>
			  </body>
			  </html>`, action, value, authReq.ID)
		default:
			s.renderError(r, w, http.StatusBadRequest, "Requested resource does not exist.")
		}
	default:
		s.renderError(r, w, http.StatusBadRequest, "Unsupported request method.")
	}
}

func (s *Server) handlePasswordLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	authID := r.URL.Query().Get("state")
	if authID == "" {
		s.renderError(r, w, http.StatusBadRequest, "User session error.")
		return
	}

	backLink := r.URL.Query().Get("back")

	authReq, err := s.storage.GetAuthRequest(ctx, authID)
	if err != nil {
		if err == storage.ErrNotFound {
			s.logger.ErrorContext(r.Context(), "invalid 'state' parameter provided", "err", err)
			s.renderError(r, w, http.StatusBadRequest, "Requested resource does not exist.")
			return
		}
		s.logger.ErrorContext(r.Context(), "failed to get auth request", "err", err)
		s.renderError(r, w, http.StatusInternalServerError, "Database error.")
		return
	}

	connID, err := url.PathUnescape(mux.Vars(r)["connector"])
	if err != nil {
		s.logger.ErrorContext(r.Context(), "failed to parse connector", "err", err)
		s.renderError(r, w, http.StatusBadRequest, "Requested resource does not exist")
		return
	} else if connID != "" && connID != authReq.ConnectorID {
		s.logger.ErrorContext(r.Context(), "connector mismatch: password login triggered for different connector from authentication start", "start_connector_id", authReq.ConnectorID, "password_connector_id", connID)
		s.renderError(r, w, http.StatusInternalServerError, "Requested resource does not exist.")
		return
	}

	conn, err := s.getConnector(ctx, authReq.ConnectorID)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "failed to get connector", "connector_id", authReq.ConnectorID, "err", err)
		s.renderError(r, w, http.StatusInternalServerError, "Connector failed to initialize.")
		return
	}

	pwConn, ok := conn.Connector.(connector.PasswordConnector)
	if !ok {
		s.logger.ErrorContext(r.Context(), "expected password connector in handlePasswordLogin()", "password_connector", pwConn)
		s.renderError(r, w, http.StatusInternalServerError, "Requested resource does not exist.")
		return
	}

	switch r.Method {
	case http.MethodGet:
		if err := s.templates.password(r, w, r.URL.String(), "", usernamePrompt(pwConn), false, backLink); err != nil {
			s.logger.ErrorContext(r.Context(), "server template error", "err", err)
		}
	case http.MethodPost:
		username := r.FormValue("login")
		password := r.FormValue("password")
		scopes := parseScopes(authReq.Scopes)

		identity, ok, err := pwConn.Login(r.Context(), scopes, username, password)
		if err != nil {
			s.logger.ErrorContext(r.Context(), "failed to login user", "err", err)
			s.renderError(r, w, http.StatusInternalServerError, ErrMsgLoginError)
			return
		}
		if !ok {
			if err := s.templates.password(r, w, r.URL.String(), username, usernamePrompt(pwConn), true, backLink); err != nil {
				s.logger.ErrorContext(r.Context(), "server template error", "err", err)
			}
			s.logger.ErrorContext(r.Context(), "failed login attempt: Invalid credentials.", "user", username)
			return
		}
		redirectURL, canSkipApproval, err := s.finalizeLogin(r.Context(), identity, authReq, conn.Connector)
		if err != nil {
			s.logger.ErrorContext(r.Context(), "failed to finalize login", "err", err)
			s.renderError(r, w, http.StatusInternalServerError, "Login error.")
			return
		}

		if canSkipApproval {
			authReq, err = s.storage.GetAuthRequest(ctx, authReq.ID)
			if err != nil {
				s.logger.ErrorContext(r.Context(), "failed to get finalized auth request", "err", err)
				s.renderError(r, w, http.StatusInternalServerError, "Login error.")
				return
			}
			s.sendCodeResponse(w, r, authReq)
			return
		}

		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
	default:
		s.renderError(r, w, http.StatusBadRequest, "Unsupported request method.")
	}
}

func (s *Server) handleConnectorCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var authID string
	switch r.Method {
	case http.MethodGet: // OAuth2 callback
		if authID = r.URL.Query().Get("state"); authID == "" {
			s.renderError(r, w, http.StatusBadRequest, "User session error.")
			return
		}
	case http.MethodPost: // SAML POST binding
		if authID = r.PostFormValue("RelayState"); authID == "" {
			s.renderError(r, w, http.StatusBadRequest, "User session error.")
			return
		}
	default:
		s.renderError(r, w, http.StatusBadRequest, "Method not supported")
		return
	}

	authReq, err := s.storage.GetAuthRequest(ctx, authID)
	if err != nil {
		if err == storage.ErrNotFound {
			s.logger.ErrorContext(r.Context(), "invalid 'state' parameter provided", "err", err)
			s.renderError(r, w, http.StatusBadRequest, "Requested resource does not exist.")
			return
		}
		s.logger.ErrorContext(r.Context(), "failed to get auth request", "err", err)
		s.renderError(r, w, http.StatusInternalServerError, "Database error.")
		return
	}

	connID, err := url.PathUnescape(mux.Vars(r)["connector"])
	if err != nil {
		s.logger.ErrorContext(r.Context(), "failed to get connector", "connector_id", authReq.ConnectorID, "err", err)
		s.renderError(r, w, http.StatusInternalServerError, "Requested resource does not exist.")
		return
	} else if connID != "" && connID != authReq.ConnectorID {
		s.logger.ErrorContext(r.Context(), "connector mismatch: callback triggered for different connector than authentication start", "authentication_start_connector_id", authReq.ConnectorID, "connector_id", connID)
		s.renderError(r, w, http.StatusInternalServerError, "Requested resource does not exist.")
		return
	}

	conn, err := s.getConnector(ctx, authReq.ConnectorID)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "failed to get connector", "connector_id", authReq.ConnectorID, "err", err)
		s.renderError(r, w, http.StatusInternalServerError, "Requested resource does not exist.")
		return
	}

	callStart := time.Now()
	var identity connector.Identity
	switch conn := conn.Connector.(type) {
	case connector.CallbackConnector:
		if r.Method != http.MethodGet {
			s.logger.ErrorContext(r.Context(), "SAML request mapped to OAuth2 connector")
			s.renderError(r, w, http.StatusBadRequest, "Invalid request")
			return
		}
		identity, err = conn.HandleCallback(parseScopes(authReq.Scopes), authReq.ConnectorData, r)
	case connector.SAMLConnector:
		if r.Method != http.MethodPost {
			s.logger.ErrorContext(r.Context(), "OAuth2 request mapped to SAML connector")
			s.renderError(r, w, http.StatusBadRequest, "Invalid request")
			return
		}
		identity, err = conn.HandlePOST(parseScopes(authReq.Scopes), r.PostFormValue("SAMLResponse"), authReq.ID)
	default:
		s.renderError(r, w, http.StatusInternalServerError, "Requested resource does not exist.")
		return
	}

	if err != nil {
		if s.authMetrics != nil {
			s.authMetrics.Record(authReq.ConnectorID, time.Since(callStart).Milliseconds(), true)
		}
		s.logger.ErrorContext(r.Context(), "failed to authenticate", "err", err)
		var groupsErr *connector.UserNotInRequiredGroupsError
		if errors.As(err, &groupsErr) {
			s.renderError(r, w, http.StatusForbidden, ErrMsgNotInRequiredGroups)
		} else {
			s.renderError(r, w, http.StatusInternalServerError, ErrMsgAuthenticationFailed)
		}
		return
	}
	if s.authMetrics != nil {
		s.authMetrics.Record(authReq.ConnectorID, time.Since(callStart).Milliseconds(), false)
	}

	redirectURL, canSkipApproval, err := s.finalizeLogin(ctx, identity, authReq, conn.Connector)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "failed to finalize login", "err", err)
		s.renderError(r, w, http.StatusInternalServerError, "Login error.")
		return
	}

	if canSkipApproval {
		authReq, err = s.storage.GetAuthRequest(ctx, authReq.ID)
		if err != nil {
			s.logger.ErrorContext(r.Context(), "failed to get finalized auth request", "err", err)
			s.renderError(r, w, http.StatusInternalServerError, "Login error.")
			return
		}
		s.sendCodeResponse(w, r, authReq)
		return
	}

	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// finalizeLogin associates the user's identity with the current AuthRequest, then returns
// the approval page's path.
func (s *Server) finalizeLogin(ctx context.Context, identity connector.Identity, authReq storage.AuthRequest, conn connector.Connector) (string, bool, error) {
	claims := storage.Claims{
		UserID:            identity.UserID,
		Username:          identity.Username,
		PreferredUsername: identity.PreferredUsername,
		Email:             identity.Email,
		EmailVerified:     identity.EmailVerified,
		Groups:            identity.Groups,
	}

	updater := func(a storage.AuthRequest) (storage.AuthRequest, error) {
		a.LoggedIn = true
		a.Claims = claims
		a.ConnectorData = identity.ConnectorData
		return a, nil
	}
	if err := s.storage.UpdateAuthRequest(ctx, authReq.ID, updater); err != nil {
		return "", false, fmt.Errorf("failed to update auth request: %v", err)
	}

	// ARMORNET FORK: upstream logged username, preferred_username, email and
	// groups here. Identity stores no PII, and a log line is storage.
	s.logger.InfoContext(ctx, "login successful", "connector_id", authReq.ConnectorID)

	offlineAccessRequested := false
	for _, scope := range authReq.Scopes {
		if scope == scopeOfflineAccess {
			offlineAccessRequested = true
			break
		}
	}
	_, canRefresh := conn.(connector.RefreshConnector)

	if offlineAccessRequested && canRefresh {
		// Try to retrieve an existing OfflineSession object for the corresponding user.
		session, err := s.storage.GetOfflineSessions(ctx, identity.UserID, authReq.ConnectorID)
		switch {
		case err != nil && err == storage.ErrNotFound:
			offlineSessions := storage.OfflineSessions{
				UserID:        identity.UserID,
				ConnID:        authReq.ConnectorID,
				Refresh:       make(map[string]*storage.RefreshTokenRef),
				ConnectorData: identity.ConnectorData,
			}

			// Create a new OfflineSession object for the user and add a reference object for
			// the newly received refreshtoken.
			if err := s.storage.CreateOfflineSessions(ctx, offlineSessions); err != nil {
				s.logger.ErrorContext(ctx, "failed to create offline session", "err", err)
				return "", false, err
			}
		case err == nil:
			// Update existing OfflineSession obj with new RefreshTokenRef.
			if err := s.storage.UpdateOfflineSessions(ctx, session.UserID, session.ConnID, func(old storage.OfflineSessions) (storage.OfflineSessions, error) {
				if len(identity.ConnectorData) > 0 {
					old.ConnectorData = identity.ConnectorData
				}
				return old, nil
			}); err != nil {
				s.logger.ErrorContext(ctx, "failed to update offline session", "err", err)
				return "", false, err
			}
		default:
			s.logger.ErrorContext(ctx, "failed to get offline session", "err", err)
			return "", false, err
		}
	}

	// we can skip the redirect to /approval and go ahead and send code if it's not required
	if s.skipApproval && !authReq.ForceApprovalPrompt {
		return "", true, nil
	}

	// an HMAC is used here to ensure that the request ID is unpredictable, ensuring that an attacker who intercepted the original
	// flow would be unable to poll for the result at the /approval endpoint
	h := hmac.New(sha256.New, authReq.HMACKey)
	h.Write([]byte(authReq.ID))
	mac := h.Sum(nil)

	returnURL := path.Join(s.issuerURL.Path, "/approval") + "?req=" + authReq.ID + "&hmac=" + base64.RawURLEncoding.EncodeToString(mac)
	return returnURL, false, nil
}

func (s *Server) handleApproval(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	macEncoded := r.FormValue("hmac")
	if macEncoded == "" {
		s.renderError(r, w, http.StatusUnauthorized, "Unauthorized request")
		return
	}
	mac, err := base64.RawURLEncoding.DecodeString(macEncoded)
	if err != nil {
		s.renderError(r, w, http.StatusUnauthorized, "Unauthorized request")
		return
	}

	authReq, err := s.storage.GetAuthRequest(ctx, r.FormValue("req"))
	if err != nil {
		s.logger.ErrorContext(r.Context(), "failed to get auth request", "err", err)
		s.renderError(r, w, http.StatusInternalServerError, "Database error.")
		return
	}
	if !authReq.LoggedIn {
		s.logger.ErrorContext(r.Context(), "auth request does not have an identity for approval")
		s.renderError(r, w, http.StatusInternalServerError, "Login process not yet finalized.")
		return
	}

	// build expected hmac with secret key
	h := hmac.New(sha256.New, authReq.HMACKey)
	h.Write([]byte(authReq.ID))
	expectedMAC := h.Sum(nil)
	// constant time comparison
	if !hmac.Equal(mac, expectedMAC) {
		s.renderError(r, w, http.StatusUnauthorized, "Unauthorized request")
		return
	}

	switch r.Method {
	case http.MethodGet:
		client, err := s.storage.GetClient(ctx, authReq.ClientID)
		if err != nil {
			s.logger.ErrorContext(r.Context(), "Failed to get client", "client_id", authReq.ClientID, "err", err)
			s.renderError(r, w, http.StatusInternalServerError, "Failed to retrieve client.")
			return
		}
		if err := s.templates.approval(r, w, authReq.ID, authReq.Claims.Username, client.Name, authReq.Scopes); err != nil {
			s.logger.ErrorContext(r.Context(), "server template error", "err", err)
		}
	case http.MethodPost:
		if r.FormValue("approval") != "approve" {
			s.renderError(r, w, http.StatusInternalServerError, "Approval rejected.")
			return
		}
		s.sendCodeResponse(w, r, authReq)
	}
}

func (s *Server) sendCodeResponse(w http.ResponseWriter, r *http.Request, authReq storage.AuthRequest) {
	ctx := r.Context()
	if s.now().After(authReq.Expiry) {
		s.renderError(r, w, http.StatusBadRequest, "User session has expired.")
		return
	}

	if err := s.storage.DeleteAuthRequest(ctx, authReq.ID); err != nil {
		if err != storage.ErrNotFound {
			s.logger.ErrorContext(r.Context(), "Failed to delete authorization request", "err", err)
			s.renderError(r, w, http.StatusInternalServerError, "Internal server error.")
		} else {
			s.renderError(r, w, http.StatusBadRequest, "User session error.")
		}
		return
	}
	u, err := url.Parse(authReq.RedirectURI)
	if err != nil {
		s.renderError(r, w, http.StatusInternalServerError, "Invalid redirect URI.")
		return
	}

	var (
		// Was the initial request using the implicit or hybrid flow instead of
		// the "normal" code flow?
		implicitOrHybrid = false

		// Only present in hybrid or code flow. code.ID == "" if this is not set.
		code storage.AuthCode

		// ID token returned immediately if the response_type includes "id_token".
		// Only valid for implicit and hybrid flows.
		idToken       string
		idTokenExpiry time.Time

		// Access token
		accessToken string
	)

	for _, responseType := range authReq.ResponseTypes {
		switch responseType {
		case responseTypeCode:
			code = storage.AuthCode{
				ID:            storage.NewID(),
				ClientID:      authReq.ClientID,
				ConnectorID:   authReq.ConnectorID,
				Nonce:         authReq.Nonce,
				Scopes:        authReq.Scopes,
				Claims:        authReq.Claims,
				Expiry:        s.now().Add(time.Minute * 30),
				RedirectURI:   authReq.RedirectURI,
				ConnectorData: authReq.ConnectorData,
				PKCE:          authReq.PKCE,
			}
			if err := s.storage.CreateAuthCode(ctx, code); err != nil {
				s.logger.ErrorContext(r.Context(), "Failed to create auth code", "err", err)
				s.renderError(r, w, http.StatusInternalServerError, "Internal server error.")
				return
			}

			// Implicit and hybrid flows that try to use the OOB redirect URI are
			// rejected earlier. If we got here we're using the code flow.
			if authReq.RedirectURI == redirectURIOOB {
				if err := s.templates.oob(r, w, code.ID); err != nil {
					s.logger.ErrorContext(r.Context(), "server template error", "err", err)
				}
				return
			}
		case responseTypeToken:
			implicitOrHybrid = true
			var err error

			accessToken, _, err = s.newAccessToken(r.Context(), authReq.ClientID, authReq.Claims, authReq.Scopes, authReq.Nonce, authReq.ConnectorID)
			if err != nil {
				s.logger.ErrorContext(r.Context(), "failed to create new access token", "err", err)
				s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
				return
			}
		case responseTypeIDToken:
			implicitOrHybrid = true
			var err error

			idToken, idTokenExpiry, err = s.newIDToken(r.Context(), authReq.ClientID, authReq.Claims, authReq.Scopes, authReq.Nonce, accessToken, code.ID, authReq.ConnectorID)
			if err != nil {
				s.logger.ErrorContext(r.Context(), "failed to create ID token", "err", err)
				s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
				return
			}
		}
	}

	if implicitOrHybrid {
		v := url.Values{}
		if accessToken != "" {
			v.Set("access_token", accessToken)
			v.Set("token_type", "bearer")
			// The hybrid flow with "code token" or "code id_token token" doesn't return an
			// "expires_in" value. If "code" wasn't provided, indicating the implicit flow,
			// don't add it.
			//
			// https://openid.net/specs/openid-connect-core-1_0.html#HybridAuthResponse
			if code.ID == "" {
				v.Set("expires_in", strconv.Itoa(int(idTokenExpiry.Sub(s.now()).Seconds())))
			}
		}
		v.Set("state", authReq.State)
		if idToken != "" {
			v.Set("id_token", idToken)
		}
		if code.ID != "" {
			v.Set("code", code.ID)
		}

		// Implicit and hybrid flows return their values as part of the fragment.
		//
		//   HTTP/1.1 303 See Other
		//   Location: https://client.example.org/cb#
		//     access_token=SlAV32hkKG
		//     &token_type=bearer
		//     &id_token=eyJ0 ... NiJ9.eyJ1c ... I6IjIifX0.DeWt4Qu ... ZXso
		//     &expires_in=3600
		//     &state=af0ifjsldkj
		//
		u.Fragment = v.Encode()
	} else {
		// The code flow add values to the URL query.
		//
		//   HTTP/1.1 303 See Other
		//   Location: https://client.example.org/cb?
		//     code=SplxlOBeZQQYbYS6WxSbIA
		//     &state=af0ifjsldkj
		//
		q := u.Query()
		q.Set("code", code.ID)
		q.Set("state", authReq.State)
		u.RawQuery = q.Encode()
	}

	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

func (s *Server) withClientFromStorage(w http.ResponseWriter, r *http.Request, handler func(http.ResponseWriter, *http.Request, storage.Client)) {
	s.withClient(w, r, handler, false)
}

// withPKCEOrSecretClient is withClientFromStorage for the authorization_code
// grant alone. ARMORNET PATCH: a PUBLIC client authenticates there with its
// PKCE verifier instead of a secret (RFC 6749 §2.3, RFC 7636), and
// handleAuthCode refuses a public client whose code carries no challenge.
//
// The device flow got the same treatment in deviceflowhandlers.go; this grant
// was missed, so a public browser client could never exchange its code. Every
// other grant — refresh, password, token exchange and above all client
// credentials — still demands the secret, public client or not. Re-apply on an
// upstream Dex pull.
func (s *Server) withPKCEOrSecretClient(w http.ResponseWriter, r *http.Request, handler func(http.ResponseWriter, *http.Request, storage.Client)) {
	s.withClient(w, r, handler, true)
}

func (s *Server) withClient(w http.ResponseWriter, r *http.Request, handler func(http.ResponseWriter, *http.Request, storage.Client), publicByPKCE bool) {
	ctx := r.Context()
	clientID, clientSecret, ok := r.BasicAuth()
	if ok {
		var err error
		if clientID, err = url.QueryUnescape(clientID); err != nil {
			s.tokenErrHelper(w, errInvalidRequest, "client_id improperly encoded", http.StatusBadRequest)
			return
		}
		if clientSecret, err = url.QueryUnescape(clientSecret); err != nil {
			s.tokenErrHelper(w, errInvalidRequest, "client_secret improperly encoded", http.StatusBadRequest)
			return
		}
	} else {
		clientID = r.PostFormValue("client_id")
		clientSecret = r.PostFormValue("client_secret")
	}

	client, err := s.storage.GetClient(ctx, clientID)
	if err != nil {
		if err != storage.ErrNotFound {
			s.logger.ErrorContext(r.Context(), "failed to get client", "err", err)
			s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		} else {
			s.tokenErrHelper(w, errInvalidClient, "Invalid client credentials.", http.StatusUnauthorized)
		}
		return
	}

	// ARMORNET FORK: client.Secret is an argon2id hash, so upstream's
	// subtle.ConstantTimeCompare against the presented plaintext never matches.
	// Verify through Server.verifyClientSecret (server.go), which is the single
	// place any handler is allowed to compare a client secret.
	//
	// Re-apply this on an upstream Dex pull (see the Dex migration notes).
	if !(publicByPKCE && client.Public) && !s.verifyClientSecret(client.Secret, clientSecret) {
		if clientSecret == "" {
			s.logger.InfoContext(r.Context(), "missing client_secret on token request", "client_id", client.ID)
		} else {
			s.logger.InfoContext(r.Context(), "invalid client_secret on token request", "client_id", client.ID)
		}
		s.tokenErrHelper(w, errInvalidClient, "Invalid client credentials.", http.StatusUnauthorized)
		return
	}

	handler(w, r, client)
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		s.tokenErrHelper(w, errInvalidRequest, "method not allowed", http.StatusBadRequest)
		return
	}

	err := r.ParseForm()
	if err != nil {
		s.logger.ErrorContext(r.Context(), "could not parse request body", "err", err)
		s.tokenErrHelper(w, errInvalidRequest, "", http.StatusBadRequest)
		return
	}

	grantType := r.PostFormValue("grant_type")
	if !contains(s.supportedGrantTypes, grantType) {
		s.logger.ErrorContext(r.Context(), "unsupported grant type", "grant_type", grantType)
		s.tokenErrHelper(w, errUnsupportedGrantType, "", http.StatusBadRequest)
		return
	}
	switch grantType {
	case grantTypeDeviceCode:
		s.handleDeviceToken(w, r)
	case grantTypeAuthorizationCode:
		s.withPKCEOrSecretClient(w, r, s.handleAuthCode)
	case grantTypeRefreshToken:
		s.withClientFromStorage(w, r, s.handleRefreshToken)
	case grantTypePassword:
		s.withClientFromStorage(w, r, s.handlePasswordGrant)
	case grantTypeTokenExchange:
		s.withClientFromStorage(w, r, s.handleTokenExchange)
	case grantTypeClientCredentials:
		s.withClientFromStorage(w, r, s.handleClientCredentials)
	default:
		s.tokenErrHelper(w, errUnsupportedGrantType, "", http.StatusBadRequest)
	}
}

func (s *Server) calculateCodeChallenge(codeVerifier, codeChallengeMethod string) (string, error) {
	switch codeChallengeMethod {
	case codeChallengeMethodPlain:
		return codeVerifier, nil
	case codeChallengeMethodS256:
		shaSum := sha256.Sum256([]byte(codeVerifier))
		return base64.RawURLEncoding.EncodeToString(shaSum[:]), nil
	default:
		return "", fmt.Errorf("unknown challenge method (%v)", codeChallengeMethod)
	}
}

// handle an access token request https://tools.ietf.org/html/rfc6749#section-4.1.3
func (s *Server) handleAuthCode(w http.ResponseWriter, r *http.Request, client storage.Client) {
	ctx := r.Context()
	code := r.PostFormValue("code")
	redirectURI := r.PostFormValue("redirect_uri")

	if code == "" {
		s.tokenErrHelper(w, errInvalidRequest, `Required param: code.`, http.StatusBadRequest)
		return
	}

	authCode, err := s.storage.GetAuthCode(ctx, code)
	if err != nil || s.now().After(authCode.Expiry) || authCode.ClientID != client.ID {
		if err != storage.ErrNotFound {
			s.logger.ErrorContext(r.Context(), "failed to get auth code", "err", err)
			s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		} else {
			s.tokenErrHelper(w, errInvalidGrant, "Invalid or expired code parameter.", http.StatusBadRequest)
		}
		return
	}

	// RFC 7636 (PKCE)
	codeChallengeFromStorage := authCode.PKCE.CodeChallenge
	providedCodeVerifier := r.PostFormValue("code_verifier")

	// ARMORNET PATCH: a public client presented no secret (see
	// withPKCEOrSecretClient), so the verifier is its only proof of holding
	// the code. Without a challenge there is nothing to verify.
	if client.Public && codeChallengeFromStorage == "" {
		s.tokenErrHelper(w, errInvalidGrant, "PKCE is required for public clients.", http.StatusBadRequest)
		return
	}

	switch {
	case providedCodeVerifier != "" && codeChallengeFromStorage != "":
		calculatedCodeChallenge, err := s.calculateCodeChallenge(providedCodeVerifier, authCode.PKCE.CodeChallengeMethod)
		if err != nil {
			s.logger.ErrorContext(r.Context(), "failed to calculate code challenge", "err", err)
			s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
			return
		}
		if codeChallengeFromStorage != calculatedCodeChallenge {
			s.tokenErrHelper(w, errInvalidGrant, "Invalid code_verifier.", http.StatusBadRequest)
			return
		}
	case providedCodeVerifier != "":
		// Received no code_challenge on /auth, but a code_verifier on /token
		s.tokenErrHelper(w, errInvalidRequest, "No PKCE flow started. Cannot check code_verifier.", http.StatusBadRequest)
		return
	case codeChallengeFromStorage != "":
		// Received PKCE request on /auth, but no code_verifier on /token
		s.tokenErrHelper(w, errInvalidGrant, "Expecting parameter code_verifier in PKCE flow.", http.StatusBadRequest)
		return
	}

	if authCode.RedirectURI != redirectURI {
		s.tokenErrHelper(w, errInvalidRequest, "redirect_uri did not match URI from initial request.", http.StatusBadRequest)
		return
	}

	tokenResponse, err := s.exchangeAuthCode(ctx, w, authCode, client)
	if err != nil {
		s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		return
	}
	s.writeAccessToken(w, tokenResponse)
}

func (s *Server) exchangeAuthCode(ctx context.Context, w http.ResponseWriter, authCode storage.AuthCode, client storage.Client) (*accessTokenResponse, error) {
	accessToken, _, err := s.newAccessToken(ctx, client.ID, authCode.Claims, authCode.Scopes, authCode.Nonce, authCode.ConnectorID)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to create new access token", "err", err)
		s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		return nil, err
	}

	idToken, expiry, err := s.newIDToken(ctx, client.ID, authCode.Claims, authCode.Scopes, authCode.Nonce, accessToken, authCode.ID, authCode.ConnectorID)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to create ID token", "err", err)
		s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		return nil, err
	}

	if err := s.storage.DeleteAuthCode(ctx, authCode.ID); err != nil {
		s.logger.ErrorContext(ctx, "failed to delete auth code", "err", err)
		s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		return nil, err
	}

	reqRefresh := func() bool {
		// Ensure the connector supports refresh tokens.
		//
		// Connectors like `saml` do not implement RefreshConnector.
		conn, err := s.getConnector(ctx, authCode.ConnectorID)
		if err != nil {
			s.logger.ErrorContext(ctx, "connector not found", "connector_id", authCode.ConnectorID, "err", err)
			s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
			return false
		}

		_, ok := conn.Connector.(connector.RefreshConnector)
		if !ok {
			return false
		}

		for _, scope := range authCode.Scopes {
			if scope == scopeOfflineAccess {
				return true
			}
		}
		return false
	}()
	var refreshToken string
	if reqRefresh {
		refresh := storage.RefreshToken{
			ID:            storage.NewID(),
			Token:         storage.NewID(),
			ClientID:      authCode.ClientID,
			ConnectorID:   authCode.ConnectorID,
			Scopes:        authCode.Scopes,
			Claims:        authCode.Claims,
			Nonce:         authCode.Nonce,
			ConnectorData: authCode.ConnectorData,
			CreatedAt:     s.now(),
			LastUsed:      s.now(),
		}
		token := &internal.RefreshToken{
			RefreshId: refresh.ID,
			Token:     refresh.Token,
		}
		if refreshToken, err = internal.Marshal(token); err != nil {
			s.logger.ErrorContext(ctx, "failed to marshal refresh token", "err", err)
			s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
			return nil, err
		}

		if err := s.storage.CreateRefresh(ctx, refresh); err != nil {
			s.logger.ErrorContext(ctx, "failed to create refresh token", "err", err)
			s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
			return nil, err
		}

		// deleteToken determines if we need to delete the newly created refresh token
		// due to a failure in updating/creating the OfflineSession object for the
		// corresponding user.
		var deleteToken bool
		defer func() {
			if deleteToken {
				// Delete newly created refresh token from storage.
				if err := s.storage.DeleteRefresh(ctx, refresh.ID); err != nil {
					s.logger.ErrorContext(ctx, "failed to delete refresh token", "err", err)
					s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
					return
				}
			}
		}()

		tokenRef := storage.RefreshTokenRef{
			ID:        refresh.ID,
			ClientID:  refresh.ClientID,
			CreatedAt: refresh.CreatedAt,
			LastUsed:  refresh.LastUsed,
		}

		// Try to retrieve an existing OfflineSession object for the corresponding user.
		if session, err := s.storage.GetOfflineSessions(ctx, refresh.Claims.UserID, refresh.ConnectorID); err != nil {
			if err != storage.ErrNotFound {
				s.logger.ErrorContext(ctx, "failed to get offline session", "err", err)
				s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
				deleteToken = true
				return nil, err
			}
			offlineSessions := storage.OfflineSessions{
				UserID:  refresh.Claims.UserID,
				ConnID:  refresh.ConnectorID,
				Refresh: make(map[string]*storage.RefreshTokenRef),
			}
			offlineSessions.Refresh[tokenRef.ClientID] = &tokenRef

			// Create a new OfflineSession object for the user and add a reference object for
			// the newly received refreshtoken.
			if err := s.storage.CreateOfflineSessions(ctx, offlineSessions); err != nil {
				s.logger.ErrorContext(ctx, "failed to create offline session", "err", err)
				s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
				deleteToken = true
				return nil, err
			}
		} else {
			if oldTokenRef, ok := session.Refresh[tokenRef.ClientID]; ok {
				// Delete old refresh token from storage.
				if err := s.storage.DeleteRefresh(ctx, oldTokenRef.ID); err != nil && err != storage.ErrNotFound {
					s.logger.ErrorContext(ctx, "failed to delete refresh token", "err", err)
					s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
					deleteToken = true
					return nil, err
				}
			}

			// Update existing OfflineSession obj with new RefreshTokenRef.
			if err := s.storage.UpdateOfflineSessions(ctx, session.UserID, session.ConnID, func(old storage.OfflineSessions) (storage.OfflineSessions, error) {
				old.Refresh[tokenRef.ClientID] = &tokenRef
				return old, nil
			}); err != nil {
				s.logger.ErrorContext(ctx, "failed to update offline session", "err", err)
				s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
				deleteToken = true
				return nil, err
			}
		}
	}
	return s.toAccessTokenResponse(idToken, accessToken, refreshToken, expiry), nil
}

func (s *Server) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	const prefix = "Bearer "

	auth := r.Header.Get("authorization")
	if len(auth) < len(prefix) || !strings.EqualFold(prefix, auth[:len(prefix)]) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		s.tokenErrHelper(w, errAccessDenied, "Invalid bearer token.", http.StatusUnauthorized)
		return
	}
	rawIDToken := auth[len(prefix):]

	verifier := oidc.NewVerifier(s.issuerURL.String(), &signerKeySet{s.signer}, &oidc.Config{SkipClientIDCheck: true})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "failed to verify ID token", "err", err)
		s.tokenErrHelper(w, errAccessDenied, "Invalid bearer token.", http.StatusForbidden)
		return
	}

	var claims json.RawMessage
	if err := idToken.Claims(&claims); err != nil {
		s.logger.ErrorContext(r.Context(), "failed to decode ID token claims", "err", err)
		s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(claims)
}

func (s *Server) handlePasswordGrant(w http.ResponseWriter, r *http.Request, client storage.Client) {
	ctx := r.Context()
	// Parse the fields
	if err := r.ParseForm(); err != nil {
		s.tokenErrHelper(w, errInvalidRequest, "Couldn't parse data", http.StatusBadRequest)
		return
	}
	q := r.Form

	nonce := q.Get("nonce")
	// Some clients, like the old go-oidc, provide extra whitespace. Tolerate this.
	scopes := strings.Fields(q.Get("scope"))

	// Parse the scopes if they are passed
	var (
		unrecognized  []string
		invalidScopes []string
	)
	hasOpenIDScope := false
	for _, scope := range scopes {
		switch scope {
		case scopeOpenID:
			hasOpenIDScope = true
		case scopeOfflineAccess, scopeEmail, scopeProfile, scopeGroups, scopeFederatedID:
		default:
			peerID, ok := parseCrossClientScope(scope)
			if !ok {
				unrecognized = append(unrecognized, scope)
				continue
			}

			isTrusted, err := s.validateCrossClientTrust(ctx, client.ID, peerID)
			if err != nil {
				s.logger.ErrorContext(r.Context(), "error validating cross client trust", "client_id", client.ID, "peer_id", peerID, "err", err)
				s.tokenErrHelper(w, errInvalidClient, "Error validating cross client trust.", http.StatusBadRequest)
				return
			}
			if !isTrusted {
				invalidScopes = append(invalidScopes, scope)
			}
		}
	}
	if !hasOpenIDScope {
		s.tokenErrHelper(w, errInvalidRequest, `Missing required scope(s) ["openid"].`, http.StatusBadRequest)
		return
	}
	if len(unrecognized) > 0 {
		s.tokenErrHelper(w, errInvalidRequest, fmt.Sprintf("Unrecognized scope(s) %q", unrecognized), http.StatusBadRequest)
		return
	}
	if len(invalidScopes) > 0 {
		s.tokenErrHelper(w, errInvalidRequest, fmt.Sprintf("Client can't request scope(s) %q", invalidScopes), http.StatusBadRequest)
		return
	}

	// Which connector
	connID := s.passwordConnector
	conn, err := s.getConnector(ctx, connID)
	if err != nil {
		s.tokenErrHelper(w, errInvalidRequest, "Requested connector does not exist.", http.StatusBadRequest)
		return
	}

	passwordConnector, ok := conn.Connector.(connector.PasswordConnector)
	if !ok {
		s.tokenErrHelper(w, errInvalidRequest, "Requested password connector does not correct type.", http.StatusBadRequest)
		return
	}

	// Login
	username := q.Get("username")
	password := q.Get("password")
	identity, ok, err := passwordConnector.Login(ctx, parseScopes(scopes), username, password)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "failed to login user", "err", err)
		s.tokenErrHelper(w, errInvalidRequest, "Could not login user", http.StatusBadRequest)
		return
	}
	if !ok {
		s.tokenErrHelper(w, errAccessDenied, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Build the claims to send the id token
	claims := storage.Claims{
		UserID:            identity.UserID,
		Username:          identity.Username,
		PreferredUsername: identity.PreferredUsername,
		Email:             identity.Email,
		EmailVerified:     identity.EmailVerified,
		Groups:            identity.Groups,
	}

	accessToken, _, err := s.newAccessToken(ctx, client.ID, claims, scopes, nonce, connID)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "password grant failed to create new access token", "err", err)
		s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		return
	}

	idToken, expiry, err := s.newIDToken(ctx, client.ID, claims, scopes, nonce, accessToken, "", connID)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "password grant failed to create new ID token", "err", err)
		s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		return
	}

	reqRefresh := func() bool {
		// Ensure the connector supports refresh tokens.
		//
		// Connectors like `saml` do not implement RefreshConnector.
		_, ok := conn.Connector.(connector.RefreshConnector)
		if !ok {
			return false
		}

		for _, scope := range scopes {
			if scope == scopeOfflineAccess {
				return true
			}
		}
		return false
	}()
	var refreshToken string
	if reqRefresh {
		refresh := storage.RefreshToken{
			ID:          storage.NewID(),
			Token:       storage.NewID(),
			ClientID:    client.ID,
			ConnectorID: connID,
			Scopes:      scopes,
			Claims:      claims,
			Nonce:       nonce,
			// ConnectorData: authCode.ConnectorData,
			CreatedAt: s.now(),
			LastUsed:  s.now(),
		}
		token := &internal.RefreshToken{
			RefreshId: refresh.ID,
			Token:     refresh.Token,
		}
		if refreshToken, err = internal.Marshal(token); err != nil {
			s.logger.ErrorContext(r.Context(), "failed to marshal refresh token", "err", err)
			s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
			return
		}

		if err := s.storage.CreateRefresh(ctx, refresh); err != nil {
			s.logger.ErrorContext(r.Context(), "failed to create refresh token", "err", err)
			s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
			return
		}

		// deleteToken determines if we need to delete the newly created refresh token
		// due to a failure in updating/creating the OfflineSession object for the
		// corresponding user.
		var deleteToken bool
		defer func() {
			if deleteToken {
				// Delete newly created refresh token from storage.
				if err := s.storage.DeleteRefresh(ctx, refresh.ID); err != nil {
					s.logger.ErrorContext(r.Context(), "failed to delete refresh token", "err", err)
					s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
					return
				}
			}
		}()

		tokenRef := storage.RefreshTokenRef{
			ID:        refresh.ID,
			ClientID:  refresh.ClientID,
			CreatedAt: refresh.CreatedAt,
			LastUsed:  refresh.LastUsed,
		}

		// Try to retrieve an existing OfflineSession object for the corresponding user.
		if session, err := s.storage.GetOfflineSessions(ctx, refresh.Claims.UserID, refresh.ConnectorID); err != nil {
			if err != storage.ErrNotFound {
				s.logger.ErrorContext(r.Context(), "failed to get offline session", "err", err)
				s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
				deleteToken = true
				return
			}
			offlineSessions := storage.OfflineSessions{
				UserID:        refresh.Claims.UserID,
				ConnID:        refresh.ConnectorID,
				Refresh:       make(map[string]*storage.RefreshTokenRef),
				ConnectorData: identity.ConnectorData,
			}
			offlineSessions.Refresh[tokenRef.ClientID] = &tokenRef

			// Create a new OfflineSession object for the user and add a reference object for
			// the newly received refreshtoken.
			if err := s.storage.CreateOfflineSessions(ctx, offlineSessions); err != nil {
				s.logger.ErrorContext(r.Context(), "failed to create offline session", "err", err)
				s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
				deleteToken = true
				return
			}
		} else {
			if oldTokenRef, ok := session.Refresh[tokenRef.ClientID]; ok {
				// Delete old refresh token from storage.
				if err := s.storage.DeleteRefresh(ctx, oldTokenRef.ID); err != nil {
					if err == storage.ErrNotFound {
						s.logger.Warn("database inconsistent, refresh token missing", "token_id", oldTokenRef.ID)
					} else {
						s.logger.ErrorContext(r.Context(), "failed to delete refresh token", "err", err)
						s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
						deleteToken = true
						return
					}
				}
			}

			// Update existing OfflineSession obj with new RefreshTokenRef.
			if err := s.storage.UpdateOfflineSessions(ctx, session.UserID, session.ConnID, func(old storage.OfflineSessions) (storage.OfflineSessions, error) {
				old.Refresh[tokenRef.ClientID] = &tokenRef
				old.ConnectorData = identity.ConnectorData
				return old, nil
			}); err != nil {
				s.logger.ErrorContext(r.Context(), "failed to update offline session", "err", err)
				s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
				deleteToken = true
				return
			}
		}
	}

	resp := s.toAccessTokenResponse(idToken, accessToken, refreshToken, expiry)
	s.writeAccessToken(w, resp)
}

func (s *Server) handleTokenExchange(w http.ResponseWriter, r *http.Request, client storage.Client) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		s.logger.ErrorContext(r.Context(), "could not parse request body", "err", err)
		s.tokenErrHelper(w, errInvalidRequest, "", http.StatusBadRequest)
		return
	}
	q := r.Form

	scopes := strings.Fields(q.Get("scope"))            // OPTIONAL, map to issued token scope
	requestedTokenType := q.Get("requested_token_type") // OPTIONAL, default to access token
	if requestedTokenType == "" {
		requestedTokenType = tokenTypeAccess
	}
	subjectToken := q.Get("subject_token")          // REQUIRED
	subjectTokenType := q.Get("subject_token_type") // REQUIRED
	connID := q.Get("connector_id")                 // REQUIRED, not in RFC

	switch subjectTokenType {
	case tokenTypeID, tokenTypeAccess: // ok, continue
	default:
		s.tokenErrHelper(w, errRequestNotSupported, "Invalid subject_token_type.", http.StatusBadRequest)
		return
	}

	if subjectToken == "" {
		s.tokenErrHelper(w, errInvalidRequest, "Missing subject_token", http.StatusBadRequest)
		return
	}

	conn, err := s.getConnector(ctx, connID)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "failed to get connector", "err", err)
		s.tokenErrHelper(w, errInvalidRequest, "Requested connector does not exist.", http.StatusBadRequest)
		return
	}
	teConn, ok := conn.Connector.(connector.TokenIdentityConnector)
	if !ok {
		s.logger.ErrorContext(r.Context(), "connector doesn't implement token exchange", "connector_id", connID)
		s.tokenErrHelper(w, errInvalidRequest, "Requested connector does not exist.", http.StatusBadRequest)
		return
	}
	identity, err := teConn.TokenIdentity(ctx, subjectTokenType, subjectToken)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "failed to verify subject token", "err", err)
		s.tokenErrHelper(w, errAccessDenied, "", http.StatusUnauthorized)
		return
	}

	claims := storage.Claims{
		UserID:            identity.UserID,
		Username:          identity.Username,
		PreferredUsername: identity.PreferredUsername,
		Email:             identity.Email,
		EmailVerified:     identity.EmailVerified,
		Groups:            identity.Groups,
	}
	resp := accessTokenResponse{
		IssuedTokenType: requestedTokenType,
		TokenType:       "bearer",
	}
	var expiry time.Time
	switch requestedTokenType {
	case tokenTypeID:
		resp.AccessToken, expiry, err = s.newIDToken(r.Context(), client.ID, claims, scopes, "", "", "", connID)
	case tokenTypeAccess:
		resp.AccessToken, expiry, err = s.newAccessToken(r.Context(), client.ID, claims, scopes, "", connID)
	default:
		s.tokenErrHelper(w, errRequestNotSupported, "Invalid requested_token_type.", http.StatusBadRequest)
		return
	}
	if err != nil {
		s.logger.ErrorContext(r.Context(), "token exchange failed to create new token", "requested_token_type", requestedTokenType, "err", err)
		s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		return
	}
	resp.ExpiresIn = int(time.Until(expiry).Seconds())

	// Token response must include cache headers https://tools.ietf.org/html/rfc6749#section-5.1
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

type accessTokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in,omitempty"`
	RefreshToken    string `json:"refresh_token,omitempty"`
	IDToken         string `json:"id_token,omitempty"`
	Scope           string `json:"scope,omitempty"`
}

func (s *Server) toAccessTokenResponse(idToken, accessToken, refreshToken string, expiry time.Time) *accessTokenResponse {
	return &accessTokenResponse{
		AccessToken:  accessToken,
		TokenType:    "bearer",
		ExpiresIn:    int(expiry.Sub(s.now()).Seconds()),
		RefreshToken: refreshToken,
		IDToken:      idToken,
	}
}

func (s *Server) writeAccessToken(w http.ResponseWriter, resp *accessTokenResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		// TODO(nabokihms): error with context
		s.logger.Error("failed to marshal access token response", "err", err)
		s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))

	// Token response must include cache headers https://tools.ietf.org/html/rfc6749#section-5.1
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Write(data)
}

func (s *Server) renderError(r *http.Request, w http.ResponseWriter, status int, description string) {
	if err := s.templates.err(r, w, status, description); err != nil {
		s.logger.ErrorContext(r.Context(), "server template error", "err", err)
	}
}

func (s *Server) tokenErrHelper(w http.ResponseWriter, typ string, description string, statusCode int) {
	if err := tokenErr(w, typ, description, statusCode); err != nil {
		// TODO(nabokihms): error with context
		s.logger.Error("token error response", "err", err)
	}
}

// ARMORNET FORK: handleClientCredentials implements RFC 6749 §4.4 (client
// credentials grant). The client has already been authenticated (client_id +
// client_secret verified via constant-time compare) by withClientFromStorage
// before this function is called.
//
// Design notes vs upstream Dex:
//   - sub is the plain client.ID string, NOT the base64-protobuf envelope that
//     genSubject produces for user tokens. This lets the armornet AgentTokenProvider
//     split "agent:<org_id>:<uuid>" without any Dex-internal decoding.
//   - User-context scopes (profile, email, groups, offline_access) are silently
//     ignored — there is no user, connector, or session behind this grant.
//   - openid scope is required; everything else is stripped.
//   - No refresh token is ever issued.
func (s *Server) handleClientCredentials(w http.ResponseWriter, r *http.Request, client storage.Client) {
	scopes := strings.Fields(r.FormValue("scope"))

	hasOpenID := false
	for _, sc := range scopes {
		if sc == scopeOpenID {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		s.tokenErrHelper(w, errInvalidRequest, `Missing required scope(s) ["openid"].`, http.StatusBadRequest)
		return
	}

	token, expiry, err := s.newClientCredentialsToken(r.Context(), client.ID)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "client_credentials: sign token", "client_id", client.ID, "err", err)
		s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	s.writeAccessToken(w, s.toAccessTokenResponse("", token, "", expiry))
}

// newClientCredentialsToken signs a JWT whose sub is clientID as a verbatim
// string. It intentionally bypasses genSubject (which base64-encodes a protobuf
// envelope of {UserID, ConnID}) because client credentials tokens have no user
// or connector identity. The resulting JWT is verifiable via Dex's OIDC JWKS
// endpoint with SkipClientIDCheck: true.
func (s *Server) newClientCredentialsToken(ctx context.Context, clientID string) (string, time.Time, error) {
	issuedAt := s.now()
	expiry := issuedAt.Add(s.idTokensValidFor)

	tok := idTokenClaims{
		Issuer:   s.issuerURL.String(),
		Subject:  clientID,
		Audience: audience{clientID},
		Expiry:   expiry.Unix(),
		IssuedAt: issuedAt.Unix(),
	}
	payload, err := json.Marshal(tok)
	if err != nil {
		return "", expiry, fmt.Errorf("marshal claims: %w", err)
	}
	signed, err := s.signer.Sign(ctx, payload)
	if err != nil {
		return "", expiry, fmt.Errorf("sign token: %w", err)
	}
	return signed, expiry, nil
}

// Check for username prompt override from connector. Defaults to "Username".
func usernamePrompt(conn connector.PasswordConnector) string {
	if attr := conn.Prompt(); attr != "" {
		return attr
	}
	return "Username"
}

// ARMORNET FORK: handleRevoke implements RFC 7009 refresh token revocation.
// The client is authenticated via HTTP Basic Auth (client_id + client_secret)
// before this handler is invoked by withClientFromStorage.
//
// Per RFC 7009 §2.2: the server MUST respond with HTTP 200 for any token that
// was already invalid, unknown, or revoked — only return non-200 for server errors.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	s.withClientFromStorage(w, r, s.handleTokenRevoke)
}

func (s *Server) handleTokenRevoke(w http.ResponseWriter, r *http.Request, client storage.Client) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tokenStr := r.FormValue("token")
	if tokenStr == "" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Decode the opaque refresh token envelope.
	var tok internal.RefreshToken
	if err := internal.Unmarshal(tokenStr, &tok); err != nil {
		// Unknown format — treat as already-invalid per RFC 7009.
		w.WriteHeader(http.StatusOK)
		return
	}

	refresh, err := s.storage.GetRefresh(ctx, tok.RefreshId)
	if err != nil {
		if err == storage.ErrNotFound {
			w.WriteHeader(http.StatusOK)
			return
		}
		s.logger.ErrorContext(ctx, "revoke: failed to get refresh token", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// A client may only revoke its own tokens.
	if refresh.ClientID != client.ID {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Constant-time verification that the caller holds the actual secret value.
	if subtle.ConstantTimeCompare([]byte(tok.Token), []byte(refresh.Token)) != 1 {
		w.WriteHeader(http.StatusOK)
		return
	}

	if err := s.storage.DeleteRefresh(ctx, refresh.ID); err != nil && err != storage.ErrNotFound {
		s.logger.ErrorContext(ctx, "revoke: failed to delete refresh token", "id", refresh.ID, "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Remove the client's entry from the user's offline session map.
	updateErr := s.storage.UpdateOfflineSessions(ctx, refresh.Claims.UserID, refresh.ConnectorID,
		func(old storage.OfflineSessions) (storage.OfflineSessions, error) {
			delete(old.Refresh, client.ID)
			return old, nil
		},
	)
	if updateErr != nil && updateErr != storage.ErrNotFound {
		s.logger.WarnContext(ctx, "revoke: failed to update offline session", "err", updateErr)
	}

	w.WriteHeader(http.StatusOK)
}

// ARMORNET FORK: handleEndSession implements OpenID Connect RP-Initiated Logout 1.0.
// Accepts GET or POST. Recognises id_token_hint, post_logout_redirect_uri, and state.
// On success it deletes the user's offline session and all associated refresh tokens,
// then either redirects to post_logout_redirect_uri or returns 200.
func (s *Server) handleEndSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		s.renderError(r, w, http.StatusBadRequest, "Failed to parse request.")
		return
	}

	idTokenHint := r.FormValue("id_token_hint")
	postLogoutURI := r.FormValue("post_logout_redirect_uri")
	state := r.FormValue("state")

	if idTokenHint != "" {
		// Verify the ID token using Dex's own signing keys (same as /userinfo).
		verifier := oidc.NewVerifier(
			s.issuerURL.String(),
			&signerKeySet{s.signer},
			&oidc.Config{SkipClientIDCheck: true, SkipExpiryCheck: true},
		)
		idToken, err := verifier.Verify(ctx, idTokenHint)
		if err != nil {
			s.logger.WarnContext(ctx, "end_session: invalid id_token_hint", "err", err)
			// Per spec: ignore invalid hint rather than returning an error.
		} else {
			// Decode the subject protobuf envelope to get userID + connectorID.
			var subj internal.IDTokenSubject
			if err := internal.Unmarshal(idToken.Subject, &subj); err == nil {
				s.terminateUserSession(ctx, subj.UserId, subj.ConnId)
			}
		}
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if postLogoutURI != "" {
		target := postLogoutURI
		if state != "" {
			target += "?state=" + url.QueryEscape(state)
		}
		http.Redirect(w, r, target, http.StatusFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// terminateUserSession deletes all refresh tokens and the offline session for a
// given (userID, connectorID) pair. It also fans out OIDC Back-Channel Logout 1.0
// logout_tokens to every registered client that has a BackchannelLogoutURI.
// Errors are logged but not propagated — the caller has already committed to treating
// the session as ended.
func (s *Server) terminateUserSession(ctx context.Context, userID, connID string) {
	session, err := s.storage.GetOfflineSessions(ctx, userID, connID)
	if err != nil {
		if err != storage.ErrNotFound {
			s.logger.ErrorContext(ctx, "end_session: get offline session", "err", err)
		}
		return
	}

	// Fan-out: POST a logout_token to every client that registered a BackchannelLogoutURI.
	// Each POST runs in its own goroutine with an independent per-request timeout (Trap 4).
	var wg sync.WaitGroup
	for clientID := range session.Refresh {
		client, err := s.storage.GetClient(ctx, clientID)
		if err != nil {
			s.logger.WarnContext(ctx, "end_session: get client for backchannel logout", "client_id", clientID, "err", err)
			continue
		}
		if client.BackchannelLogoutURI == "" {
			continue // Trap 7: silently skip clients that haven't registered a back-channel URI
		}
		wg.Add(1)
		go func(c storage.Client) {
			defer wg.Done()
			s.sendBackchannelLogout(ctx, userID, c)
		}(client)
	}

	for _, ref := range session.Refresh {
		if delErr := s.storage.DeleteRefresh(ctx, ref.ID); delErr != nil && delErr != storage.ErrNotFound {
			s.logger.WarnContext(ctx, "end_session: delete refresh token", "id", ref.ID, "err", delErr)
		}
	}

	if delErr := s.storage.DeleteOfflineSessions(ctx, userID, connID); delErr != nil && delErr != storage.ErrNotFound {
		s.logger.WarnContext(ctx, "end_session: delete offline session", "err", delErr)
	}

	// Wait for all fan-out goroutines with an overall cap (Trap 4).
	fanOutDone := make(chan struct{})
	go func() { wg.Wait(); close(fanOutDone) }()
	select {
	case <-fanOutDone:
	case <-time.After(10 * time.Second):
		s.logger.WarnContext(ctx, "end_session: backchannel logout fan-out exceeded 10s cap")
	}
}

// backchannelLogoutEventURI is the OIDC Back-Channel Logout 1.0 event type URI (§4.1).
const backchannelLogoutEventURI = "http://schemas.openid.net/event/backchannel-logout"

// backchannelLogoutToken is the claim set for a logout_token JWT (OIDC BCL 1.0 §4.1).
type backchannelLogoutToken struct {
	Issuer   string              `json:"iss"`
	Subject  string              `json:"sub"`
	Audience audience            `json:"aud"`
	IssuedAt int64               `json:"iat"`
	Expiry   int64               `json:"exp"`
	JTI      string              `json:"jti"`
	Events   map[string]struct{} `json:"events"`
}

// sendBackchannelLogout signs a logout_token and POSTs it to client.BackchannelLogoutURI.
// The call applies an independent 5-second HTTP timeout (Trap 4), so a slow RP cannot
// block the fan-out loop.
func (s *Server) sendBackchannelLogout(ctx context.Context, subject string, client storage.Client) {
	now := time.Now()
	claims := backchannelLogoutToken{
		Issuer:   s.issuerURL.String(),
		Subject:  subject, // Trap 5: full Dex compound subject (connector_id:remote_subject)
		Audience: audience{client.ID},
		IssuedAt: now.Unix(),
		Expiry:   now.Add(2 * time.Minute).Unix(),
		JTI:      storage.NewID(),
		Events:   map[string]struct{}{backchannelLogoutEventURI: {}},
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		s.logger.ErrorContext(ctx, "backchannel-logout: marshal claims", "client_id", client.ID, "err", err)
		return
	}
	logoutToken, err := s.signer.Sign(ctx, payload)
	if err != nil {
		s.logger.ErrorContext(ctx, "backchannel-logout: sign token", "client_id", client.ID, "err", err)
		return
	}

	// Trap 4: each POST has its own timeout — a slow RP times out independently.
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	body := url.Values{"logout_token": {logoutToken}}.Encode()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, client.BackchannelLogoutURI,
		strings.NewReader(body))
	if err != nil {
		s.logger.WarnContext(ctx, "backchannel-logout: build request", "client_id", client.ID, "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.logger.WarnContext(ctx, "backchannel-logout: POST failed",
			"client_id", client.ID, "uri", client.BackchannelLogoutURI, "err", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s.logger.WarnContext(ctx, "backchannel-logout: non-2xx response",
			"client_id", client.ID, "status", resp.StatusCode)
	}
}
