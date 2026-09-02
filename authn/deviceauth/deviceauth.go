// Package deviceauth drives the OAuth 2.0 Device Authorization Grant
// (RFC 8628) from a command-line client.
//
// It exists so a human can sign in to Armornet from a machine that has no
// browser, no callback listener, and no client secret: the CLI asks for a code,
// the person approves it in a browser they are already signed in to, and the CLI
// polls until tokens come back.
//
// This authenticates a PERSON. It is not how an agent authenticates — an agent
// is a machine, runs unattended, and uses client credentials. The two identities
// coexist deliberately (see docs/wip/per-org-proxy-routing.md).
package deviceauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// grantType is the RFC 8628 device grant identifier.
const grantType = "urn:ietf:params:oauth:grant-type:device_code"

// defaultInterval is the poll cadence when the server names none. RFC 8628
// says 5 seconds.
const defaultInterval = 5 * time.Second

// Authorization is what the server hands back when a device flow starts: the
// code to show the user, and the code the client polls with.
type Authorization struct {
	// UserCode is shown to the person. Short and human-transcribable.
	UserCode string `json:"user_code"`
	// VerificationURI is where they enter it.
	VerificationURI string `json:"verification_uri"`
	// VerificationURIComplete has the code pre-filled. Optional per the RFC —
	// offer it as a convenience, never as the only instruction, because the user
	// may be reading a terminal on a different machine than the browser.
	VerificationURIComplete string `json:"verification_uri_complete"`

	// DeviceCode is the client's polling credential. Never display it: it is the
	// bearer of this pending authorization.
	DeviceCode string `json:"device_code"`
	// ExpiresIn is the authorization's lifetime in seconds.
	ExpiresIn int `json:"expires_in"`
	// Interval is the minimum poll cadence in seconds.
	Interval int `json:"interval"`
}

// Token is a completed authorization.
type Token struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// Client talks to one issuer's device endpoints.
type Client struct {
	// IssuerURL is the OIDC issuer base, e.g. https://armornet.io/dex.
	IssuerURL string
	// ClientID is the public client the CLI authenticates as.
	ClientID string
	// ClientSecret is sent only because this deployment's Dex compares it on the
	// device-token exchange even for a public client. It is an identifier, not a
	// credential — a distributed binary cannot keep a secret, and the flow's real
	// protection is a human approving a one-time code in a browser. Leave empty
	// against an issuer that correctly omits the check.
	ClientSecret string
	// Scopes requested. Defaults to openid when empty.
	Scopes []string

	HTTPClient *http.Client

	// baseInterval overrides the RFC 8628 poll cadence. Unexported and only set
	// by tests: a real client must honour the server's interval, and exporting
	// this would invite someone to poll faster than they were told to.
	baseInterval time.Duration
}

// pollBase is the starting poll cadence: the server's interval when it named
// one, else the RFC default.
func (c *Client) pollBase(auth Authorization) time.Duration {
	if c.baseInterval > 0 {
		return c.baseInterval
	}
	if auth.Interval > 0 {
		return time.Duration(auth.Interval) * time.Second
	}
	return defaultInterval
}

// slowDownStep is how much a `slow_down` adds to the cadence. RFC 8628 says
// increase by 5 seconds.
func (c *Client) slowDownStep() time.Duration {
	if c.baseInterval > 0 {
		return c.baseInterval
	}
	return defaultInterval
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// ErrAccessDenied reports that the user actively refused the request. Unlike a
// timeout this is final — re-polling would be wrong.
var ErrAccessDenied = errors.New("deviceauth: the request was denied")

// ErrExpired reports that the user code lapsed before anyone approved it.
var ErrExpired = errors.New("deviceauth: the code expired before it was approved")

// Authorize begins a device flow and returns the codes. Nothing is authenticated
// yet — the caller shows UserCode/VerificationURI to the person, then calls Wait.
func (c *Client) Authorize(ctx context.Context) (Authorization, error) {
	scopes := c.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}
	form := url.Values{
		"client_id": {c.ClientID},
		"scope":     {strings.Join(scopes, " ")},
	}
	if c.ClientSecret != "" {
		form.Set("client_secret", c.ClientSecret)
	}

	body, _, err := c.post(ctx, "/device/code", form)
	if err != nil {
		return Authorization{}, err
	}
	var auth Authorization
	if err := json.Unmarshal(body, &auth); err != nil {
		return Authorization{}, fmt.Errorf("deviceauth: parse device code response: %w", err)
	}
	if auth.DeviceCode == "" || auth.UserCode == "" {
		return Authorization{}, fmt.Errorf("deviceauth: issuer returned no device code")
	}
	return auth, nil
}

// Wait polls until the user approves, refuses, or the code expires.
//
// It honours the server's interval and backs off on the server's request
// (slow_down), because polling faster than told is how a client gets itself
// rate-limited or blocked.
func (c *Client) Wait(ctx context.Context, auth Authorization) (Token, error) {
	interval := c.pollBase(auth)

	// Bound the wait by the code's own lifetime — polling a code the server has
	// already forgotten is pure noise.
	if auth.ExpiresIn > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(auth.ExpiresIn)*time.Second)
		defer cancel()
	}

	form := url.Values{
		"grant_type":  {grantType},
		"device_code": {auth.DeviceCode},
		"client_id":   {c.ClientID},
	}
	if c.ClientSecret != "" {
		form.Set("client_secret", c.ClientSecret)
	}

	for {
		body, status, err := c.post(ctx, "/token", form)
		if err != nil {
			return Token{}, err
		}
		if status == http.StatusOK {
			var tok Token
			if err := json.Unmarshal(body, &tok); err != nil {
				return Token{}, fmt.Errorf("deviceauth: parse token response: %w", err)
			}
			return tok, nil
		}

		switch oauthError(body) {
		case "authorization_pending":
			// Expected: nobody has approved it yet.
		case "slow_down":
			// The server is telling us to back off.
			interval += c.slowDownStep()
		case "access_denied":
			return Token{}, ErrAccessDenied
		case "expired_token":
			return Token{}, ErrExpired
		default:
			return Token{}, fmt.Errorf("deviceauth: token exchange failed (%d): %s", status, truncate(body))
		}

		select {
		case <-ctx.Done():
			// A deadline here means the code lapsed, which is a distinct and
			// actionable outcome — not a generic cancellation.
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return Token{}, ErrExpired
			}
			return Token{}, ctx.Err()
		case <-time.After(interval):
		}
	}
}

// ErrRefreshRejected reports that the issuer no longer honours the refresh
// token — revoked, expired or rotated away. The person must sign in again.
var ErrRefreshRejected = errors.New("deviceauth: the refresh token was rejected")

// Refresh trades a refresh token for fresh tokens, so a long-running holder of
// a device session keeps a current ID token without asking the person again.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (Token, error) {
	if refreshToken == "" {
		return Token{}, ErrRefreshRejected
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {c.ClientID},
	}
	if c.ClientSecret != "" {
		form.Set("client_secret", c.ClientSecret)
	}
	body, status, err := c.post(ctx, "/token", form)
	if err != nil {
		return Token{}, err
	}
	if status != http.StatusOK {
		if oauthError(body) == "invalid_grant" {
			return Token{}, ErrRefreshRejected
		}
		return Token{}, fmt.Errorf("deviceauth: refresh failed (%d): %s", status, truncate(body))
	}
	var tok Token
	if err := json.Unmarshal(body, &tok); err != nil {
		return Token{}, fmt.Errorf("deviceauth: parse refresh response: %w", err)
	}
	return tok, nil
}

// post issues a form POST to a path under the issuer and returns body + status.
// A non-2xx is NOT an error here: the device grant signals its normal states
// (pending, slow_down) through 4xx bodies, so the caller inspects them.
func (c *Client) post(ctx context.Context, path string, form url.Values) ([]byte, int, error) {
	endpoint := strings.TrimSuffix(c.IssuerURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("deviceauth: POST %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("deviceauth: read %s: %w", endpoint, err)
	}
	return body, resp.StatusCode, nil
}

// oauthError pulls the OAuth2 `error` code out of a response body, or "" when
// the body is not an OAuth2 error object.
func oauthError(body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	return e.Error
}

func truncate(b []byte) string {
	const max = 200
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "…"
}
