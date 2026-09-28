package web

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// BrowserScopes omits offline_access (an unused refresh token is just a credential
// to leak); federated:id names the answering connector, which the callback checks.
var BrowserScopes = []string{oidc.ScopeOpenID, "email", "profile", "federated:id"}

// BrowserScopeParam is BrowserScopes as the space-separated `scope` value the
// hand-built authorize URLs carry, so they cannot drift from the exchange.
func BrowserScopeParam() string { return strings.Join(BrowserScopes, " ") }

// StepUpScopeParam asks for the upstream user id (federated:id) and login
// (profile) and nothing else — a step-up proves an account, it collects no email.
func StepUpScopeParam() string { return oidc.ScopeOpenID + " profile federated:id" }

// DexClient never sends a token back: sign-out is local, the ID token read once.
type DexClient interface {
	Exchange(ctx context.Context, code, verifier string) (*TokenSet, error)
	ValidateIDToken(ctx context.Context, raw string) (*IDTokenClaims, error)
}

// TokenSet is what the callback keeps from a code exchange, in memory only:
// the ID token to verify, and the expiry that bounds the session.
type TokenSet struct {
	IDToken string
	Expiry  time.Time
}

// IDTokenClaims holds validated claims extracted from an ID token.
type IDTokenClaims struct {
	Subject string
	OrgID   string
	Nonce   string
	Email   string
	// EmailVerified is the provider's word that Email belongs to this login;
	// without it Email is whatever the account typed.
	EmailVerified bool
	Name          string
	// ConnectorID (federated:id) is the upstream that answered; unchecked, a
	// connector the browser swapped in, maybe another org's, is trusted.
	ConnectorID    string
	UpstreamUserID string
	Username       string
}

// OIDCDexClient discovers lazily: an embedded issuer is still starting when the
// host does.
type OIDCDexClient struct {
	issuerURL    string
	clientID     string
	clientSecret string
	redirectURI  string

	mu           sync.Mutex
	provider     *oidc.Provider
	oauth2Config *oauth2.Config
}

// NewOIDCDexClient builds a client that will discover the issuer on first use.
func NewOIDCDexClient(_ context.Context, issuerURL, clientID, clientSecret, redirectURI string) (*OIDCDexClient, error) {
	return &OIDCDexClient{
		issuerURL:    issuerURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURI:  redirectURI,
	}, nil
}

func (c *OIDCDexClient) ensureProvider(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.provider != nil {
		return nil
	}
	provider, err := oidc.NewProvider(ctx, c.issuerURL)
	if err != nil {
		return fmt.Errorf("dex client: OIDC discovery failed for %s: %w", c.issuerURL, err)
	}
	c.provider = provider
	c.oauth2Config = &oauth2.Config{
		ClientID:     c.clientID,
		ClientSecret: c.clientSecret,
		RedirectURL:  c.redirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       BrowserScopes,
	}
	return nil
}

// Exchange performs the authorization-code → token exchange with PKCE verifier.
func (c *OIDCDexClient) Exchange(ctx context.Context, code, verifier string) (*TokenSet, error) {
	if err := c.ensureProvider(ctx); err != nil {
		return nil, err
	}
	token, err := c.oauth2Config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		return nil, fmt.Errorf("dex client: code exchange failed: %w", err)
	}
	rawID, _ := token.Extra("id_token").(string)
	if rawID == "" {
		return nil, fmt.Errorf("dex client: id_token missing from token response")
	}
	expiry := token.Expiry
	if expiry.IsZero() {
		expiry = time.Now().Add(time.Hour)
	}
	return &TokenSet{IDToken: rawID, Expiry: expiry}, nil
}

// ValidateIDToken verifies the raw ID token JWT and extracts claims.
func (c *OIDCDexClient) ValidateIDToken(ctx context.Context, raw string) (*IDTokenClaims, error) {
	if err := c.ensureProvider(ctx); err != nil {
		return nil, err
	}
	token, err := c.provider.Verifier(&oidc.Config{ClientID: c.clientID}).Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("dex client: ID token verification failed: %w", err)
	}
	var claims struct {
		Subject         string `json:"sub"`
		Nonce           string `json:"nonce"`
		Email           string `json:"email"`
		EmailVerified   bool   `json:"email_verified"`
		Name            string `json:"name"`
		Username        string `json:"preferred_username"`
		FederatedClaims struct {
			ConnectorID string `json:"connector_id"`
			UserID      string `json:"user_id"`
		} `json:"federated_claims"`
	}
	if err := token.Claims(&claims); err != nil {
		return nil, fmt.Errorf("dex client: failed to parse structured claims: %w", err)
	}
	// Loosely, so a non-string org_id is ignored rather than failing sign-in.
	var loose map[string]any
	_ = token.Claims(&loose)
	orgID, _ := loose["org_id"].(string)
	return &IDTokenClaims{
		Subject:        claims.Subject,
		OrgID:          orgID,
		Nonce:          claims.Nonce,
		Email:          claims.Email,
		EmailVerified:  claims.EmailVerified,
		Name:           claims.Name,
		ConnectorID:    claims.FederatedClaims.ConnectorID,
		UpstreamUserID: claims.FederatedClaims.UserID,
		Username:       claims.Username,
	}, nil
}

// ValidateLogoutToken implements LogoutTokenVerifier so one client serves both
// directions of the issuer conversation.
func (c *OIDCDexClient) ValidateLogoutToken(ctx context.Context, raw string) (*LogoutTokenClaims, error) {
	if err := c.ensureProvider(ctx); err != nil {
		return nil, err
	}
	return ValidateLogoutToken(ctx, c.provider.Verifier(&oidc.Config{ClientID: c.clientID}), raw)
}
