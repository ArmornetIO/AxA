package authn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type agentClaims struct {
	subject string
	orgID   string
	agentID string
}

func (c *agentClaims) Subject() string  { return c.subject }
func (c *agentClaims) OrgID() string    { return c.orgID }
func (c *agentClaims) Groups() []string { return nil }
func (c *agentClaims) IsAgent() bool    { return true }
func (c *agentClaims) AgentID() string  { return c.agentID }

// AgentPrincipal is implemented only by claims minted for a machine agent via
// client-credentials auth (agentClaims). It exists so consumers can identify an
// agent caller through a real type assertion rather than by string-parsing the
// subject. Its OrgID is TRUSTED — a segment of the Dex-signed subject
// "agent:<org>:<uuid>" validated by AgentTokenProvider — so a caller may scope
// the agent to that org without requiring a users-table membership row.
type AgentPrincipal interface {
	// IsAgent is a marker distinguishing agent claims from human session/PAT
	// claims that may coincidentally expose OrgID().
	IsAgent() bool
	// OrgID is the agent's trusted organization (subject segment 2).
	OrgID() string
	// AgentID is the agent's per-instance uuid (subject segment 3).
	AgentID() string
}

// AgentTokenProvider validates Dex client-credentials JWTs whose sub follows
// the convention "agent:<org_id>:<agent_uuid>".
//
// @aag component=auth-provider
// @aag container=rest-server
// @aag layer=api
// @aag boundary=internal
// @aag description=OIDC JWT validator for agent machine-to-machine authentication
// @aag authenticates-with=oidc
// @aag handles-data=auth-tokens
type AgentTokenProvider struct {
	verifier *oidc.IDTokenVerifier
}

// NewAgentTokenProvider constructs an AgentTokenProvider via OIDC HTTP discovery.
// Use NewAgentTokenProviderFromVerifier when the verifier is already available
// in-process (e.g. from dex.Server.NewVerifier).
func NewAgentTokenProvider(ctx context.Context, issuerURL string) (*AgentTokenProvider, error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("agent auth: OIDC discovery failed for %s: %w", issuerURL, err)
	}
	// SkipClientIDCheck: client_credentials tokens carry the client as audience,
	// not the BFF client ID.
	return &AgentTokenProvider{
		verifier: provider.Verifier(&oidc.Config{SkipClientIDCheck: true}),
	}, nil
}

// NewAgentTokenProviderFromVerifier constructs an AgentTokenProvider from a
// pre-built verifier, bypassing HTTP discovery entirely.
func NewAgentTokenProviderFromVerifier(v *oidc.IDTokenVerifier) *AgentTokenProvider {
	return &AgentTokenProvider{verifier: v}
}

// Authenticate answers ErrNoCredential for anything that is not an agent token, and
// does so before opening a span: in a Service every cookie request passes
// through here first, and a span per skip would read as an auth failure.
func (p *AgentTokenProvider) Authenticate(ctx context.Context, r *http.Request) (Claims, error) {
	// Handshake-aware: an agent connecting over a WebSocket may present its
	// token in the subprotocol, because a browser has no way to set a header.
	// On any other request this is exactly BearerToken.
	raw := HandshakeBearerToken(r)
	if raw == "" || !isAgentToken(raw) {
		return nil, ErrNoCredential
	}

	ctx, span := otel.Tracer("armornet/auth").Start(ctx, "auth.agent_oidc.validate",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attribute.String("auth.method", "agent_oidc")),
	)
	defer span.End()

	token, err := p.verifier.Verify(ctx, raw)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "token verification failed")
		return nil, fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	parts := strings.SplitN(token.Subject, ":", 3)
	if len(parts) != 3 || parts[0] != "agent" {
		span.SetStatus(codes.Error, "not an agent token")
		return nil, fmt.Errorf("%w: not an agent token", ErrUnauthorized)
	}
	span.SetAttributes(
		attribute.String("auth.subject", token.Subject),
		attribute.String("auth.org_id", parts[1]),
		attribute.String("auth.agent_id", parts[2]),
	)
	return &agentClaims{
		subject: token.Subject,
		orgID:   parts[1],
		agentID: parts[2],
	}, nil
}

// isAgentToken reports whether an UNVERIFIED token claims an agent subject.
// It decides whether the agent provider owns the request, and owning it means a
// failure ends the chain — so it reads the sub claim, not the whole payload: an
// "agent:" in a display name must not claim a user's token.
func isAgentToken(raw string) bool {
	parts := strings.SplitN(raw, ".", 3)
	if len(parts) != 3 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return false
	}
	return strings.HasPrefix(claims.Sub, "agent:")
}
