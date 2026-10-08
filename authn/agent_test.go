package authn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// makeJWT constructs a minimal unsigned JWT with the given payload map.
// Only the payload matters for isAgentToken; signature is a dummy.
func makeJWT(t *testing.T, payload map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(payload)
	require.NoError(t, err)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	body := base64.RawURLEncoding.EncodeToString(raw)
	return header + "." + body + ".fakesig"
}

// protobufLikeSub simulates the opaque base64 subject that Dex generates for
// normal user tokens via genSubject(). The exact bytes don't matter — what
// matters is that it does NOT contain the literal string "agent:".
func protobufLikeSub() string {
	// proto.Marshal({UserId: "user123", ConnId: "mock"}) produces some bytes.
	// We use a hand-crafted base64 that won't accidentally contain "agent:".
	return base64.RawURLEncoding.EncodeToString([]byte("\x0a\x06user123\x12\x04mock"))
}

// ── isAgentToken ──────────────────────────────────────────────────────────────

func TestIsAgentToken_PlainAgentSub(t *testing.T) {
	tok := makeJWT(t, map[string]any{
		"sub": "agent:org-abc:00000000-0000-0000-0000-000000000001",
		"iss": "http://localhost:5556/dex",
	})
	require.True(t, isAgentToken(tok))
}

func TestIsAgentToken_ProtobufEncodedSub(t *testing.T) {
	// A token issued by the normal Dex user flow has an opaque proto-encoded sub.
	tok := makeJWT(t, map[string]any{
		"sub": protobufLikeSub(),
		"iss": "http://localhost:5556/dex",
	})
	require.False(t, isAgentToken(tok), "protobuf-encoded sub must not look like an agent token")
}

func TestIsAgentToken_NotAJWT(t *testing.T) {
	require.False(t, isAgentToken("not.a.jwt.at.all.extra"))
	require.False(t, isAgentToken("onlytwoparts.here"))
	require.False(t, isAgentToken(""))
}

func TestIsAgentToken_MalformedPayload(t *testing.T) {
	// Valid JWT structure but payload is not valid base64.
	require.False(t, isAgentToken("header.!!!notbase64!!!.sig"))
}

func TestIsAgentToken_AgentPrefixInOtherClaim(t *testing.T) {
	// Recognition ends the chain, so an "agent:" outside sub — a display name the
	// upstream IdP lets the user set — must not claim the token.
	tok := makeJWT(t, map[string]any{
		"sub":  "user:org:uuid",
		"name": "agent:impersonator",
	})
	require.False(t, isAgentToken(tok))
}

// ── AgentTokenProvider ───────────────────────────────────────────────────────

func TestAgentTokenProvider_SkipsWhatItDoesNotOwn(t *testing.T) {
	// No verifier: reaching verification would panic, which is the assertion that
	// a skip never gets that far.
	p := &AgentTokenProvider{}
	for name, bearer := range map[string]string{
		"no bearer":     "",
		"session token": "opaque-session-token",
		"pat":           "anet_user_abc123",
		"user jwt":      makeJWT(t, map[string]any{"sub": protobufLikeSub()}),
		"agent in name": makeJWT(t, map[string]any{"sub": "user:o:u", "name": "agent:x"}),
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if bearer != "" {
				r.Header.Set("Authorization", "Bearer "+bearer)
			}
			_, err := p.Authenticate(context.Background(), r)
			require.True(t, errors.Is(err, ErrNoCredential), "err = %v", err)
		})
	}
}

// ── agentClaims ──────────────────────────────────────────────────────────────

func TestAgentClaims_SubjectParsing(t *testing.T) {
	cases := []struct {
		name    string
		subject string
		wantOrg string
		wantID  string
		wantErr bool
	}{
		{
			name:    "valid three-part subject",
			subject: "agent:org-abc:00000000-0000-0000-0000-000000000001",
			wantOrg: "org-abc",
			wantID:  "00000000-0000-0000-0000-000000000001",
		},
		{
			name:    "two parts only",
			subject: "agent:only-one-colon",
			wantErr: true,
		},
		{
			name:    "wrong prefix",
			subject: "user:org:uuid",
			wantErr: true,
		},
		{
			name:    "empty subject",
			subject: "",
			wantErr: true,
		},
		{
			name:    "agent prefix with empty org and id",
			subject: "agent::",
			wantOrg: "",
			wantID:  "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parts := strings.SplitN(tc.subject, ":", 3)
			if tc.wantErr {
				ok := len(parts) == 3 && parts[0] == "agent"
				require.False(t, ok, "expected parsing to fail for subject %q", tc.subject)
				return
			}
			require.Len(t, parts, 3)
			require.Equal(t, "agent", parts[0])
			require.Equal(t, tc.wantOrg, parts[1])
			require.Equal(t, tc.wantID, parts[2])
		})
	}
}

func TestAgentClaims_Interface(t *testing.T) {
	c := &agentClaims{
		subject: "agent:org-x:uuid-y",
		orgID:   "org-x",
		agentID: "uuid-y",
	}
	require.Equal(t, "agent:org-x:uuid-y", c.Subject())
	require.Equal(t, "org-x", c.OrgID())
	require.Empty(t, c.Groups())
}
