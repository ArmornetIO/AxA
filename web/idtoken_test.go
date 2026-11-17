package web_test

import (
	"context"
	"testing"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ArmornetIO/axa/web"
)

// A real Dex-shaped federated:id JWT: every sign-in parses it, so a broken JSON
// tag must fail here, not lock everyone out in production.
func TestValidateIDToken_ReadsFederatedConnector(t *testing.T) {
	const clientID = "armornet-bff"
	ts := newTestBCOIDCServer(t, clientID)
	raw := ts.sign(t, jwtv5.MapClaims{
		"events": nil,
		"jti":    nil,
		"nonce":  "n-1",
		"email":  "carol@org1.com",
		"federated_claims": map[string]any{
			"connector_id": "oidc-org-1",
			"user_id":      "upstream-42",
		},
	})

	c, err := web.NewOIDCDexClient(context.Background(), ts.issuerURL(), clientID, "secret", "http://app.local/callback")
	require.NoError(t, err)
	claims, err := c.ValidateIDToken(context.Background(), raw)
	require.NoError(t, err)

	assert.Equal(t, "oidc-org-1", claims.ConnectorID)
	assert.Equal(t, "upstream-42", claims.UpstreamUserID)
	assert.Equal(t, "n-1", claims.Nonce)
}

// Without federated:id Dex omits the block; the client must report an empty
// connector (which the callback refuses) rather than error or guess.
func TestValidateIDToken_NoFederatedClaims_EmptyConnector(t *testing.T) {
	const clientID = "armornet-bff"
	ts := newTestBCOIDCServer(t, clientID)
	raw := ts.sign(t, jwtv5.MapClaims{"events": nil, "jti": nil, "nonce": "n-2"})

	c, err := web.NewOIDCDexClient(context.Background(), ts.issuerURL(), clientID, "secret", "http://app.local/callback")
	require.NoError(t, err)
	claims, err := c.ValidateIDToken(context.Background(), raw)
	require.NoError(t, err)
	assert.Empty(t, claims.ConnectorID)
}
