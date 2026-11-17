package storage_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ArmornetIO/axa/internal/dex/storage"
)

// Trap 6: BackchannelLogoutURI must be a first-class field on storage.Client so
// that terminateUserSession can fetch the correct endpoint for each registered client.
func TestClient_BackchannelLogoutURIField(t *testing.T) {
	c := storage.Client{
		ID:                               "armornet-bff",
		Secret:                           "secret",
		RedirectURIs:                     []string{"http://app.local/callback"},
		BackchannelLogoutURI:             "http://app.local/api/auth/backchannel-logout",
		BackchannelLogoutSessionRequired: false,
	}
	assert.Equal(t, "http://app.local/api/auth/backchannel-logout", c.BackchannelLogoutURI)
	assert.False(t, c.BackchannelLogoutSessionRequired)
}

func TestClient_BackchannelLogoutSessionRequired(t *testing.T) {
	c := storage.Client{
		ID:                               "rp",
		BackchannelLogoutURI:             "https://rp.example.com/bc-logout",
		BackchannelLogoutSessionRequired: true,
	}
	assert.True(t, c.BackchannelLogoutSessionRequired)
}

// Client without BackchannelLogoutURI (zero value) — must still be valid.
func TestClient_NoBackchannelLogoutURI_IsValid(t *testing.T) {
	c := storage.Client{ID: "legacy-client"}
	assert.Empty(t, c.BackchannelLogoutURI)
	assert.False(t, c.BackchannelLogoutSessionRequired)
}
