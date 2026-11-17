package server

// ARMORNET FORK. Covers the two fork fields that decide whether the server comes
// up at all — ContinueOnConnectorFailure and AllowNoConnectors — plus the `> 0`
// guard on the all-connectors-failed check, which upstream does not have.

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ArmornetIO/axa/internal/dex/server/signer"
	"github.com/ArmornetIO/axa/internal/dex/storage"
	"github.com/ArmornetIO/axa/internal/dex/storage/memory"
)

// newServerWithConnectors starts a server over fresh memory storage seeded with
// exactly the given connectors, and returns whatever newServer returned. Unlike
// newTestServer it never seeds a connector of its own and never t.Fatals, so a
// refusal to start is observable.
func newServerWithConnectors(t *testing.T, conns []storage.Connector, updateConfig func(c *Config)) (*Server, error) {
	t.Helper()

	logger := newLogger(t)
	ctx := t.Context()

	sig, err := signer.NewMockSigner(testKey)
	require.NoError(t, err)

	config := Config{
		Issuer:             "http://127.0.0.1:5556",
		Storage:            memory.New(logger),
		Web:                WebConfig{Dir: "../web"},
		Logger:             logger,
		PrometheusRegistry: prometheus.NewRegistry(),
		HealthChecker:      AlwaysHealthy(),
		Signer:             sig,
	}
	if updateConfig != nil {
		updateConfig(&config)
	}

	for _, conn := range conns {
		require.NoError(t, config.Storage.CreateConnector(ctx, conn))
	}

	return newServer(ctx, config)
}

func goodConnector(id string) storage.Connector {
	return storage.Connector{ID: id, Type: "mockCallback", Name: id, ResourceVersion: "1"}
}

// A connector type nothing implements — OpenConnector fails on it.
func brokenConnector(id string) storage.Connector {
	return storage.Connector{ID: id, Type: "noSuchConnectorType", Name: id, ResourceVersion: "1"}
}

func TestContinueOnConnectorFailure_BadConnectorDoesNotTakeServerDown(t *testing.T) {
	s, err := newServerWithConnectors(t,
		[]storage.Connector{goodConnector("good"), brokenConnector("bad")},
		func(c *Config) { c.ContinueOnConnectorFailure = true })
	require.NoError(t, err, "one bad connector must not stop the server")
	assert.Equal(t, []string{"good"}, s.OpenConnectorIDs(),
		"only the connector that opened may be reported as a login path")
}

func TestContinueOnConnectorFailure_Off_BadConnectorIsFatal(t *testing.T) {
	_, err := newServerWithConnectors(t,
		[]storage.Connector{goodConnector("good"), brokenConnector("bad")}, nil)
	require.Error(t, err, "upstream behaviour: a bad connector is fatal when the flag is off")
}

// The `> 0` guard: a fresh install has zero connector rows and seeds them after
// startup, so nothing failed and the server must come up.
func TestContinueOnConnectorFailure_NoConnectorsIsNotTotalFailure(t *testing.T) {
	s, err := newServerWithConnectors(t, nil, func(c *Config) {
		c.ContinueOnConnectorFailure = true
		c.AllowNoConnectors = true
	})
	require.NoError(t, err, "zero connectors is not 0/0 connectors failing")
	assert.Empty(t, s.OpenConnectorIDs())
}

func TestContinueOnConnectorFailure_EveryConnectorFailingIsStillFatal(t *testing.T) {
	_, err := newServerWithConnectors(t,
		[]storage.Connector{brokenConnector("bad1"), brokenConnector("bad2")},
		func(c *Config) { c.ContinueOnConnectorFailure = true })
	require.Error(t, err, "no login path at all must not be reported as a healthy start")
	assert.Contains(t, err.Error(), "failed to open all connectors")
}

// Without AllowNoConnectors an empty storage is still fatal, whatever the
// failure flag says.
func TestAllowNoConnectors_Off_EmptyStorageIsFatal(t *testing.T) {
	_, err := newServerWithConnectors(t, nil, func(c *Config) {
		c.ContinueOnConnectorFailure = true
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no connectors specified")
}
