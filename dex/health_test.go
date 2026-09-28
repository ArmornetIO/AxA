package dex

// "Can anyone sign in?" is no longer a row count; Dex's in-memory storage gives
// a real *dexserver.Server without a database.

import (
	"crypto/rand"
	"crypto/rsa"
	"log/slog"
	"testing"

	dexserver "github.com/ArmornetIO/identity/internal/dex/server"
	"github.com/ArmornetIO/identity/internal/dex/server/signer"
	dexstorage "github.com/ArmornetIO/identity/internal/dex/storage"
	"github.com/ArmornetIO/identity/internal/dex/storage/memory"
	healthpkg "github.com/ArmornetIO/ota/health"
)

// initialisedServer returns a Server whose broker is wired to a live Dex server
// over memory storage seeded with conns.
func initialisedServer(t *testing.T, conns []dexstorage.Connector) *Server {
	t.Helper()
	ctx := t.Context()

	srv, err := New(Config{IssuerURL: "https://api.example.com/dex"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	stor := memory.New(slog.New(slog.NewTextHandler(t.Output(), nil)))
	for _, c := range conns {
		if err := stor.CreateConnector(ctx, c); err != nil {
			t.Fatalf("create connector %s: %v", c.ID, err)
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sig, err := signer.NewMockSigner(key)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	dexSrv, err := dexserver.NewServer(ctx, dexserver.Config{
		Issuer:                     srv.cfg.IssuerURL,
		Storage:                    stor,
		Logger:                     slog.New(slog.NewTextHandler(t.Output(), nil)),
		Signer:                     sig,
		AllowNoConnectors:          true,
		ContinueOnConnectorFailure: true,
	})
	if err != nil {
		t.Fatalf("dex server init: %v", err)
	}

	srv.b.initialise(dexSrv, stor, newSecretResolver())
	return srv
}

func TestHealth_BeforeStartIsStarting(t *testing.T) {
	srv, err := New(Config{IssuerURL: "https://api.example.com/dex"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := srv.Health().Status; got != healthpkg.StatusStarting {
		t.Errorf("Status = %v, want %v", got, healthpkg.StatusStarting)
	}
}

func TestHealth_NoConnectorsIsPermanentError(t *testing.T) {
	h := initialisedServer(t, nil).Health()
	if h.Status != healthpkg.StatusPermanentError {
		t.Errorf("Status = %v, want %v", h.Status, healthpkg.StatusPermanentError)
	}
	if h.Reason != "no connectors configured" {
		t.Errorf("Reason = %q", h.Reason)
	}
}

// A new connector is stored, not opened; reading that as broken would gate
// readiness on a sign-in that could then never happen.
func TestHealth_NewlyCreatedConnectorIsNotBroken(t *testing.T) {
	srv := initialisedServer(t, nil)
	if err := srv.b.stor.CreateConnector(t.Context(), dexstorage.Connector{
		ID: "mock", Type: "mockCallback", Name: "Mock", ResourceVersion: "1",
	}); err != nil {
		t.Fatalf("create connector: %v", err)
	}

	h := srv.Health()
	if h.Status == healthpkg.StatusPermanentError {
		t.Fatalf("Status = %v (reason %q) — a connector nothing has tried to open yet is not broken",
			h.Status, h.Reason)
	}
}

// Every attempted open failed: no login path. Reached via OpenConnector, the
// lazy login-path open, since init refuses when all fail.
func TestHealth_EveryAttemptedConnectorFailedIsPermanentError(t *testing.T) {
	srv := initialisedServer(t, nil)
	broken := dexstorage.Connector{
		ID: "broken", Type: "noSuchConnectorType", Name: "Broken", ResourceVersion: "1",
	}
	if err := srv.b.stor.CreateConnector(t.Context(), broken); err != nil {
		t.Fatalf("create connector: %v", err)
	}
	if _, err := srv.b.dexSrv.OpenConnector(broken); err == nil {
		t.Fatal("expected the broken connector to refuse to open")
	}

	h := srv.Health()
	if h.Status != healthpkg.StatusPermanentError {
		t.Fatalf("Status = %v, want %v (reason %q)", h.Status, healthpkg.StatusPermanentError, h.Reason)
	}
	if h.Details["opened"] != 0 || h.Details["failed"] != 1 {
		t.Errorf("Details = %v, want opened=0 failed=1", h.Details)
	}
}

// A connector that opens after an earlier failure clears it — otherwise fixing
// a misconfiguration would need a restart to be believed.
func TestHealth_RecoveredConnectorClearsTheFailure(t *testing.T) {
	srv := initialisedServer(t, nil)
	conn := dexstorage.Connector{
		ID: "flaky", Type: "noSuchConnectorType", Name: "Flaky", ResourceVersion: "1",
	}
	if err := srv.b.stor.CreateConnector(t.Context(), conn); err != nil {
		t.Fatalf("create connector: %v", err)
	}
	if _, err := srv.b.dexSrv.OpenConnector(conn); err == nil {
		t.Fatal("expected the broken connector to refuse to open")
	}
	if got := srv.Health().Status; got != healthpkg.StatusPermanentError {
		t.Fatalf("Status = %v, want the failure to register first", got)
	}

	// The operator fixes the type and it opens.
	conn.Type = "mockCallback"
	if _, err := srv.b.dexSrv.OpenConnector(conn); err != nil {
		t.Fatalf("OpenConnector after fix: %v", err)
	}
	if got := srv.Health().Status; got == healthpkg.StatusPermanentError {
		t.Fatalf("Status = %v — a connector that now opens must clear its earlier failure", got)
	}
}

func TestHealth_OneOpenedConnectorIsOK(t *testing.T) {
	h := initialisedServer(t, []dexstorage.Connector{
		{ID: "mock", Type: "mockCallback", Name: "Mock", ResourceVersion: "1"},
		{ID: "broken", Type: "noSuchConnectorType", Name: "Broken", ResourceVersion: "1"},
	}).Health()

	if h.Status != healthpkg.StatusOK {
		t.Errorf("Status = %v, want %v (reason %q)", h.Status, healthpkg.StatusOK, h.Reason)
	}
}
