// Package dex is axa.Broker on an embedded Dex (the fork in pkg/dex).
package dex

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"time"

	"github.com/ArmornetIO/axa"
	"github.com/ArmornetIO/axa/internal/dex/pkg/httpclient"
	dexserver "github.com/ArmornetIO/axa/internal/dex/server"
	"github.com/ArmornetIO/axa/internal/dex/server/signer"
	dexstorage "github.com/ArmornetIO/axa/internal/dex/storage"
	healthpkg "github.com/ArmornetIO/ota/health"
	"github.com/coreos/go-oidc/v3/oidc"
)

type Config struct {
	// IssuerURL is required, with no trailing slash ("https://api.armornet.io/dex").
	IssuerURL string

	// RotateKeysAfter defaults to 6h; Dex keeps old keys in the JWKS for the
	// token lifetime.
	RotateKeysAfter time.Duration

	// IDTokensValidFor is the lifetime of issued ID tokens. Defaults to 24h.
	// Must be > RotateKeysAfter to ensure tokens stay valid across one rotation.
	IDTokensValidFor time.Duration

	// Seeders run once storage is healthy and must be idempotent.
	Seeders []axa.StartupSeeder

	// HostAuthUI redirects Dex's login, approval and error pages to the host's
	// /dex-* SPA routes; false if it serves none.
	HostAuthUI bool

	// DatabaseURL is the Postgres DSN for Dex's Ent storage. Required; the host
	// supplies it (the module does not read the environment).
	DatabaseURL string

	// Connectors are static: secrets resolve at Start and are never persisted.
	Connectors []axa.Connector

	// ConfigSealer seals stored connector configs; nil stores cleartext JSON.
	ConfigSealer axa.ConfigSealer

	// DialControl vets each address an upstream connector dials (discovery,
	// token, userinfo). A tenant-supplied issuer is attacker-chosen, so a host
	// that lets tenants add connectors should refuse internal addresses here.
	// Nil dials anything. It is process-wide: Dex builds its clients itself.
	DialControl func(network, address string, c syscall.RawConn) error

	// DeviceApprover names the person signed in to the host on r, "" for
	// nobody. Set, a device code is granted only to the person who approved it
	// in the host (deviceapproval.go), so a device login carries the host's
	// sign-in, MFA included. Nil keeps upstream Dex's device flow, where an
	// upstream sign-in alone grants a code. Approvals are sealed with
	// ConfigSealer; without one every device sign-in is refused.
	DeviceApprover func(r *http.Request) string
}

func (c *Config) setDefaults() {
	if c.RotateKeysAfter == 0 {
		c.RotateKeysAfter = 6 * time.Hour
	}
	if c.IDTokensValidFor == 0 {
		c.IDTokensValidFor = 24 * time.Hour
	}
}

func (c *Config) validate() error {
	if c.IssuerURL == "" {
		return fmt.Errorf("dex: IssuerURL is required (set ARMORNET_ISSUER_URL)")
	}
	if c.IDTokensValidFor > 0 && c.RotateKeysAfter > 0 && c.IDTokensValidFor < c.RotateKeysAfter {
		return fmt.Errorf("dex: IDTokensValidFor (%v) must be >= RotateKeysAfter (%v) to avoid premature token expiry",
			c.IDTokensValidFor, c.RotateKeysAfter)
	}
	return nil
}

// Server serves no HTTP itself; the host mounts Broker().Handler().
type Server struct {
	cfg Config
	b   *broker
}

func New(cfg Config) (*Server, error) {
	cfg.setDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	httpclient.DialControl = cfg.DialControl
	b := newBrokerShell()
	if cfg.DeviceApprover != nil {
		b.wrap = deviceGate{
			approver: cfg.DeviceApprover,
			sealer:   cfg.ConfigSealer,
			secure:   strings.HasPrefix(cfg.IssuerURL, "https://"),
			spa:      cfg.HostAuthUI,
			now:      time.Now,
		}.wrap
	}
	return &Server{cfg: cfg, b: b}, nil
}

// Broker is non-nil from New, so it can be wired before Start.
func (s *Server) Broker() axa.Broker { return s.b }

// Start opens Postgres storage, builds Dex, runs the seeders, then blocks.
func (s *Server) Start(ctx context.Context) error {
	stor, err := newStorage(s.cfg.DatabaseURL, s.cfg.ConfigSealer, s.cfg.DeviceApprover != nil)
	if err != nil {
		return fmt.Errorf("dex: storage init: %w", err)
	}

	secrets := newSecretResolver()

	localSigner, err := (&signer.LocalConfig{
		KeysRotationPeriod: s.cfg.RotateKeysAfter.String(),
	}).Open(ctx, stor, s.cfg.IDTokensValidFor, nil, slog.Default())
	if err != nil {
		return fmt.Errorf("dex: signer init: %w", err)
	}

	staticConns := buildStaticConnectors(ctx, secrets, s.cfg.Connectors)

	srv, err := dexserver.NewServer(ctx, dexserver.Config{
		Issuer:                  s.cfg.IssuerURL,
		Storage:                 stor,
		Connectors:              staticConns,
		Web:                     dexserver.WebConfig{HostAuthUI: s.cfg.HostAuthUI},
		Logger:                  slog.Default(),
		IDTokensValidFor:        s.cfg.IDTokensValidFor,
		Signer:                  localSigner,
		EnableClientCredentials: true, // ARMORNET FORK: required for agent M2M auth
		AllowNoConnectors:       true, // ARMORNET FORK: connectors are seeded dynamically after startup
		SkipApprovalScreen:      true, // upstream IdP (GitHub/Auth0/etc.) handles user consent; Dex consent is redundant
		// One bad tenant connector must not stop init: fixing it needs login,
		// which needs this server. Dex still refuses when EVERY connector fails.
		ContinueOnConnectorFailure: true,
	})
	if err != nil {
		return fmt.Errorf("dex: server init: %w", err)
	}

	s.b.initialise(srv, stor, secrets)

	for _, seeder := range s.cfg.Seeders {
		slog.InfoContext(ctx, "dex: running startup seeder", "seeder", seeder.Name())
		if err := seed(ctx, seeder, s.b); err != nil {
			return fmt.Errorf("dex: seeder %q: %w", seeder.Name(), err)
		}
	}

	// After seeding is the first moment "can anyone sign in?" has an answer;
	// none is fine on a fresh install, all-failed is not.
	if failed := len(srv.FailedConnectorIDs()); failed > 0 && len(srv.OpenConnectorIDs()) == 0 {
		slog.ErrorContext(ctx, "dex: every connector that was opened failed — nobody can sign in; see the per-connector errors above",
			"failed", failed)
	}

	slog.Info("dex: ready", "issuer", s.cfg.IssuerURL)
	<-ctx.Done()
	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	if s.b != nil && s.b.stor != nil {
		if err := s.b.stor.Close(); err != nil {
			return fmt.Errorf("dex: storage close: %w", err)
		}
	}
	return nil
}

// Health checks readiness, connectors, then the recent auth error rate.
func (s *Server) Health() healthpkg.ComponentHealth {
	if !s.b.ready() {
		return healthpkg.ComponentHealth{Status: healthpkg.StatusStarting, Reason: "broker initialising"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	conns, err := s.b.Connectors().List(ctx)
	if err != nil {
		return healthpkg.ComponentHealth{Status: healthpkg.StatusRecoverableError, Reason: "connector list: " + err.Error()}
	}
	n := len(conns)
	if n == 0 {
		return healthpkg.ComponentHealth{
			Status:  healthpkg.StatusPermanentError,
			Reason:  "no connectors configured",
			Details: map[string]any{"connectors": n},
		}
	}

	// Rows aren't logins: all attempted opens failing means nobody (god admins
	// too) can sign in. Key on FAILED, not "none opened": new ones are unopened.
	s.b.mu.RLock()
	srv := s.b.dexSrv
	s.b.mu.RUnlock()
	if srv != nil {
		opened, failed := len(srv.OpenConnectorIDs()), len(srv.FailedConnectorIDs())
		if opened == 0 && failed > 0 {
			return healthpkg.ComponentHealth{
				Status:  healthpkg.StatusPermanentError,
				Reason:  "every connector that was opened failed — nobody can sign in",
				Details: map[string]any{"connectors": n, "opened": opened, "failed": failed},
			}
		}
	}

	// Auth metrics layer — derived from the sliding window of recent IDP callbacks.
	s.b.mu.RLock()
	dexSrv := s.b.dexSrv
	s.b.mu.RUnlock()
	if dexSrv != nil {
		if ah := dexSrv.AuthHealth(); ah.Status != healthpkg.StatusOK {
			ah.Details = map[string]any{"connectors": n}
			return ah
		}
	}

	return healthpkg.ComponentHealth{
		Status:  healthpkg.StatusOK,
		Details: map[string]any{"connectors": n},
	}
}

// inProcessTransport keeps NewVerifier's key fetches inside the process.
type inProcessTransport struct{ handler http.Handler }

func (t *inProcessTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	t.handler.ServeHTTP(w, req)
	return w.Result(), nil
}

// NewVerifier skips discovery and fetches JWKS lazily in process: no network,
// no startup ordering.
func (s *Server) NewVerifier(ctx context.Context, issuerURL string) *oidc.IDTokenVerifier {
	client := &http.Client{Transport: &inProcessTransport{handler: s.b.Handler()}}
	ctx = oidc.ClientContext(ctx, client)
	// NewRemoteKeySet is lazy — keys are fetched in-process on first JWT verification,
	// by which point Dex's Start() has completed and the handler is ready.
	keySet := oidc.NewRemoteKeySet(ctx, issuerURL+"/keys")
	return oidc.NewVerifier(issuerURL, keySet, &oidc.Config{SkipClientIDCheck: true})
}

// seed reruns a whole seeder on a serialization failure: two servers seeding
// one database collide, and seeders converge, so a rerun is safe. The storage
// already retries each update; this covers a seeder that does several.
func seed(ctx context.Context, seeder axa.StartupSeeder, b axa.Broker) error {
	return retrySerialization(ctx, func() error { return seeder.Seed(ctx, b) })
}

// buildStaticConnectors logs and skips a connector whose secret won't resolve.
func buildStaticConnectors(ctx context.Context, secrets SecretResolver, conns []axa.Connector) []dexstorage.Connector {
	var out []dexstorage.Connector
	for _, c := range conns {
		dc, err := BuildDexConnector(ctx, c, secrets)
		if err != nil {
			slog.WarnContext(ctx, "dex: skipping static connector — secret resolution failed", "connector", c.ID, "err", err)
			continue
		}
		out = append(out, dc)
	}
	return out
}
