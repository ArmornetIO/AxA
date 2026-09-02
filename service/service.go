// Package service is Dex + OpenFGA + health as one Start/Stop Server, so a host
// (own pod, goroutine, or inside armornet) wires one object instead of four.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	otellog "go.opentelemetry.io/otel/log"
	lognoop "go.opentelemetry.io/otel/log/noop"

	"github.com/ArmornetIO/identity"
	"github.com/ArmornetIO/identity/authz"
	"github.com/ArmornetIO/identity/dex"
	"github.com/ArmornetIO/identity/fga"
	health "github.com/ArmornetIO/ota/health"
)

const defaultHealthAddr = ":8090"

type Config struct {
	Dex dex.Config
	// FGA builds an embedded engine; ignored when FGAClient is set.
	FGA fga.Config
	// FGAClient points at an external OpenFGA (authz.NewSDKClient) instead.
	FGAClient authz.FGAClientIface
	// Mapper expands IdP group claims into FGA tuples; nil expands nothing.
	Mapper *authz.ClaimMapper
	// Logger gets the authz.decision audit records; nil is a no-op.
	Logger otellog.Logger
	Health HealthConfig
}

type HealthConfig struct {
	// Disabled: the host serves /healthz itself and registers HealthCheckers().
	Disabled bool
	// Addr defaults to ":8090".
	Addr string
	// PollInterval defaults to 10s.
	PollInterval time.Duration
}

// Server has a plain Start/Stop, so a host's lifecycle can run it as is.
type Server struct {
	cfg       Config
	dex       *dex.Server
	fga       *fga.Server // nil when an external FGAClient is injected
	fgaClient authz.FGAClientIface
	checker   *authz.Checker
	health    *health.Server
	httpSrv   *http.Server // nil when Health.Disabled
}

// New builds FGA eagerly, so Checker() works before Start; Dex initialises in Start.
func New(ctx context.Context, cfg Config) (*Server, error) {
	d, err := dex.New(cfg.Dex)
	if err != nil {
		return nil, fmt.Errorf("identity: dex: %w", err)
	}

	// External client, else an embedded engine if FGA has a DSN, else issuer-only
	// (Checker() nil).
	var f *fga.Server
	fgaClient := cfg.FGAClient
	if fgaClient == nil && cfg.FGA.DatastoreURI != "" {
		f, err = fga.New(ctx, cfg.FGA)
		if err != nil {
			return nil, fmt.Errorf("identity: fga: %w", err)
		}
		fgaClient = f.Client()
	}

	var checker *authz.Checker
	if fgaClient != nil {
		mapper := cfg.Mapper
		if mapper == nil {
			mapper = &authz.ClaimMapper{} // empty passthrough: no group→tuple expansion
		}
		logger := cfg.Logger
		if logger == nil {
			logger = lognoop.NewLoggerProvider().Logger("identity/service")
		}
		checker = authz.NewChecker(fgaClient, mapper, logger)
	}

	s := &Server{
		cfg:       cfg,
		dex:       d,
		fga:       f,
		fgaClient: fgaClient,
		checker:   checker,
		health:    health.NewServer(health.Config{PollInterval: cfg.Health.PollInterval}),
	}

	for name, fn := range s.HealthCheckers() {
		s.health.Register(name, fn)
	}

	if !cfg.Health.Disabled {
		addr := cfg.Health.Addr
		if addr == "" {
			addr = defaultHealthAddr
		}
		s.httpSrv = &http.Server{
			Addr:              addr,
			Handler:           s.healthMux(),
			ReadHeaderTimeout: 10 * time.Second,
		}
	}

	return s, nil
}

// Start blocks until ctx ends, returning early on the first sub-server error so
// a standalone pod exits non-zero on a bad DSN.
func (s *Server) Start(ctx context.Context) error {
	if !s.cfg.Health.Disabled {
		go s.health.Start(ctx)
	} else {
		// Still warm the cache once so HealthCheckers() consumers see real data
		// on their host's first poll rather than the initial "Starting" value.
		s.health.Poll(ctx)
	}

	// Buffered to the number of senders so a goroutine never blocks on send after
	// Start has already returned.
	errCh := make(chan error, 3)
	go func() { errCh <- wrapErr("dex", s.dex.Start(ctx)) }()
	if s.fga != nil {
		go func() { errCh <- wrapErr("fga", s.fga.Start(ctx)) }()
	}
	if s.httpSrv != nil {
		go func() {
			slog.InfoContext(ctx, "identity: health endpoint listening", "addr", s.httpSrv.Addr)
			err := s.httpSrv.ListenAndServe()
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			errCh <- wrapErr("health", err)
		}()
	}

	slog.InfoContext(ctx, "identity: service started")
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errCh:
			if err != nil {
				return err
			}
			// A sub-server ended cleanly; keep the rest of the plane running.
		}
	}
}

func (s *Server) Stop(ctx context.Context) error {
	var errs []error
	if s.httpSrv != nil {
		if err := s.httpSrv.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs = append(errs, wrapErr("health", err))
		}
	}
	if err := s.dex.Stop(ctx); err != nil {
		errs = append(errs, wrapErr("dex", err))
	}
	if s.fga != nil {
		if err := s.fga.Stop(ctx); err != nil {
			errs = append(errs, wrapErr("fga", err))
		}
	}
	return errors.Join(errs...)
}

// Broker is usable right after New; it answers 503 until Start initialises Dex.
func (s *Server) Broker() identity.Broker { return s.dex.Broker() }

func (s *Server) Checker() *authz.Checker { return s.checker }

// FGAClient is the embedded engine or the injected one, for writing tuples.
func (s *Server) FGAClient() authz.FGAClientIface { return s.fgaClient }

// StoreID and ModelID are "" with an external client: the host owns that store.
func (s *Server) StoreID() string {
	if s.fga == nil {
		return ""
	}
	return s.fga.StoreID()
}

func (s *Server) ModelID() string {
	if s.fga == nil {
		return ""
	}
	return s.fga.ModelID()
}

// NewVerifier checks embedded-Dex tokens in process: no network, no discovery.
func (s *Server) NewVerifier(ctx context.Context, issuerURL string) *oidc.IDTokenVerifier {
	return s.dex.NewVerifier(ctx, issuerURL)
}

// HealthCheckers is what a Health.Disabled host registers on its own health.Server.
func (s *Server) HealthCheckers() map[string]func() health.ComponentHealth {
	checkers := map[string]func() health.ComponentHealth{
		"identity": s.dex.Health,
	}
	// Only when owned: issuer-only mode must not report a phantom authz failure.
	if s.checker != nil {
		checkers["authz"] = s.authzHealth
	}
	return checkers
}

// A nil checker after New is misconfiguration, not warm-up, so it is fatal.
func (s *Server) authzHealth() health.ComponentHealth {
	if s.checker == nil {
		return health.ComponentHealth{Status: health.StatusFatalError, Reason: "authz checker not wired"}
	}
	return health.ComponentHealth{Status: health.StatusOK}
}

// wrapErr keeps nil nil, so results go straight to the channel.
func wrapErr(component string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("identity: %s: %w", component, err)
}
