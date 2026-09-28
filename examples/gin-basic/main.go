// gin-basic puts a Gin API behind identity's browser sign-in: Dex, identity/web
// and the API in one process, with Dex's mock connector as the IdP.
package main

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"

	"github.com/ArmornetIO/identity"
	"github.com/ArmornetIO/identity/authn"
	"github.com/ArmornetIO/identity/dex"
	"github.com/ArmornetIO/identity/pgstore"
	"github.com/ArmornetIO/identity/service"
	"github.com/ArmornetIO/identity/web"
)

const (
	clientID    = "gin-basic"
	connectorID = "mock"
	orgSlug     = "demo"
)

//go:embed index.html
var indexHTML []byte

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, stop); err != nil {
		slog.Error("gin-basic", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, stop context.CancelFunc) error {
	dsn := env("DATABASE_URL", "postgres://postgres:identity@localhost:5433/identity?sslmode=disable")
	// Port 8081, so it runs beside an armornet dev server on 8080.
	base := env("BASE_URL", "http://localhost:8081")
	issuer := base + "/dex"

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	// Identity never migrates on its own; the host applies the reference DDL.
	// Every statement is idempotent, so running it on each start is fine here.
	for _, ddl := range []string{pgstore.Schema(), dex.Schema()} {
		if _, err := db.ExecContext(ctx, ddl); err != nil {
			return err
		}
	}

	orgs := pgstore.NewOrgStore(db)
	if err := ensureOrg(ctx, orgs); err != nil {
		return err
	}

	// Issuer only: no FGA datastore, so no authorization engine. Health is off
	// because this process serves its own endpoints.
	svc, err := service.New(ctx, service.Config{
		Dex: dex.Config{
			IssuerURL:   issuer,
			DatabaseURL: dsn,
			Seeders:     []identity.StartupSeeder{seed{redirect: base + "/callback"}},
		},
		Health: service.HealthConfig{Disabled: true},
	})
	if err != nil {
		return err
	}
	go func() {
		if err := svc.Start(ctx); err != nil {
			slog.Error("identity service stopped", "err", err)
			stop()
		}
	}()

	// A public client: the flow proves itself with PKCE, so there is no
	// secret to keep.
	dexClient, _ := web.NewOIDCDexClient(ctx, issuer, clientID, "", base+"/callback")
	auth := &web.Handlers{
		PreAuth:     pgstore.NewPreAuthStore(db),
		Sessions:    pgstore.NewSessionStore(db),
		Dex:         dexClient,
		Orgs:        orgs,
		Users:       pgstore.NewUserStore(db),
		IssuerURL:   issuer,
		ClientID:    clientID,
		RedirectURI: base + "/callback",
		// Single-tenant: a first sign-in becomes a member of the one org.
		SelfRegister: true,
	}

	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())
	mountAuth(r, auth)
	r.Any("/dex/*path", gin.WrapH(svc.Broker().Handler()))

	page := func(c *gin.Context) { c.Data(http.StatusOK, "text/html; charset=utf-8", indexHTML) }
	r.GET("/", page)
	r.GET("/callback", page)
	// identity/ts's resolveSlug lookup. Public: it runs before anyone signs in.
	r.GET("/api/orgs/:slug/connectors", func(c *gin.Context) {
		id, conns, err := orgs.ResolveSlug(c.Request.Context(), c.Param("slug"))
		if errors.Is(err, authn.ErrNoOrg) {
			c.JSON(http.StatusNotFound, gin.H{"error": "no such workspace"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "lookup failed"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"org_id": id, "connectors": conns})
	})

	api := r.Group("/api", requireSession(auth))
	api.GET("/hello", func(c *gin.Context) {
		sess := c.MustGet("session").(authn.SessionRecord)
		c.JSON(http.StatusOK, gin.H{"hello": sess.Subject, "org_id": sess.OrgID})
	})

	// ADDR differs from BASE_URL's port only behind a proxy — the custom-login
	// example's dev server, which must own the origin the browser sees.
	u, err := url.Parse(base)
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: env("ADDR", ":"+u.Port()), Handler: r, ReadHeaderTimeout: 10 * time.Second}
	// #nosec G118 -- shutdown watcher; Background is the only correct parent once ctx is done
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
		_ = svc.Stop(shutdown)
	}()
	slog.Info("listening", "url", base)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// mountAuth translates identity/web's {name} patterns to gin's :name and fills
// r.PathValue, which gin does not.
func mountAuth(r gin.IRoutes, auth *web.Handlers) {
	for _, rt := range auth.Routes() {
		h := rt.Handler
		path := rt.Path
		if i := strings.IndexByte(path, '{'); i >= 0 {
			path = path[:i] + ":" + strings.Trim(path[i:], "{}")
		}
		r.Handle(rt.Method, path, func(c *gin.Context) {
			for _, p := range c.Params {
				c.Request.SetPathValue(p.Key, p.Value)
			}
			h.ServeHTTP(c.Writer, c.Request)
		})
	}
}

// requireSession is the whole of "behind our auth" for this API: a live
// session cookie, or 401.
func requireSession(auth *web.Handlers) gin.HandlerFunc {
	return func(c *gin.Context) {
		sess, ok := auth.SessionFrom(c.Request)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "sign in first"})
			return
		}
		c.Set("session", sess)
		c.Next()
	}
}

func ensureOrg(ctx context.Context, orgs *pgstore.OrgStore) error {
	if _, _, err := orgs.ResolveSlug(ctx, orgSlug); err == nil {
		return nil
	}
	return orgs.CreateOrg(ctx, authn.Organization{ID: "demo-org", Name: "Demo", Slug: orgSlug})
}

// seed registers the mock connector and the public OAuth client once Dex's
// storage is up. Both are idempotent.
type seed struct{ redirect string }

func (seed) Name() string { return "gin-basic" }

func (s seed) Seed(ctx context.Context, b identity.Broker) error {
	err := b.Connectors().Create(ctx, identity.Connector{
		ID:     connectorID,
		Name:   "Mock (signs you in as a test user)",
		Config: identity.OpaqueConnectorConfig{Type: "mockCallback", RawConfig: json.RawMessage(`{}`)},
	})
	if err != nil && !errors.Is(err, identity.ErrConnectorExists) {
		return err
	}
	client := identity.Client{ID: clientID, Name: "gin-basic", RedirectURIs: []string{s.redirect}, Public: true}
	if _, err = b.Clients().Create(ctx, client); errors.Is(err, identity.ErrClientExists) {
		// BASE_URL may have changed since the client was made.
		err = b.Clients().Update(ctx, client)
	}
	return err
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
