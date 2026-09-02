package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	"golang.org/x/crypto/bcrypt"

	"github.com/ArmornetIO/identity/internal/dex/connector"
	"github.com/ArmornetIO/identity/internal/dex/connector/atlassiancrowd"
	"github.com/ArmornetIO/identity/internal/dex/connector/authproxy"
	"github.com/ArmornetIO/identity/internal/dex/connector/bitbucketcloud"
	"github.com/ArmornetIO/identity/internal/dex/connector/gitea"
	"github.com/ArmornetIO/identity/internal/dex/connector/github"
	"github.com/ArmornetIO/identity/internal/dex/connector/gitlab"
	"github.com/ArmornetIO/identity/internal/dex/connector/google"
	"github.com/ArmornetIO/identity/internal/dex/connector/keystone"
	"github.com/ArmornetIO/identity/internal/dex/connector/ldap"
	"github.com/ArmornetIO/identity/internal/dex/connector/linkedin"
	"github.com/ArmornetIO/identity/internal/dex/connector/microsoft"
	"github.com/ArmornetIO/identity/internal/dex/connector/mock"
	"github.com/ArmornetIO/identity/internal/dex/connector/oauth"
	"github.com/ArmornetIO/identity/internal/dex/connector/oidc"
	"github.com/ArmornetIO/identity/internal/dex/connector/saml"
	"github.com/ArmornetIO/identity/internal/dex/server/signer"
	"github.com/ArmornetIO/identity/internal/dex/storage"
	"github.com/ArmornetIO/identity/internal/dex/web"
)

// LocalConnector is the local passwordDB connector which is an internal
// connector maintained by the server.
const LocalConnector = "local"

// staticResourceVersion is set on connectors loaded from Config.Connectors.
// It signals to getConnector that this connector is not in storage and should
// not trigger a storage refresh.
const staticResourceVersion = "static"

// Connector is a connector with resource version metadata.
type Connector struct {
	ResourceVersion string
	Connector       connector.Connector
}

// Config holds the server's configuration options.
//
// Multiple servers using the same storage are expected to be configured identically.
type Config struct {
	Issuer string

	// The backing persistence layer.
	Storage storage.Storage

	AllowedGrantTypes []string

	// Valid values are "code" to enable the code flow and "token" to enable the implicit
	// flow. If no response types are supplied this value defaults to "code".
	SupportedResponseTypes []string

	// Headers is a map of headers to be added to the all responses.
	Headers http.Header

	// Header to extract real ip from.
	RealIPHeader       string
	TrustedRealIPCIDRs []netip.Prefix

	// List of allowed origins for CORS requests on discovery, token and keys endpoint.
	// If none are indicated, CORS requests are disabled. Passing in "*" will allow any
	// domain.
	AllowedOrigins []string

	// List of allowed headers for CORS requests on discovery, token, and keys endpoint.
	AllowedHeaders []string

	// If enabled, the server won't prompt the user to approve authorization requests.
	// Logging in implies approval.
	SkipApprovalScreen bool

	// If enabled, the connectors selection page will always be shown even if there's only one
	AlwaysShowLoginScreen bool

	IDTokensValidFor       time.Duration // Defaults to 24 hours
	AuthRequestsValidFor   time.Duration // Defaults to 24 hours
	DeviceRequestsValidFor time.Duration // Defaults to 5 minutes

	// Refresh token expiration settings
	RefreshTokenPolicy *RefreshTokenPolicy

	// If set, the server will use this connector to handle password grants
	PasswordConnector string

	// ARMORNET FORK: EnableClientCredentials opts this Dex server into the
	// OAuth2 client_credentials grant (RFC 6749 §4.4) for machine-to-machine
	// authentication. Disabled by default to preserve upstream Dex behaviour.
	// Armornet enables this in internal/identity/dex/server.go.
	EnableClientCredentials bool

	// ARMORNET FORK: AllowNoConnectors skips the startup check that requires at
	// least one connector to be present in storage. Set this when connectors are
	// seeded dynamically after the server starts (e.g. via the provisioning API)
	// and agent M2M auth via client_credentials does not require a connector.
	AllowNoConnectors bool

	GCFrequency time.Duration // Defaults to 5 minutes

	// If specified, the server will use this function for determining time.
	Now func() time.Time

	Web WebConfig

	Logger *slog.Logger

	// Signer is used to sign tokens.
	Signer signer.Signer

	PrometheusRegistry *prometheus.Registry

	// Meter is used to emit OTel metrics for auth events. If nil, a no-op
	// meter is used so the server works without an OTel provider.
	Meter metric.Meter

	HealthChecker HealthChecker

	// If enabled, the server will continue starting even if some connectors fail to initialize.
	// This allows the server to operate with a subset of connectors if some are misconfigured.
	ContinueOnConnectorFailure bool

	// RequirePKCE, when true, rejects authorization requests that omit code_challenge
	// or that use any method other than S256. Advertised in the discovery document.
	RequirePKCE bool

	// Connectors is an optional list of static (in-memory) connectors loaded at
	// startup without touching storage. Secrets must already be resolved into the
	// Config bytes. Use this for global connectors whose secrets should not be
	// persisted to the database.
	// ARMORNET FORK: re-introduced from upstream dexidp/dex.
	Connectors []storage.Connector
}

// WebConfig holds the server's frontend templates and asset configuration.
type WebConfig struct {
	// A file path to static web assets.
	//
	// It is expected to contain the following directories:
	//
	//   * static - Static static served at "( issuer URL )/static".
	//   * templates - HTML templates controlled by dex.
	//   * themes/(theme) - Static static served at "( issuer URL )/theme".
	Dir string

	// Alternative way to programmatically configure static web assets.
	// If Dir is specified, WebFS is ignored.
	// It's expected to contain the same files and directories as mentioned above.
	//
	// Note: this is experimental. Might get removed without notice!
	WebFS fs.FS

	// Defaults to "( issuer URL )/theme/logo.png"
	LogoURL string

	// Defaults to "dex"
	Issuer string

	// Defaults to "light"
	Theme string

	// Map of extra values passed into the templates
	Extra map[string]string

	// HostAuthUI, when true, causes Dex to 302-redirect its login, approval,
	// and error flows to the host's /dex-* routes (relative paths) instead of
	// rendering Go HTML templates.
	HostAuthUI bool
}

func value(val, defaultValue time.Duration) time.Duration {
	if val == 0 {
		return defaultValue
	}
	return val
}

// Server is the top level object.
type Server struct {
	issuerURL url.URL

	// mutex for the connectors map.
	mu sync.Mutex
	// Map of connector IDs to connectors.
	connectors map[string]Connector
	// failedConnectors holds the ids of connectors an open was ATTEMPTED for
	// and refused. Distinct from "not in connectors": a connector created
	// after startup has never been tried, and reading that as broken turns the
	// first connector an operator adds into a permanent health error.
	// ARMORNET FORK.
	failedConnectors map[string]struct{}
	// staticConnectors holds display metadata for connectors loaded from Config.Connectors.
	// They are in s.connectors for auth but not in storage; we need their metadata for
	// the login picker.
	staticConnectors []storage.Connector

	storage storage.Storage

	mux http.Handler

	templates *templates

	// If enabled, don't prompt user for approval after logging in through connector.
	skipApproval bool

	// If enabled, show the connector selection screen even if there's only one
	alwaysShowLogin bool

	requirePKCE bool

	// Used for password grant
	passwordConnector string

	supportedResponseTypes map[string]bool

	supportedGrantTypes []string

	now func() time.Time

	idTokensValidFor       time.Duration
	authRequestsValidFor   time.Duration
	deviceRequestsValidFor time.Duration

	refreshTokenPolicy *RefreshTokenPolicy

	logger *slog.Logger

	signer signer.Signer

	authMetrics *AuthMetrics
}

// NewServer constructs a server from the provided config.
func NewServer(ctx context.Context, c Config) (*Server, error) {
	return newServer(ctx, c)
}

func newServer(ctx context.Context, c Config) (*Server, error) {
	issuerURL, err := url.Parse(c.Issuer)
	if err != nil {
		return nil, fmt.Errorf("server: can't parse issuer URL")
	}

	if c.Storage == nil {
		return nil, errors.New("server: storage cannot be nil")
	}

	if len(c.SupportedResponseTypes) == 0 {
		c.SupportedResponseTypes = []string{responseTypeCode}
	}
	if len(c.AllowedHeaders) == 0 {
		c.AllowedHeaders = []string{"Authorization"}
	}

	allSupportedGrants := map[string]bool{
		grantTypeAuthorizationCode: true,
		grantTypeRefreshToken:      true,
		grantTypeDeviceCode:        true,
		grantTypeTokenExchange:     true,
	}
	supportedRes := make(map[string]bool)

	for _, respType := range c.SupportedResponseTypes {
		switch respType {
		case responseTypeCode, responseTypeIDToken, responseTypeCodeIDToken:
			// continue
		case responseTypeToken, responseTypeCodeToken, responseTypeIDTokenToken, responseTypeCodeIDTokenToken:
			// response_type=token is an implicit flow, let's add it to the discovery info
			// https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.1
			allSupportedGrants[grantTypeImplicit] = true
		default:
			return nil, fmt.Errorf("unsupported response_type %q", respType)
		}
		supportedRes[respType] = true
	}

	if c.PasswordConnector != "" {
		allSupportedGrants[grantTypePassword] = true
	}
	if c.EnableClientCredentials {
		allSupportedGrants[grantTypeClientCredentials] = true
	}

	var supportedGrants []string
	if len(c.AllowedGrantTypes) > 0 {
		for _, grant := range c.AllowedGrantTypes {
			if allSupportedGrants[grant] {
				supportedGrants = append(supportedGrants, grant)
			}
		}
	} else {
		for grant := range allSupportedGrants {
			supportedGrants = append(supportedGrants, grant)
		}
	}
	sort.Strings(supportedGrants)

	webFS := web.FS()
	if c.Web.Dir != "" {
		webFS = os.DirFS(c.Web.Dir)
	} else if c.Web.WebFS != nil {
		webFS = c.Web.WebFS
	}

	web := webConfig{
		webFS:     webFS,
		logoURL:   c.Web.LogoURL,
		issuerURL: c.Issuer,
		issuer:    c.Web.Issuer,
		theme:     c.Web.Theme,
		extra:     c.Web.Extra,
		spaRoutes: c.Web.HostAuthUI,
	}

	static, theme, robots, tmpls, err := loadWebConfig(web)
	if err != nil {
		return nil, fmt.Errorf("server: failed to load web static: %v", err)
	}

	now := c.Now
	if now == nil {
		now = time.Now
	}

	meter := c.Meter
	if meter == nil {
		meter = noop.NewMeterProvider().Meter("dex")
	}
	authMetrics, err := NewAuthMetrics(meter)
	if err != nil {
		return nil, fmt.Errorf("server: failed to create auth metrics: %w", err)
	}

	s := &Server{
		issuerURL:              *issuerURL,
		connectors:             make(map[string]Connector),
		staticConnectors:       c.Connectors,
		failedConnectors:       make(map[string]struct{}),
		storage:                newKeyCacher(c.Storage, now),
		supportedResponseTypes: supportedRes,
		supportedGrantTypes:    supportedGrants,
		idTokensValidFor:       value(c.IDTokensValidFor, 24*time.Hour),
		authRequestsValidFor:   value(c.AuthRequestsValidFor, 24*time.Hour),
		deviceRequestsValidFor: value(c.DeviceRequestsValidFor, 5*time.Minute),
		refreshTokenPolicy:     c.RefreshTokenPolicy,
		skipApproval:           c.SkipApprovalScreen,
		alwaysShowLogin:        c.AlwaysShowLoginScreen,
		requirePKCE:            c.RequirePKCE,
		now:                    now,
		templates:              tmpls,
		passwordConnector:      c.PasswordConnector,
		logger:                 c.Logger,
		signer:                 c.Signer,
		authMetrics:            authMetrics,
	}

	// Retrieves connector objects in backend storage. This list includes the static connectors
	// defined in the ConfigMap and dynamic connectors retrieved from the storage.
	storageConnectors, err := c.Storage.ListConnectors(ctx)
	if err != nil {
		return nil, fmt.Errorf("server: failed to list connector objects from storage: %v", err)
	}

	if len(storageConnectors) == 0 && len(c.Connectors) == 0 && !c.AllowNoConnectors {
		return nil, errors.New("server: no connectors specified")
	}

	var failedCount int
	for _, conn := range storageConnectors {
		if _, err := s.OpenConnector(conn); err != nil {
			failedCount++
			if c.ContinueOnConnectorFailure {
				s.logger.Error("server: Failed to open connector", "id", conn.ID, "err", err)
				continue
			}
			return nil, fmt.Errorf("server: Failed to open connector %s: %v", conn.ID, err)
		}
	}

	// ARMORNET FORK: `> 0` guard. Upstream compares failedCount to the list
	// length, which is also true when the list is EMPTY — so enabling
	// ContinueOnConnectorFailure made a server with no connectors yet refuse to
	// start with "failed to open all connectors (0/0)". That is every fresh
	// install here: AllowNoConnectors is on and connectors are seeded after
	// startup. Nothing failed when there was nothing to open.
	if c.ContinueOnConnectorFailure && len(storageConnectors) > 0 && failedCount == len(storageConnectors) {
		return nil, fmt.Errorf("server: failed to open all connectors (%d/%d)", failedCount, len(storageConnectors))
	}

	// Load static (in-memory) connectors from Config.Connectors. These are never
	// written to storage; we tag them with staticResourceVersion so getConnector
	// can skip the storage refresh cycle for them.
	for _, conn := range c.Connectors {
		conn.ResourceVersion = staticResourceVersion
		if _, err := s.OpenConnector(conn); err != nil {
			if c.ContinueOnConnectorFailure {
				s.logger.Error("server: Failed to open static connector", "id", conn.ID, "err", err)
				continue
			}
			return nil, fmt.Errorf("server: Failed to open static connector %s: %v", conn.ID, err)
		}
	}

	instrumentHandler := func(_ string, handler http.Handler) http.HandlerFunc {
		return handler.ServeHTTP
	}

	if c.PrometheusRegistry != nil {
		requestCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Count of all HTTP requests.",
		}, []string{"code", "method", "handler"})

		durationHist := prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "request_duration_seconds",
			Help:    "A histogram of latencies for requests.",
			Buckets: []float64{.25, .5, 1, 2.5, 5, 10},
		}, []string{"code", "method", "handler"})

		sizeHist := prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "response_size_bytes",
			Help:    "A histogram of response sizes for requests.",
			Buckets: []float64{200, 500, 900, 1500},
		}, []string{"code", "method", "handler"})

		c.PrometheusRegistry.MustRegister(requestCounter, durationHist, sizeHist)

		instrumentHandler = func(handlerName string, handler http.Handler) http.HandlerFunc {
			return promhttp.InstrumentHandlerDuration(durationHist.MustCurryWith(prometheus.Labels{"handler": handlerName}),
				promhttp.InstrumentHandlerCounter(requestCounter.MustCurryWith(prometheus.Labels{"handler": handlerName}),
					promhttp.InstrumentHandlerResponseSize(sizeHist.MustCurryWith(prometheus.Labels{"handler": handlerName}), handler),
				),
			)
		}
	}

	parseRealIP := func(r *http.Request) (string, error) {
		remoteAddr, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return "", err
		}

		remoteIP, err := netip.ParseAddr(remoteAddr)
		if err != nil {
			return "", err
		}

		for _, n := range c.TrustedRealIPCIDRs {
			if !n.Contains(remoteIP) {
				return remoteAddr, nil // Fallback to the address from the request if the header is provided
			}
		}

		ipVal := r.Header.Get(c.RealIPHeader)
		if ipVal != "" {
			ip, err := netip.ParseAddr(ipVal)
			if err == nil {
				return ip.String(), nil
			}
		}

		return remoteAddr, nil
	}

	handlerWithHeaders := func(handlerName string, handler http.Handler) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			for k, v := range c.Headers {
				w.Header()[k] = v
			}

			// Context values are used for logging purposes with the log/slog logger.
			rCtx := r.Context()
			rCtx = WithRequestID(rCtx)

			if c.RealIPHeader != "" {
				realIP, err := parseRealIP(r)
				if err == nil {
					rCtx = WithRemoteIP(rCtx, realIP)
				}
			}

			r = r.WithContext(rCtx)
			instrumentHandler(handlerName, handler)(w, r)
		}
	}

	r := mux.NewRouter().SkipClean(true).UseEncodedPath()
	handle := func(p string, h http.Handler) {
		r.Handle(path.Join(issuerURL.Path, p), handlerWithHeaders(p, h))
	}
	handleFunc := func(p string, h http.HandlerFunc) {
		handle(p, h)
	}
	handlePrefix := func(p string, h http.Handler) {
		prefix := path.Join(issuerURL.Path, p)
		r.PathPrefix(prefix).Handler(http.StripPrefix(prefix, h))
	}
	handleWithCORS := func(p string, h http.HandlerFunc) {
		var handler http.Handler = h
		if len(c.AllowedOrigins) > 0 {
			cors := handlers.CORS(
				handlers.AllowedOrigins(c.AllowedOrigins),
				handlers.AllowedHeaders(c.AllowedHeaders),
			)
			handler = cors(handler)
		}
		r.Handle(path.Join(issuerURL.Path, p), handlerWithHeaders(p, handler))
	}
	r.NotFoundHandler = http.NotFoundHandler()

	discoveryHandler, err := s.discoveryHandler(ctx)
	if err != nil {
		return nil, err
	}
	handleWithCORS("/.well-known/openid-configuration", discoveryHandler)
	// Handle the root path for the better user experience.
	handleWithCORS("/", func(w http.ResponseWriter, r *http.Request) {
		_, err := fmt.Fprintf(w, `<!DOCTYPE html>
			<title>Dex</title>
			<h1>Dex IdP</h1>
			<h3>A Federated OpenID Connect Provider</h3>
			<p><a href=%q>Discovery</a></p>`,
			s.issuerURL.JoinPath(".well-known", "openid-configuration").String())
		if err != nil {
			s.logger.Error("failed to write response", "err", err)
			s.renderError(r, w, http.StatusInternalServerError, "Handling the / path error.")
			return
		}
	})

	// TODO(ericchiang): rate limit certain paths based on IP.
	handleWithCORS("/token", s.handleToken)
	handleWithCORS("/keys", s.handlePublicKeys)
	handleWithCORS("/userinfo", s.handleUserInfo)
	handleWithCORS("/token/introspect", s.handleIntrospect)
	// ARMORNET FORK: RFC 7009 revocation + OIDC RP-Initiated Logout 1.0
	handleWithCORS("/revoke", s.handleRevoke)
	handleFunc("/end_session", s.handleEndSession)
	handleFunc("/auth", s.handleAuthorization)
	handleFunc("/auth/{connector}", s.handleConnectorLogin)
	handleFunc("/auth/{connector}/login", s.handlePasswordLogin)
	handleFunc("/device", s.handleDeviceExchange)
	handleFunc("/device/auth/verify_code", s.verifyUserCode)
	handleFunc("/device/code", s.handleDeviceCode)
	// TODO(nabokihms): "/device/token" endpoint is deprecated, consider using /token endpoint instead
	handleFunc("/device/token", s.handleDeviceTokenDeprecated)
	handleFunc(deviceCallbackURI, s.handleDeviceCallback)
	handleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		// Strip the X-Remote-* headers to prevent security issues on
		// misconfigured authproxy connector setups.
		for key := range r.Header {
			if strings.HasPrefix(strings.ToLower(key), "x-remote-") {
				r.Header.Del(key)
			}
		}
		s.handleConnectorCallback(w, r)
	})
	// For easier connector-specific web server configuration, e.g. for the
	// "authproxy" connector.
	handleFunc("/callback/{connector}", s.handleConnectorCallback)
	handleFunc("/approval", s.handleApproval)
	handle("/healthz", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c.HealthChecker != nil && !c.HealthChecker.IsHealthy() {
			s.renderError(r, w, http.StatusInternalServerError, "Health check failed.")
			return
		}
		fmt.Fprintf(w, "Health check passed")
	}))

	handlePrefix("/static", static)
	handlePrefix("/theme", theme)
	handleFunc("/robots.txt", robots)

	s.mux = r

	s.signer.Start(ctx)
	s.startGarbageCollection(ctx, value(c.GCFrequency, 5*time.Minute), now)

	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) absPath(pathItems ...string) string {
	paths := make([]string, len(pathItems)+1)
	paths[0] = s.issuerURL.Path
	copy(paths[1:], pathItems)
	return path.Join(paths...)
}

func (s *Server) absURL(pathItems ...string) string {
	u := s.issuerURL
	u.Path = s.absPath(pathItems...)
	return u.String()
}

func newPasswordDB(s storage.Storage) interface {
	connector.Connector
	connector.PasswordConnector
} {
	return passwordDB{s}
}

type passwordDB struct {
	s storage.Storage
}

func resolvePasswordName(p storage.Password) string {
	if p.Name != "" {
		return p.Name
	}
	return p.Username
}

func resolvePasswordEmailVerified(p storage.Password) bool {
	if p.EmailVerified != nil {
		return *p.EmailVerified
	}
	return true
}

func (db passwordDB) Login(ctx context.Context, s connector.Scopes, email, password string) (connector.Identity, bool, error) {
	p, err := db.s.GetPassword(ctx, email)
	if err != nil {
		if err != storage.ErrNotFound {
			return connector.Identity{}, false, fmt.Errorf("get password: %v", err)
		}
		return connector.Identity{}, false, nil
	}
	// This check prevents dex users from logging in using static passwords
	// configured with hash costs that are too high or low.
	if err := checkCost(p.Hash); err != nil {
		return connector.Identity{}, false, err
	}
	if err := bcrypt.CompareHashAndPassword(p.Hash, []byte(password)); err != nil {
		return connector.Identity{}, false, nil
	}
	return connector.Identity{
		UserID:            p.UserID,
		Username:          resolvePasswordName(p),
		PreferredUsername: p.PreferredUsername,
		Email:             p.Email,
		EmailVerified:     resolvePasswordEmailVerified(p),
		Groups:            p.Groups,
	}, true, nil
}

const (
	recCost     = 12 // recommended bcrypt cost balancing strength and performance
	upBoundCost = 16 // sane upper bound determined by benchmarking
)

// checkCost returns an error if the bcrypt hash cost is outside the acceptable range.
func checkCost(hash []byte) error {
	actual, err := bcrypt.Cost(hash)
	if err != nil {
		return fmt.Errorf("parsing bcrypt hash: %v", err)
	}
	if actual < bcrypt.DefaultCost {
		return fmt.Errorf("given hash cost = %d does not meet minimum cost requirement = %d", actual, bcrypt.DefaultCost)
	}
	if actual > upBoundCost {
		return fmt.Errorf("given hash cost = %d is above upper bound cost = %d, recommended cost = %d", actual, upBoundCost, recCost)
	}
	return nil
}

func (db passwordDB) Refresh(ctx context.Context, s connector.Scopes, identity connector.Identity) (connector.Identity, error) {
	// If the user has been deleted, the refresh token will be rejected.
	p, err := db.s.GetPassword(ctx, identity.Email)
	if err != nil {
		if err == storage.ErrNotFound {
			return connector.Identity{}, errors.New("user not found")
		}
		return connector.Identity{}, fmt.Errorf("get password: %v", err)
	}

	// User removed but a new user with the same email exists.
	if p.UserID != identity.UserID {
		return connector.Identity{}, errors.New("user not found")
	}

	// If a user has updated their username, that will be reflected in the
	// refreshed token.
	//
	// No other fields are expected to be refreshable as email is effectively used
	// as an ID.
	identity.Username = resolvePasswordName(p)
	identity.PreferredUsername = p.PreferredUsername
	identity.EmailVerified = resolvePasswordEmailVerified(p)
	identity.Groups = p.Groups

	return identity, nil
}

func (db passwordDB) Prompt() string {
	return "Email Address"
}

// newKeyCacher returns a storage which caches keys so long as the next
func newKeyCacher(s storage.Storage, now func() time.Time) storage.Storage {
	if now == nil {
		now = time.Now
	}
	return &keyCacher{Storage: s, now: now}
}

type keyCacher struct {
	storage.Storage

	now  func() time.Time
	keys atomic.Value // Always holds nil or type *storage.Keys.
}

func (k *keyCacher) GetKeys(ctx context.Context) (storage.Keys, error) {
	keys, ok := k.keys.Load().(*storage.Keys)
	if ok && keys != nil && k.now().Before(keys.NextRotation) {
		return *keys, nil
	}

	storageKeys, err := k.Storage.GetKeys(ctx)
	if err != nil {
		return storageKeys, err
	}

	if k.now().Before(storageKeys.NextRotation) {
		k.keys.Store(&storageKeys)
	}
	return storageKeys, nil
}

// VerifyClientSecret delegates to the underlying storage if it implements the
// clientSecretVerifier interface (e.g. the ent Database with argon2id hashing),
// otherwise falls back to constant-time equality.
// ARMORNET FORK: keyCacher wraps storage.Storage (an interface), so custom
// methods on the concrete backend are not promoted — this method re-exposes them.
func (k *keyCacher) VerifyClientSecret(stored, plaintext string) bool {
	type clientSecretVerifier interface {
		VerifyClientSecret(stored, plaintext string) bool
	}
	if v, ok := k.Storage.(clientSecretVerifier); ok {
		return v.VerifyClientSecret(stored, plaintext)
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(plaintext)) == 1
}

// verifyClientSecret reports whether the presented plaintext matches a stored
// client secret. ARMORNET FORK: the single place any handler compares a client
// secret.
//
// It exists because the stored value is an argon2id hash, not the plaintext, so
// a direct comparison is always false. That is not hypothetical — the device
// flow did exactly that and silently rejected every confidential client until it
// was pointed here. Route all comparisons through this method so a future
// handler cannot reintroduce the same bug.
func (s *Server) verifyClientSecret(stored, plaintext string) bool {
	type clientSecretVerifier interface {
		VerifyClientSecret(stored, plaintext string) bool
	}
	if v, ok := s.storage.(clientSecretVerifier); ok {
		return v.VerifyClientSecret(stored, plaintext)
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(plaintext)) == 1
}

func (s *Server) startGarbageCollection(ctx context.Context, frequency time.Duration, now func() time.Time) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(frequency):
				if r, err := s.storage.GarbageCollect(ctx, now()); err != nil {
					s.logger.ErrorContext(ctx, "garbage collection failed", "err", err)
				} else if !r.IsEmpty() {
					s.logger.InfoContext(ctx, "garbage collection run, delete auth",
						"requests", r.AuthRequests, "auth_codes", r.AuthCodes,
						"device_requests", r.DeviceRequests, "device_tokens", r.DeviceTokens)
				}
			}
		}
	}()
}

// ConnectorConfig is a configuration that can open a connector.
type ConnectorConfig interface {
	Open(id string, logger *slog.Logger) (connector.Connector, error)
}

// ConnectorsConfig variable provides an easy way to return a config struct
// depending on the connector type.
var ConnectorsConfig = map[string]func() ConnectorConfig{
	"keystone":        func() ConnectorConfig { return new(keystone.Config) },
	"mockCallback":    func() ConnectorConfig { return new(mock.CallbackConfig) },
	"mockPassword":    func() ConnectorConfig { return new(mock.PasswordConfig) },
	"ldap":            func() ConnectorConfig { return new(ldap.Config) },
	"gitea":           func() ConnectorConfig { return new(gitea.Config) },
	"github":          func() ConnectorConfig { return new(github.Config) },
	"gitlab":          func() ConnectorConfig { return new(gitlab.Config) },
	"google":          func() ConnectorConfig { return new(google.Config) },
	"oidc":            func() ConnectorConfig { return new(oidc.Config) },
	"oauth":           func() ConnectorConfig { return new(oauth.Config) },
	"saml":            func() ConnectorConfig { return new(saml.Config) },
	"authproxy":       func() ConnectorConfig { return new(authproxy.Config) },
	"linkedin":        func() ConnectorConfig { return new(linkedin.Config) },
	"microsoft":       func() ConnectorConfig { return new(microsoft.Config) },
	"bitbucket-cloud": func() ConnectorConfig { return new(bitbucketcloud.Config) },
	"atlassian-crowd": func() ConnectorConfig { return new(atlassiancrowd.Config) },
	// Keep around for backwards compatibility.
	"samlExperimental": func() ConnectorConfig { return new(saml.Config) },
}

// openConnector will parse the connector config and open the connector.
func openConnector(logger *slog.Logger, conn storage.Connector) (connector.Connector, error) {
	var c connector.Connector

	f, ok := ConnectorsConfig[conn.Type]
	if !ok {
		return c, fmt.Errorf("unknown connector type %q", conn.Type)
	}

	connConfig := f()
	if len(conn.Config) != 0 {
		data := []byte(string(conn.Config))
		if err := json.Unmarshal(data, connConfig); err != nil {
			return c, fmt.Errorf("parse connector config: %v", err)
		}
	}

	c, err := connConfig.Open(conn.ID, logger)
	if err != nil {
		return c, fmt.Errorf("failed to create connector %s: %v", conn.ID, err)
	}

	return c, nil
}

// OpenConnector updates server connector map with specified connector object.
func (s *Server) OpenConnector(conn storage.Connector) (Connector, error) {
	var c connector.Connector

	if conn.Type == LocalConnector {
		c = newPasswordDB(s.storage)
	} else {
		var err error
		c, err = openConnector(s.logger, conn)
		if err != nil {
			// ARMORNET FORK: record the failure. This is the only place an open
			// is attempted, so it is the only place that can tell "broken" from
			// "not tried yet".
			s.mu.Lock()
			s.failedConnectors[conn.ID] = struct{}{}
			s.mu.Unlock()
			return Connector{}, fmt.Errorf("failed to open connector: %v", err)
		}
	}

	connector := Connector{
		ResourceVersion: conn.ResourceVersion,
		Connector:       c,
	}
	s.mu.Lock()
	s.connectors[conn.ID] = connector
	// ARMORNET FORK: a connector that opens is no longer broken — a lazy retry
	// after the operator fixed its config must clear the earlier failure.
	delete(s.failedConnectors, conn.ID)
	s.mu.Unlock()

	return connector, nil
}

// FailedConnectorIDs returns the ids of connectors whose open was attempted and
// refused.
// ARMORNET FORK.
func (s *Server) FailedConnectorIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.failedConnectors))
	for id := range s.failedConnectors {
		ids = append(ids, id)
	}
	return ids
}

// OpenConnectorIDs returns the ids of every connector that actually opened.
// ARMORNET FORK.
//
// It exists because "a connector row exists" and "a user can sign in with it"
// stopped being the same statement once ContinueOnConnectorFailure was enabled:
// a row that fails to open is now skipped rather than fatal, so a health check
// counting rows would report a working login path that does not exist.
func (s *Server) OpenConnectorIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.connectors))
	for id := range s.connectors {
		ids = append(ids, id)
	}
	return ids
}

// getConnector retrieves the connector object with the given id.
// Static connectors (loaded from Config.Connectors) are returned directly from
// s.connectors without a storage round-trip. Dynamic connectors are refreshed
// from storage when their ResourceVersion has changed.
func (s *Server) getConnector(ctx context.Context, id string) (Connector, error) {
	s.mu.Lock()
	conn, ok := s.connectors[id]
	s.mu.Unlock()

	// Static connectors are never in storage; return immediately.
	if ok && conn.ResourceVersion == staticResourceVersion {
		return conn, nil
	}

	storageConnector, err := s.storage.GetConnector(ctx, id)
	if err != nil {
		return Connector{}, fmt.Errorf("failed to get connector object from storage: %v", err)
	}

	if !ok || storageConnector.ResourceVersion != conn.ResourceVersion {
		// Connector object does not exist in server connectors map or
		// has been updated in the storage. Need to get latest.
		conn, err = s.OpenConnector(storageConnector)
		if err != nil {
			return Connector{}, fmt.Errorf("failed to open connector: %v", err)
		}
	}

	return conn, nil
}

// listConnectors returns static connectors merged with storage connectors.
// Static connectors take precedence: if a connector ID appears in both, the
// static entry is used and the storage entry is omitted.
func (s *Server) listConnectors(ctx context.Context) ([]storage.Connector, error) {
	stored, err := s.storage.ListConnectors(ctx)
	if err != nil {
		return nil, err
	}
	if len(s.staticConnectors) == 0 {
		return stored, nil
	}
	staticIDs := make(map[string]bool, len(s.staticConnectors))
	for _, c := range s.staticConnectors {
		staticIDs[c.ID] = true
	}
	all := make([]storage.Connector, 0, len(s.staticConnectors)+len(stored))
	all = append(all, s.staticConnectors...)
	for _, c := range stored {
		if !staticIDs[c.ID] {
			all = append(all, c)
		}
	}
	return all, nil
}

type logRequestKey string

const (
	RequestKeyRequestID logRequestKey = "request_id"
	RequestKeyRemoteIP  logRequestKey = "client_remote_addr"
)

func WithRequestID(ctx context.Context) context.Context {
	return context.WithValue(ctx, RequestKeyRequestID, uuid.NewString())
}

func WithRemoteIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, RequestKeyRemoteIP, ip)
}
