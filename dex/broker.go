package dex

import (
	"net/http"
	"sync"

	"github.com/ArmornetIO/identity"
	dexserver "github.com/ArmornetIO/identity/internal/dex/server"
	dexstorage "github.com/ArmornetIO/identity/internal/dex/storage"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// broker exists from New so it can be wired early; until Start it 503s and its
// stores fail ErrNotStarted. Work needing a live store is a StartupSeeder.
type broker struct {
	mu         sync.RWMutex
	handler    http.Handler // set by initialise(); nil until then
	dexSrv     *dexserver.Server
	stor       dexstorage.Storage
	connectors *connectorStore
	clients    *clientStore
	// wrap, set from New before Start, is the device gate when one is configured.
	wrap func(http.Handler) http.Handler
}

func newBrokerShell() *broker { return &broker{} }

// initialise wires the live Dex server into the broker shell. Called by
// Server.Start() after storage and the Dex server are confirmed healthy.
func (b *broker) initialise(srv *dexserver.Server, stor dexstorage.Storage, secrets SecretResolver) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var h http.Handler = srv
	if b.wrap != nil {
		h = b.wrap(h)
	}
	b.handler = otelhttp.NewHandler(h, "dex")
	b.dexSrv = srv
	b.stor = stor
	b.connectors = &connectorStore{storage: stor, secrets: secrets}
	b.clients = &clientStore{storage: stor}
}

// Handler mounts as r.Any("/dex/*path", gin.WrapH(broker.Handler())).
func (b *broker) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.RLock()
		h := b.handler
		b.mu.RUnlock()
		if h == nil {
			http.Error(w, "identity broker starting", http.StatusServiceUnavailable)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// Connectors returns the ConnectorStore backed by Dex's K8s CRD storage.
func (b *broker) Connectors() identity.ConnectorStore {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.connectors
}

// Clients returns the ClientStore backed by Dex's K8s CRD storage.
func (b *broker) Clients() identity.ClientStore {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.clients
}

// ready reports whether initialise() has completed. Unexported — health
// checks go through Server.Health(), not through the Broker interface.
func (b *broker) ready() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.handler != nil
}

var _ identity.Broker = (*broker)(nil)
