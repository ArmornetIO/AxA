// Package identity is the broker contract the REST and OIDC layers program
// against; backends (dex/) implement it and callers never import one directly.
package axa

import (
	"context"
	"net/http"
)

// Broker issues OIDC tokens, federates upstream IdPs and serves connector and
// client CRUD. Safe for concurrent use.
type Broker interface {
	// Handler serves discovery, /auth, /token, /keys and /callback; it must not
	// rewrite the prefix it is mounted under.
	Handler() http.Handler
	Connectors() ConnectorStore
	Clients() ClientStore
}

// SeedFunc runs once storage is healthy. Idempotent: never overwrites a record.
type SeedFunc func(ctx context.Context, b Broker) error

// StartupSeeder is a SeedFunc with a name for the startup logs.
type StartupSeeder interface {
	Name() string
	Seed(ctx context.Context, b Broker) error
}

func Named(name string, fn SeedFunc) StartupSeeder { return &namedSeeder{name, fn} }

type namedSeeder struct {
	name string
	fn   SeedFunc
}

func (n *namedSeeder) Name() string                             { return n.name }
func (n *namedSeeder) Seed(ctx context.Context, b Broker) error { return n.fn(ctx, b) }
