package identity

import (
	"context"
	"errors"
)

// ClientStore is CRUD for the broker's OAuth2 clients. Unknown IDs return
// ErrClientNotFound; a duplicate Create returns ErrClientExists.
type ClientStore interface {
	// Create returns the generated secret once and never again (Dex stores it
	// hashed). A Public client gets "": PKCE needs no secret to leak.
	Create(ctx context.Context, c Client) (secret string, err error)
	// List and Get always leave Secret empty.
	List(ctx context.Context) ([]Client, error)
	Get(ctx context.Context, id string) (Client, error)
	// Update replaces Name, RedirectURIs, TrustedPeers and LogoURL, never the secret.
	Update(ctx context.Context, c Client) error
	Delete(ctx context.Context, id string) error
	// RotateSecret returns the new secret once. The old one dies immediately, with
	// no overlap, so rotate a live client only if you can deliver the new one.
	RotateSecret(ctx context.Context, id string) (secret string, err error)
}

type Client struct {
	ID   string
	Name string
	// RedirectURIs is an allowlist: any other redirect_uri is rejected.
	RedirectURIs []string
	// TrustedPeers are client IDs whose ID tokens this client accepts.
	TrustedPeers []string
	// Public clients (native apps, SPAs) use PKCE and have no secret.
	Public  bool
	LogoURL string
}

var (
	ErrClientNotFound = errors.New("identity: client not found")
	ErrClientExists   = errors.New("identity: client already exists")
)
