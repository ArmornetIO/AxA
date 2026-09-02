package dex

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/ArmornetIO/identity"
	dexstorage "github.com/ArmornetIO/identity/internal/dex/storage"
)

// clientStore implements identity.ClientStore via Dex's K8s CRD storage.
type clientStore struct {
	storage dexstorage.Storage
}

// ErrNotStarted: hook work that needs a live store as an identity.StartupSeeder.
var ErrNotStarted = errors.New("identity/dex: broker not started")

// ready guards every method against use before initialise().
func (s *clientStore) ready() error {
	if s == nil || s.storage == nil {
		return ErrNotStarted
	}
	return nil
}

// Create returns the generated secret once; Dex stores it hashed.
func (s *clientStore) Create(ctx context.Context, c identity.Client) (string, error) {
	if err := s.ready(); err != nil {
		return "", err
	}
	secret, err := generateSecret()
	if err != nil {
		return "", fmt.Errorf("identity/dex: generate client secret: %w", err)
	}

	dc := toDexClient(c, secret)
	if err := s.storage.CreateClient(ctx, dc); err != nil {
		if errors.Is(err, dexstorage.ErrAlreadyExists) {
			return "", identity.ErrClientExists
		}
		return "", fmt.Errorf("identity/dex: create client %q: %w", c.ID, err)
	}
	if c.Public {
		// Stored only because Dex's storage refuses an empty secret; a public
		// client proves itself with PKCE and must never be handed one to ship.
		return "", nil
	}
	return secret, nil
}

func (s *clientStore) List(ctx context.Context) ([]identity.Client, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	dcs, err := s.storage.ListClients(ctx)
	if err != nil {
		return nil, fmt.Errorf("identity/dex: list clients: %w", err)
	}
	out := make([]identity.Client, len(dcs))
	for i, dc := range dcs {
		out[i] = fromDexClient(dc)
	}
	return out, nil
}

func (s *clientStore) Get(ctx context.Context, id string) (identity.Client, error) {
	if err := s.ready(); err != nil {
		return identity.Client{}, err
	}
	dc, err := s.storage.GetClient(ctx, id)
	if err != nil {
		if errors.Is(err, dexstorage.ErrNotFound) {
			return identity.Client{}, identity.ErrClientNotFound
		}
		return identity.Client{}, fmt.Errorf("identity/dex: get client %q: %w", id, err)
	}
	return fromDexClient(dc), nil
}

// Update replaces mutable fields (Name, RedirectURIs, TrustedPeers, LogoURL).
// The client secret is not touched.
func (s *clientStore) Update(ctx context.Context, c identity.Client) error {
	if err := s.ready(); err != nil {
		return err
	}
	updater := func(old dexstorage.Client) (dexstorage.Client, error) {
		old.Name = c.Name
		old.RedirectURIs = c.RedirectURIs
		old.TrustedPeers = c.TrustedPeers
		old.Public = c.Public
		old.LogoURL = storedLogoURL(c.LogoURL)
		return old, nil
	}
	if err := s.storage.UpdateClient(ctx, c.ID, updater); err != nil {
		if errors.Is(err, dexstorage.ErrNotFound) {
			return identity.ErrClientNotFound
		}
		return fmt.Errorf("identity/dex: update client %q: %w", c.ID, err)
	}
	return nil
}

// RotateSecret replaces only the secret: agents keep their identity.
func (s *clientStore) RotateSecret(ctx context.Context, id string) (string, error) {
	if err := s.ready(); err != nil {
		return "", err
	}
	secret, err := generateSecret()
	if err != nil {
		return "", fmt.Errorf("identity/dex: generate client secret: %w", err)
	}

	updater := func(old dexstorage.Client) (dexstorage.Client, error) {
		old.Secret = secret
		return old, nil
	}
	if err := s.storage.UpdateClient(ctx, id, updater); err != nil {
		if errors.Is(err, dexstorage.ErrNotFound) {
			return "", identity.ErrClientNotFound
		}
		return "", fmt.Errorf("identity/dex: rotate secret for client %q: %w", id, err)
	}
	return secret, nil
}

func (s *clientStore) Delete(ctx context.Context, id string) error {
	if err := s.ready(); err != nil {
		return err
	}
	if err := s.storage.DeleteClient(ctx, id); err != nil {
		if errors.Is(err, dexstorage.ErrNotFound) {
			return identity.ErrClientNotFound
		}
		return fmt.Errorf("identity/dex: delete client %q: %w", id, err)
	}
	return nil
}

// toDexClient converts an identity.Client to Dex's storage type.
// secret is stored in Dex's CRD; it is protected by the ServiceAccount RBAC.
func toDexClient(c identity.Client, secret string) dexstorage.Client {
	return dexstorage.Client{
		ID:           c.ID,
		Secret:       secret,
		RedirectURIs: c.RedirectURIs,
		TrustedPeers: c.TrustedPeers,
		Public:       c.Public,
		Name:         c.Name,
		LogoURL:      storedLogoURL(c.LogoURL),
	}
}

// noLogoURL is a transparent 1×1 GIF: Dex refuses an empty logo_url.
const noLogoURL = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"

func storedLogoURL(u string) string {
	if u == "" {
		return noLogoURL
	}
	return u
}

// fromDexClient converts a Dex storage client to identity.Client.
// Secret is always empty — the plaintext is never returned after creation.
func fromDexClient(dc dexstorage.Client) identity.Client {
	return identity.Client{
		ID:           dc.ID,
		Name:         dc.Name,
		RedirectURIs: dc.RedirectURIs,
		TrustedPeers: dc.TrustedPeers,
		Public:       dc.Public,
		LogoURL:      readLogoURL(dc.LogoURL),
	}
}

func readLogoURL(u string) string {
	if u == noLogoURL {
		return ""
	}
	return u
}

// generateSecret produces a cryptographically random 32-byte secret encoded
// as base64url without padding, suitable for use as an OAuth2 client_secret.
func generateSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

var _ identity.ClientStore = (*clientStore)(nil)
