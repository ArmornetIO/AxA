package authn

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ArmornetIO/identity/authn/secrethash"
)

// ErrMagicLinkInvalid is every failure alike, so a redeemer can't enumerate.
var ErrMagicLinkInvalid = errors.New("authn: magic link invalid or expired")

// DefaultMagicLinkTTL is the fallback link lifetime. Magic links are meant to be
// short-lived hand-offs, not standing credentials — keep this small.
const DefaultMagicLinkTTL = 15 * time.Minute

// Grant is opaque here; the host enforces it through FGA. Subject is a host-minted
// id, NEVER the email, which only finds the grant.
type Grant struct {
	Subject    string
	OrgID      string
	ObjectType string
	ObjectID   string
	Relation   string
}

// MagicLinkClaims matches Claims' method set, so a grantee uses the SAME front
// door as any provider; the Grant rides alongside.
type MagicLinkClaims struct {
	grant Grant
}

func (c MagicLinkClaims) Subject() string  { return c.grant.Subject }
func (c MagicLinkClaims) OrgID() string    { return c.grant.OrgID }
func (c MagicLinkClaims) Groups() []string { return nil }

// Grant returns the scoped access the redeemed link confers.
func (c MagicLinkClaims) Grant() Grant { return c.grant }

// Notification: the library builds token, URL and expiry; the host picks channel
// and message.
type Notification struct {
	Email     string    // recipient — transient; the durable id is Grant.Subject
	URL       string    // redeem URL with the token embedded (built by the host's URL fn)
	Token     string    // raw token, if the host prefers to compose its own link
	ExpiresAt time.Time // when the link stops working
	Grant     Grant     // grant context (e.g. so the host can name the assessment)
}

// Notifier delivers a magic link. The identity module never touches SMTP or any
// transport — the host implements delivery (email/SMS/…).
type Notifier interface {
	Notify(ctx context.Context, n Notification) error
}

// Resolver is the host's domain seam; (_, false, nil) for an unknown email, which
// gets the SAME outcome (no enumeration).
type Resolver interface {
	Resolve(ctx context.Context, email string) (Grant, bool, error)
}

// MagicLinkRecord's table is identity's schema; the host implements the store.
type MagicLinkRecord struct {
	ID        string
	Prefix    string
	TokenHash string
	Grant     Grant
	ExpiresAt time.Time
}

// MagicLinkStore enforces single use in Consume (false if spent or expired), so
// concurrent redeems can't race.
type MagicLinkStore interface {
	Create(ctx context.Context, rec MagicLinkRecord) error
	ByPrefix(ctx context.Context, prefix string) ([]MagicLinkRecord, error)
	Consume(ctx context.Context, id string) (bool, error)
}

// MagicLinkProvider: single-use links for third parties without federated login;
// the host's Resolver and Notifier decide who, what and how.
type MagicLinkProvider struct {
	store    MagicLinkStore
	resolver Resolver
	notifier Notifier
	linkURL  func(token string) string
	ttl      time.Duration
	params   secrethash.Argon2idParams
}

// MagicLinkOption configures a MagicLinkProvider.
type MagicLinkOption func(*MagicLinkProvider)

// WithMagicLinkTTL sets how long an issued link stays valid. Keep it short.
func WithMagicLinkTTL(d time.Duration) MagicLinkOption {
	return func(p *MagicLinkProvider) {
		if d > 0 {
			p.ttl = d
		}
	}
}

// NewMagicLinkProvider's linkURL turns a raw token into the redeem URL.
func NewMagicLinkProvider(
	store MagicLinkStore,
	resolver Resolver,
	notifier Notifier,
	linkURL func(token string) string,
	opts ...MagicLinkOption,
) *MagicLinkProvider {
	p := &MagicLinkProvider{
		store:    store,
		resolver: resolver,
		notifier: notifier,
		linkURL:  linkURL,
		ttl:      DefaultMagicLinkTTL,
		params:   secrethash.DefaultArgon2Params(),
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Request is ENUMERATION-SAFE: an unknown email returns nil and sends nothing.
// Callers render the same generic reply whatever it returns.
func (p *MagicLinkProvider) Request(ctx context.Context, email string) error {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return nil
	}
	grant, ok, err := p.resolver.Resolve(ctx, email)
	if err != nil {
		return fmt.Errorf("magiclink: resolve: %w", err)
	}
	if !ok {
		return nil // enumeration-safe: silently do nothing for unknown emails
	}

	tok, err := MintToken(TokenPrefixMagic, p.params)
	if err != nil {
		return fmt.Errorf("magiclink: mint: %w", err)
	}
	id, err := newMagicID()
	if err != nil {
		return fmt.Errorf("magiclink: id: %w", err)
	}
	rec := MagicLinkRecord{
		ID:        id,
		Prefix:    tok.Prefix,
		TokenHash: tok.Hash,
		Grant:     grant,
		ExpiresAt: time.Now().Add(p.ttl),
	}
	if err := p.store.Create(ctx, rec); err != nil {
		return fmt.Errorf("magiclink: create: %w", err)
	}
	return p.notifier.Notify(ctx, Notification{
		Email:     email,
		URL:       p.linkURL(tok.Raw),
		Token:     tok.Raw,
		ExpiresAt: rec.ExpiresAt,
		Grant:     grant,
	})
}

// Redeem consumes the first live match atomically; every failure is
// ErrMagicLinkInvalid.
func (p *MagicLinkProvider) Redeem(ctx context.Context, rawToken string) (Grant, error) {
	rawToken = strings.TrimSpace(rawToken)
	if !strings.HasPrefix(rawToken, TokenPrefixMagic) {
		return Grant{}, ErrMagicLinkInvalid
	}
	cands, err := p.store.ByPrefix(ctx, TokenPrefix(rawToken))
	if err != nil {
		return Grant{}, fmt.Errorf("%w: lookup: %v", ErrMagicLinkInvalid, err)
	}
	rec, err := RedeemToken(ctx, TokenPrefixMagic, rawToken, cands,
		func(r MagicLinkRecord) StoredToken {
			return StoredToken{ID: r.ID, Hash: r.TokenHash, ExpiresAt: r.ExpiresAt}
		}, p.store.Consume)
	if err != nil {
		return Grant{}, fmt.Errorf("%w: %v", ErrMagicLinkInvalid, err)
	}
	return rec.Grant, nil
}

// newMagicID returns a random opaque record id (128 bits, base32). Used to key
// the single-use Consume; never derived from the token.
func newMagicID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)), nil
}
