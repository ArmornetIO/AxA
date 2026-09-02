package authn

import (
	"context"
	"errors"
	"time"
)

// ErrNoInvite is returned when an invite token or id names nothing the caller
// may act on — absent, or already spent for the operation attempted.
var ErrNoInvite = errors.New("authn: no such invite")

// Invite kinds. The vocabulary is identity's because it changes what the invite
// MEANS at redemption, not merely how it is labelled.
const (
	// InviteKindUser binds to one person: Binding is the address it was sent to,
	// and accepting it is a fact recorded against the accepting user.
	InviteKindUser = "user"
	// InviteKindDomain binds to an email suffix and is reusable — anyone whose
	// verified address matches may join. It is never "accepted" by one person,
	// which is why acceptance lives on a separate row rather than on the invite.
	InviteKindDomain = "domain"
)

// Invite is a pending grant of membership, flattened across the invite and the
// people attached to it.
//
// Token is the secret in the link. It is stored as-is rather than hashed, which
// is a weaker position than sessions or PATs take and is worth naming: the
// lookup is by exact token and could hash, but the value is also the row's
// unique key and the shape predates the hashing convention. A host tightening
// this should hash and keep a prefix, as magic_link does.
//
// Role is opaque here, as everywhere in this package — identity records which
// role an invite confers and never decides what it permits.
type Invite struct {
	ID    string
	OrgID string
	Kind  string
	// Binding is what the invite is FOR: an address for a user invite, a domain
	// suffix for a domain invite. Its meaning follows Kind and nothing else.
	Binding   string
	Role      string
	Token     string
	ExpiresAt time.Time
	RevokedAt *time.Time
	CreatedAt time.Time

	// The parties, from the row that holds them. Kept flat because no caller
	// wants one without the other, and the join is one-to-one.

	// InvitedBy is the internal user id of the issuer.
	InvitedBy string
	// TargetUserID is set once an invite is bound to a specific user.
	TargetUserID string
	AcceptedBy   string
	AcceptedAt   *time.Time
}

// Pending reports whether the invite can still be redeemed at t.
func (i Invite) Pending(t time.Time) bool {
	return i.RevokedAt == nil && i.AcceptedAt == nil && t.Before(i.ExpiresAt)
}

// InviteStore persists invites and the parties attached to them.
type InviteStore interface {
	// Create writes the invite and its party row together. Together, not in two
	// calls: an invite with no issuer recorded is an invite nobody can be held
	// to, and a crash between two writes would leave exactly that.
	Create(ctx context.Context, inv Invite, invitedByUserID string) (Invite, error)
	// ByToken resolves the secret in a link. It returns revoked, expired and
	// accepted invites too — the caller decides, because "this invite was already
	// used" and "no such invite" are different things to tell a person.
	ByToken(ctx context.Context, token string) (Invite, error)
	ByID(ctx context.Context, id string) (Invite, error)
	ListByOrg(ctx context.Context, orgID string) ([]Invite, error)
	// Revoke withdraws an invite, scoped by org so one tenant cannot cancel
	// another's. Returns ErrNoInvite when nothing live matched.
	Revoke(ctx context.Context, id, orgID string) error
	// MarkAccepted records who redeemed a user invite. The `not yet accepted`
	// condition is part of the write, so two people racing the same link cannot
	// both be recorded as its acceptor.
	MarkAccepted(ctx context.Context, inviteID, accepterUserID string) error
}
