package web

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"

	"github.com/ArmornetIO/axa/authn"
)

var (
	ErrInviteRevoked        = errors.New("invite has been revoked")
	ErrInviteExpired        = errors.New("invite has expired")
	ErrInviteAlreadyUsed    = errors.New("invite has already been used")
	ErrInviteEmailMismatch  = errors.New("invite is for a different email address")
	ErrInviteDomainMismatch = errors.New("invite is not valid for your email domain")
	ErrNotMember            = errors.New("not a member of this org")
)

// RedeemInvite links userID to the invite's org and returns it; fails with the
// sentinels above or authn.ErrNoInvite. A domain invite needs emailVerified:
// unlike a user invite it is not a secret handed to one person.
func RedeemInvite(ctx context.Context, invites authn.InviteStore, users authn.UserStore, email string, emailVerified bool, userID, inviteID string) (string, error) {
	inv, err := invites.ByID(ctx, inviteID)
	if err != nil {
		return "", err
	}
	if inv.RevokedAt != nil {
		return "", ErrInviteRevoked
	}
	if time.Now().After(inv.ExpiresAt) {
		return "", ErrInviteExpired
	}
	switch inv.Kind {
	case "user":
		if inv.AcceptedAt != nil {
			return "", ErrInviteAlreadyUsed
		}
		if !strings.EqualFold(email, inv.Binding) {
			return "", ErrInviteEmailMismatch
		}
	case "domain":
		if !emailVerified || ExtractDomain(email) != inv.Binding {
			return "", ErrInviteDomainMismatch
		}
	}
	if err := users.LinkOrgUser(ctx, inv.OrgID, userID, inv.Role); err != nil {
		return "", err
	}
	if inv.Kind == "user" {
		if err := invites.MarkAccepted(ctx, inv.ID, userID); err != nil {
			slog.WarnContext(ctx, "mark invite accepted", "err", err, "invite_id", inv.ID)
		}
	}
	return inv.OrgID, nil
}

// TryDomainAutoJoin links userID to orgID when the org's domain allowlist
// matches email's domain. Returns ErrNotMember when nothing matches or the IdP
// did not verify the email.
func TryDomainAutoJoin(ctx context.Context, allowlist authn.DomainAllowlistStore, users authn.UserStore, email string, emailVerified bool, orgID, userID string) error {
	if allowlist == nil || !emailVerified {
		return ErrNotMember
	}
	domain := ExtractDomain(email)
	if domain == "" {
		return ErrNotMember
	}
	entry, err := allowlist.Match(ctx, orgID, domain)
	if err != nil {
		return ErrNotMember
	}
	return users.LinkOrgUser(ctx, orgID, userID, entry.Role)
}

// TrySelfRegister is single-tenant only (multi-tenant, anyone joins any org they
// name). role must be non-privileged; default "member".
func TrySelfRegister(ctx context.Context, users authn.UserStore, enabled bool, orgID, userID, role string) error {
	if !enabled {
		return ErrNotMember
	}
	if role == "" {
		role = "member"
	}
	return users.LinkOrgUser(ctx, orgID, userID, role)
}

var (
	ErrInvalidDomain = errors.New("not a valid domain name")
	// ErrSharedDomain covers public suffixes and mailbox providers: anyone can
	// hold an address there, so a rule on one admits the public.
	ErrSharedDomain = errors.New("domain is shared by unrelated people; use a domain your org owns")
)

// sharedMailDomains are providers that hand addresses to anyone. Not
// exhaustive; publicsuffix catches "github.io"-style hosts.
var sharedMailDomains = []string{
	"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
	"yahoo.com", "ymail.com", "icloud.com", "me.com", "mac.com", "aol.com",
	"proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.net", "mail.com",
	"zoho.com", "yandex.com", "yandex.ru", "fastmail.com", "tutanota.com", "hey.com",
	"qq.com", "163.com", "126.com", "users.noreply.github.com",
}

// NormalizeDomain returns the ASCII form of a domain an org wants to bind
// membership to. It rejects malformed names, so a typo is a 400 rather than a
// rule that silently never matches, and bare public suffixes ("com", "co.uk",
// "github.io") and public mailbox providers.
func NormalizeDomain(raw string) (string, error) {
	d, err := idna.Registration.ToASCII(strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(raw)), "@"), "."))
	if err != nil || d == "" {
		return "", ErrInvalidDomain
	}
	if _, err := publicsuffix.EffectiveTLDPlusOne(d); err != nil || slices.Contains(sharedMailDomains, d) {
		return "", ErrSharedDomain
	}
	return d, nil
}

// ExtractDomain returns the lowercased domain part of an email address.
func ExtractDomain(email string) string {
	if at := strings.LastIndexByte(email, '@'); at >= 0 {
		return strings.ToLower(email[at+1:])
	}
	return ""
}

// SignupDomainAllowed keeps strangers off a pre-production login page; an empty
// allowlist disables it.
func SignupDomainAllowed(allowed []string, email string) bool {
	if len(allowed) == 0 {
		return true
	}
	domain := ExtractDomain(email)
	if domain == "" {
		return false
	}
	for _, a := range allowed {
		if strings.EqualFold(strings.TrimSpace(a), domain) {
			return true
		}
	}
	return false
}
