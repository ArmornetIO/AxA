package authn

import "strings"

// Org roles used for PAT scope entitlement. These mirror the org role chain
// (owner ⇒ admin ⇒ member); god_admin is the platform superuser.
const (
	RoleOwner    = "owner"
	RoleAdmin    = "admin"
	RoleMember   = "member"
	RoleGodAdmin = "god_admin"
)

// KnownScopes is the canonical catalog of PAT scopes the platform recognizes.
// It is the single source of truth for both the issuance allowlist and the
// scope picker offered by the UI.
var KnownScopes = []string{
	"vendors:read",
	"vendors:write",
	"assessment:read",
	"assessment:write",
	"dns:read",
	"dns:admin",
	"proxies:read",
	"proxies:admin",
	"risk:read",
	"risk:write",
	"risk:approve",
	"integrations:read",
	"integrations:write",
	"notifications:read",
	"tokens:manage",
	// Agents, their credentials, configs and models: the agent and identity
	// client commands of the CLI, for automation that deploys agents.
	"agents:read",
	"agents:write",
	"repos:read",
	"repos:write",
	"codebase:read",
	"codebase:write",
	"docs:read",
	"docs:write",
	"editor:read",
	"editor:write",
	"posture:read",
	"posture:write",
	"threat:read",
	"threat:write",
	"findings:read",
	"findings:write",
	"webhooks:read",
	"webhooks:write",
	// Secret rotation runbooks and runs; no secret value passes through these
	// routes, and a started rotation still waits on its named approvers.
	"secrets:read",
	"secrets:rotate",
	"scada:read",
	"scada:write",
	"jobboard:read",
	"jobboard:write",
	// The org's settings and its members, read only: renaming the org, sign-in
	// connectors, the domain allowlist and membership are a signed-in person's.
	"org:read",
	"members:read",
}

// IsKnownScope reports whether s is a recognized PAT scope.
func IsKnownScope(s string) bool {
	for _, k := range KnownScopes {
		if k == s {
			return true
		}
	}
	return false
}

// GrantableScopes returns the scopes a caller holding the given org role may
// grant to a personal access token. Capability attenuation: a PAT's authority
// can never exceed the issuing user's own authority.
//
//   - owner / admin / god_admin: any known scope.
//   - member: read-only scopes (suffix ":read") — no write, admin, or
//     token-management scopes.
//   - any other/unknown role: nothing (fail closed).
func GrantableScopes(role string) []string {
	switch role {
	case RoleOwner, RoleAdmin, RoleGodAdmin:
		return append([]string(nil), KnownScopes...)
	case RoleMember:
		var out []string
		for _, s := range KnownScopes {
			if strings.HasSuffix(s, ":read") {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// CanGrant reports whether a caller with role may grant scope.
func CanGrant(role, scope string) bool {
	for _, s := range GrantableScopes(role) {
		if s == scope {
			return true
		}
	}
	return false
}

// DisallowedScopes returns the subset of requested scopes that a caller with
// role may NOT grant — either because the scope exceeds the role's entitlement
// or because it is not a known scope. An empty result means the request is fully
// within the caller's authority.
func DisallowedScopes(role string, requested []string) []string {
	var bad []string
	for _, s := range requested {
		if !CanGrant(role, s) {
			bad = append(bad, s)
		}
	}
	return bad
}
