package authn_test

import (
	"sort"
	"testing"

	"github.com/ArmornetIO/identity/authn"
)

func TestGrantableScopes_AdminRolesGetEverything(t *testing.T) {
	for _, role := range []string{"owner", "admin", "god_admin"} {
		got := authn.GrantableScopes(role)
		if len(got) != len(authn.KnownScopes) {
			t.Fatalf("role %q: got %d scopes, want all %d", role, len(got), len(authn.KnownScopes))
		}
		for _, s := range authn.KnownScopes {
			if !authn.CanGrant(role, s) {
				t.Errorf("role %q must be able to grant %q", role, s)
			}
		}
	}
}

func TestGrantableScopes_MemberReadOnly(t *testing.T) {
	got := authn.GrantableScopes("member")
	want := []string{
		"agents:read",
		"assessment:read",
		"codebase:read",
		"dns:read",
		"docs:read",
		"editor:read",
		"findings:read",
		"integrations:read",
		"jobboard:read",
		"members:read",
		"notifications:read",
		"org:read",
		"posture:read",
		"proxies:read",
		"repos:read",
		"risk:read",
		"scada:read",
		"secrets:read",
		"threat:read",
		"vendors:read",
		"webhooks:read",
	}
	sort.Strings(got)
	if len(got) != len(want) {
		t.Fatalf("member scopes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("member scopes = %v, want %v", got, want)
		}
	}
	// Explicitly: a member may NOT grant write/admin/token-management scopes.
	for _, s := range []string{"vendors:write", "dns:admin", "proxies:admin", "integrations:write", "assessment:write", "tokens:manage"} {
		if authn.CanGrant("member", s) {
			t.Errorf("member must NOT be able to grant %q", s)
		}
	}
}

func TestGrantableScopes_UnknownRoleFailsClosed(t *testing.T) {
	if got := authn.GrantableScopes(""); got != nil {
		t.Errorf("empty role must grant nothing, got %v", got)
	}
	if got := authn.GrantableScopes("visitor"); got != nil {
		t.Errorf("unknown role must grant nothing, got %v", got)
	}
	if authn.CanGrant("", "vendors:read") {
		t.Error("empty role must not grant vendors:read")
	}
}

func TestDisallowedScopes(t *testing.T) {
	// A member requesting a read + an admin scope: only the admin scope is rejected.
	bad := authn.DisallowedScopes("member", []string{"vendors:read", "dns:admin", "tokens:manage"})
	sort.Strings(bad)
	want := []string{"dns:admin", "tokens:manage"}
	if len(bad) != len(want) || bad[0] != want[0] || bad[1] != want[1] {
		t.Fatalf("DisallowedScopes = %v, want %v", bad, want)
	}
	// An admin requesting the same set: nothing rejected.
	if bad := authn.DisallowedScopes("admin", []string{"vendors:read", "dns:admin", "tokens:manage"}); len(bad) != 0 {
		t.Fatalf("admin should be allowed all, got disallowed %v", bad)
	}
	// An unknown scope is always disallowed, regardless of role.
	if bad := authn.DisallowedScopes("owner", []string{"made:up"}); len(bad) != 1 || bad[0] != "made:up" {
		t.Fatalf("unknown scope must be disallowed, got %v", bad)
	}
}

func TestIsKnownScope(t *testing.T) {
	if !authn.IsKnownScope("dns:admin") {
		t.Error("dns:admin should be known")
	}
	if authn.IsKnownScope("made:up") {
		t.Error("made:up should not be known")
	}
}
