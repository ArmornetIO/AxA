package identity

import (
	"os/exec"
	"slices"
	"strings"
	"testing"
)

const (
	pkgAuthn  = "github.com/ArmornetIO/identity/authn"
	pkgAuthz  = "github.com/ArmornetIO/identity/authz"
	pkgAccess = "github.com/ArmornetIO/identity/access"
)

// goList runs go list over patterns and returns one line per package, each
// "<path> <space-separated field>".
func goList(t *testing.T, field string, patterns ...string) map[string][]string {
	t.Helper()
	args := append([]string{"list", "-f", "{{.ImportPath}} {{join ." + field + " \" \"}}"}, patterns...)
	out, err := exec.Command("go", args...).Output()
	if err != nil {
		t.Fatalf("go %s: %v", strings.Join(args, " "), err)
	}
	pkgs := map[string][]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		pkgs[f[0]] = f[1:]
	}
	return pkgs
}

func within(p, root string) bool { return p == root || strings.HasPrefix(p, root+"/") }

// TestLayering keeps authn and authz leaves that only access composes; a leaf
// importing up is what would stop authz shipping on its own.
func TestLayering(t *testing.T) {
	for leaf, banned := range map[string][]string{
		pkgAuthn + "/...": {pkgAuthz, pkgAccess},
		pkgAuthz + "/...": {pkgAuthn, pkgAccess},
	} {
		for pkg, deps := range goList(t, "Deps", leaf) {
			for _, d := range deps {
				for _, b := range banned {
					if within(d, b) {
						t.Errorf("%s depends on %s; authn and authz are leaves and only access composes them", pkg, d)
					}
				}
			}
		}
	}

	for pkg, imports := range goList(t, "Imports", "./...") {
		both := slices.ContainsFunc(imports, func(i string) bool { return within(i, pkgAuthn) }) &&
			slices.ContainsFunc(imports, func(i string) bool { return within(i, pkgAuthz) })
		if both && pkg != pkgAccess {
			t.Errorf("%s imports both authn and authz; access is the only composition point", pkg)
		}
	}
}
