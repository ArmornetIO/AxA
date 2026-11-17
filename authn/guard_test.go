package authn_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestModuleGuard pins what makes authn worth being a module: a developer takes
// it for sign-in and gets nothing of identity (Dex, Postgres, OpenFGA) or
// armornet with it. Tests count too, since a test import still drags its module
// into go.sum.
func TestModuleGuard(t *testing.T) {
	const self = "github.com/ArmornetIO/axa/authn"
	out, err := exec.Command("go", "list", "-deps", "-test", "./...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, p := range strings.Fields(string(out)) {
		// Test variants list as "authn_test [authn.test]"; they are the module itself.
		p = strings.Trim(p, "[]")
		p = strings.TrimSuffix(strings.TrimSuffix(p, ".test"), "_test")
		if strings.HasPrefix(p, "github.com/ArmornetIO/") && p != self && !strings.HasPrefix(p, self+"/") {
			t.Errorf("authn depends on %s; it must not import the rest of identity or armornet", p)
		}
	}
}
