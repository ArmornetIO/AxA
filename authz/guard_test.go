package authz_test

import (
	"encoding/json"
	"io"
	"os/exec"
	"strings"
	"testing"
)

const self = "github.com/ArmornetIO/axa/authz"

// TestModuleGuard keeps identity and armornet out, tests included: a test import
// still drags its module into go.sum.
func TestModuleGuard(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-test", "./...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, p := range strings.Fields(string(out)) {
		// Test variants list as "authz_test [authz.test]"; they are the module itself.
		p = strings.Trim(p, "[]")
		p = strings.TrimSuffix(strings.TrimSuffix(p, ".test"), "_test")
		if strings.HasPrefix(p, "github.com/ArmornetIO/") && p != self && !strings.HasPrefix(p, self+"/") {
			t.Errorf("authz depends on %s; it must not import the rest of identity or armornet", p)
		}
	}
}

var (
	builders = map[string]bool{"model": true, "rbac": true, "abac": true, "cbac": true, "mac": true}
	patterns = map[string]bool{"rbac": true, "abac": true, "cbac": true, "mac": true}
)

// importAllowed is the builders' dependency rule; pkg is
// module-relative ("model", "mac"), test marks test-only imports.
func importAllowed(pkg, imp string, test bool) bool {
	first, _, _ := strings.Cut(imp, "/")
	switch {
	case !strings.Contains(first, "."):
		return true // standard library
	case imp == self || strings.HasPrefix(imp, self+"/"):
		rel := strings.TrimPrefix(strings.TrimPrefix(imp, self), "/")
		if !patterns[pkg] {
			return true
		}
		// Patterns build on model alone; only tests compose them (abac gated by
		// an rbac role).
		return rel == "model" || test
	case strings.HasPrefix(imp, "github.com/openfga/openfga/"):
		// The server module drags in cel-go, grpc and otel: model may validate
		// with its type system, and the rest is the test harness's alone.
		return pkg == "model" && imp == "github.com/openfga/openfga/pkg/typesystem"
	case strings.HasPrefix(imp, "github.com/openfga/"), strings.HasPrefix(imp, "google.golang.org/protobuf/"):
		return true
	}
	return false
}

func TestImportAllowedRule(t *testing.T) {
	for _, tc := range []struct {
		pkg, imp string
		test     bool
		want     bool
	}{
		{"model", "fmt", false, true},
		{"model", "github.com/openfga/api/proto/openfga/v1", false, true},
		{"model", "github.com/openfga/language/pkg/go/transformer", false, true},
		{"model", "google.golang.org/protobuf/proto", false, true},
		{"model", "github.com/openfga/openfga/pkg/typesystem", false, true},
		{"model", "github.com/openfga/openfga/pkg/server", false, false},
		{"mac", "github.com/openfga/openfga/pkg/typesystem", false, false},
		{"mac", self + "/model", false, true},
		{"mac", self + "/rbac", false, false},
		{"mac", self + "/authztest", false, false},
		{"mac", self + "/authztest", true, true},
		{"mac", self + "/mac", true, true},
		{"abac", self + "/rbac", true, true},
		{"abac", self + "/rbac", false, false},
		{"model", "github.com/stretchr/testify/require", true, false},
		{"model", "github.com/ArmornetIO/axa/access", false, false},
	} {
		if got := importAllowed(tc.pkg, tc.imp, tc.test); got != tc.want {
			t.Errorf("importAllowed(%q, %q, test=%v) = %v, want %v", tc.pkg, tc.imp, tc.test, got, tc.want)
		}
	}
}

type listedPackage struct {
	ImportPath, Name                   string
	Imports, TestImports, XTestImports []string
}

func listPackages(t *testing.T) []listedPackage {
	t.Helper()
	out, err := exec.Command("go", "list", "-json", "./...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	var pkgs []listedPackage
	for dec := json.NewDecoder(strings.NewReader(string(out))); ; {
		var p listedPackage
		if err := dec.Decode(&p); err == io.EOF {
			return pkgs
		} else if err != nil {
			t.Fatalf("decode go list: %v", err)
		}
		pkgs = append(pkgs, p)
	}
}

// TestBuilderImports also keeps all but the harness off the network: builders
// produce values, never a client.
func TestBuilderImports(t *testing.T) {
	for _, p := range listPackages(t) {
		rel := strings.TrimPrefix(strings.TrimPrefix(p.ImportPath, self), "/")
		if rel != "authztest" && !strings.HasPrefix(rel, "authztest/") {
			for _, imp := range p.Imports {
				if (imp == "net" || imp == "net/http") && rel != "" {
					t.Errorf("%s imports %s; only the test harness may touch the network", p.ImportPath, imp)
				}
			}
		}
		if !builders[rel] {
			continue
		}
		for _, imp := range p.Imports {
			if !importAllowed(rel, imp, false) {
				t.Errorf("%s imports %s", p.ImportPath, imp)
			}
		}
		for _, imp := range append(p.TestImports, p.XTestImports...) {
			if !importAllowed(rel, imp, true) {
				t.Errorf("%s's tests import %s", p.ImportPath, imp)
			}
		}
	}
}
