package model

import (
	"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

// An Example without Output never runs, so pins nothing. Parsed, not
// built, so tagged examples count too; every builder package needs one.
func TestExamplesHaveOutput(t *testing.T) {
	for _, dir := range []string{"model", "rbac", "abac", "cbac", "mac", "authztest"} {
		paths, err := filepath.Glob(filepath.Join("..", dir, "*_test.go"))
		if err != nil {
			t.Fatal(err)
		}
		fset := token.NewFileSet()
		var files []*ast.File
		for _, p := range paths {
			src, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			f, err := parser.ParseFile(fset, p, src, parser.ParseComments)
			if err != nil {
				t.Fatalf("%s: %v", p, err)
			}
			files = append(files, f)
		}
		examples := doc.Examples(files...)
		if len(examples) == 0 {
			t.Errorf("%s has no Example; every builder package opens with one", dir)
		}
		for _, ex := range examples {
			if ex.Output == "" && !ex.EmptyOutput {
				t.Errorf("%s: Example%s has no Output block, so it is compiled but never run", dir, ex.Name)
			}
		}
	}
}
