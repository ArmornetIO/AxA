package fga

import (
	"testing"

	parser "github.com/openfga/language/pkg/go/transformer"
)

// TestDefaultModelCompiles guards the embedded default DSL: a typo would
// otherwise only surface at boot when writeModel parses ModelData.
func TestDefaultModelCompiles(t *testing.T) {
	dsl := DefaultModel()
	if len(dsl) == 0 {
		t.Fatal("DefaultModel() returned no bytes")
	}
	model, err := parser.TransformDSLToProto(string(dsl))
	if err != nil {
		t.Fatalf("default model DSL does not compile: %v", err)
	}
	types := map[string]bool{}
	for _, td := range model.GetTypeDefinitions() {
		types[td.GetType()] = true
	}
	for _, want := range []string{"user", "platform", "organization"} {
		if !types[want] {
			t.Errorf("default model missing expected type %q", want)
		}
	}
}
