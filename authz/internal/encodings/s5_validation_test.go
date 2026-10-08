package encodings

import (
	"context"
	"testing"

	"github.com/openfga/language/pkg/go/transformer"
	"github.com/openfga/openfga/pkg/typesystem"
)

const s5Header = "model\n  schema 1.1\ntype user\ntype organization\n  relations\n    define member: [user]\n"

// TestS5Validation: can the language module alone validate?
// typesystem.NewAndValidate is the reference.
func TestS5Validation(t *testing.T) {
	ctx := context.Background()
	for name, dsl := range map[string]string{"s1": s1Model, "s2": s2Model, "s3": s3Model} {
		m, err := transformer.TransformDSLToProto(dsl)
		if err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}
		if _, err := typesystem.NewAndValidate(ctx, m); err != nil {
			t.Errorf("%s: the spike models must be valid: %v", name, err)
		}
	}

	negatives := map[string]string{
		"undefined relation":            "type document\n  relations\n    define read: viewer\n",
		"undefined type in restriction": "type document\n  relations\n    define viewer: [group]\n",
		"undefined tupleset":            "type document\n  relations\n    define read: member from org\n",
		"tupleset over a computed":      "type document\n  relations\n    define org: [organization]\n    define parent: org\n    define read: member from parent\n",
		"cycle with no base":            "type document\n  relations\n    define a: b\n    define b: a\n",
		"undefined condition":           "type document\n  relations\n    define viewer: [user with missing]\n",
		"userset on a missing relation": "type document\n  relations\n    define viewer: [organization#admin]\n",
	}
	var missedByLanguage int
	for name, body := range negatives {
		m, err := transformer.TransformDSLToProto(s5Header + body)
		if err == nil {
			missedByLanguage++
		}
		if m == nil {
			continue // the parser refused it; nothing to hand to typesystem
		}
		if _, err := typesystem.NewAndValidate(ctx, m); err == nil {
			t.Errorf("%s: typesystem accepted it", name)
		}
	}
	// Kill criterion: language misses what typesystem catches, so the core keeps
	// typesystem. Recorded so an upgrade that closes the gap is noticed.
	if missedByLanguage == 0 {
		t.Error("the language module now rejects every negative: revisit keeping pkg/typesystem in the core")
	}
	t.Logf("the language module parsed %d of %d invalid models without complaint", missedByLanguage, len(negatives))
}
