package access

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// recordKeys closes the audit record's shape as a privacy control: personal
// data must have NOWHERE to live (no Message, Details or Extra).
var recordKeys = []string{
	"action",
	"at",
	"correlation_key",
	"id",
	"outcome",
	"predicates",
	"reason",
	"resource",
	"sealed_origin",
	"subject",
}

// TestDecisionRecordShapeIsClosed fails on any new stored Decision field.
func TestDecisionRecordShapeIsClosed(t *testing.T) {
	// Fully populated, so no key is missing merely because it was empty.
	sub := Person("11111111-2222-3333-4444-555555555555", "org-a")
	d := Decision{
		ID:             "d1",
		Subject:        &sub,
		Action:         Action{Method: "GET", Pattern: "/api/vendors/:id"},
		Resource:       Resource{Type: "vendor", ID: "v1"},
		Outcome:        Refuse,
		Reason:         ReasonRelationAbsent,
		At:             time.Now().UTC(),
		Predicates:     []Verdict{Refused(PredicateRelationship, ReasonRelationAbsent)},
		CorrelationKey: "ck",
		SealedOrigin:   []byte("sealed"),

		// The proxy response fields. Present here precisely so the test proves
		// they do NOT reach the record: an assertion is a bearer token.
		Allowed:   false,
		Audience:  "aud",
		Source:    "src",
		Assertion: "eyJ...",
		ExpiresAt: time.Now().UTC(),
	}

	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	keys := make([]string, 0, len(got))
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	want := append([]string(nil), recordKeys...)
	sort.Strings(want)

	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Fatalf("decision record keys changed.\n got: %v\nwant: %v\n\n"+
			"A new key is a deliberate change to this allowlist AND to what the "+
			"record may contain. If it can hold free-form text, it does not belong.",
			keys, want)
	}

	// The assertion is the field that would hurt most. Assert its absence by
	// value as well as by key, in case a tag is ever loosened.
	if strings.Contains(string(raw), "eyJ") {
		t.Fatal("the minted assertion reached the record")
	}
}

// No record key may be a map or a free-form string a caller's details fit in.
func TestNoFreeFormFieldInTheRecord(t *testing.T) {
	for _, banned := range []string{"message", "details", "extra", "note", "error", "context"} {
		for _, k := range recordKeys {
			if k == banned {
				t.Errorf("%q is in the record; personal data must have nowhere to live", k)
			}
		}
	}
}

// The OSS boundary: armornet specifics arrive through host seams; one import
// here would end that silently.
func TestIdentityImportsNothingFromArmornet(t *testing.T) {
	const host = "github.com/ArmornetIO/armornet/"

	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolve identity root: %v", err)
	}

	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// pkg/ is vendored upstream (Dex, OpenFGA); ginauthz is its own
			// module with its own boundary.
			switch d.Name() {
			case "pkg", "ginauthz", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return nil // not this test's business
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if !strings.HasPrefix(p, host) {
				continue
			}
			// Imports WITHIN identity are the module itself.
			if p == host+"identity" || strings.HasPrefix(p, host+"identity/") {
				continue
			}
			rel, _ := filepath.Rel(root, path)
			t.Errorf("%s imports %s — identity must reach the host through a seam, never by importing it", rel, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}
