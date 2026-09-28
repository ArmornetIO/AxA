package access

import (
	"errors"
	"testing"
)

// The constraint the whole machine-identity story turns on: the graph engine
// parses on ':', so an id carrying one is a malformed check, not a deny.
func TestSubjectIDWithColonIsRejected(t *testing.T) {
	// The agent's natural identifier, which is exactly what used to be handed
	// to the graph and exactly why the check surfaced as an outage.
	s := Subject{Kind: KindMachine, ID: "agent:org-a:1f2e3d4c", OrgID: "org-a"}
	if err := s.Valid(); !errors.Is(err, ErrNotRepresentable) {
		t.Fatalf("id containing ':' must be rejected, got %v", err)
	}
	if _, err := s.GraphSubject().Graph(); !errors.Is(err, ErrNotRepresentable) {
		t.Fatalf("Graph must refuse an id containing ':', got %v", err)
	}
}

func TestSubjectValidity(t *testing.T) {
	cases := []struct {
		name string
		s    Subject
		ok   bool
	}{
		{"person", Person("1f2e3d4c", "org-a"), true},
		{"machine", Machine("1f2e3d4c", "org-a"), true},
		{"machine without org is still representable", Machine("1f2e3d4c", ""), true},
		{"no kind", Subject{ID: "1f2e3d4c"}, false},
		{"unknown kind", Subject{Kind: "robot", ID: "1f2e3d4c"}, false},
		{"empty id", Person("", "org-a"), false},
		{"colon in id", Person("a:b", "org-a"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s.Valid() == nil; got != tc.ok {
				t.Fatalf("Valid()==nil: got %v want %v", got, tc.ok)
			}
		})
	}
}

// The graph strings are the model's vocabulary. If these change, the .fga model
// must change with them, so pin them.
func TestGraphStringsMatchTheModel(t *testing.T) {
	if got, _ := Person("abc", "o").GraphSubject().Graph(); got != "user:abc" {
		t.Errorf("person: got %q", got)
	}
	if got, _ := Machine("abc", "o").GraphSubject().Graph(); got != "agent:abc" {
		t.Errorf("machine: got %q", got)
	}
}

// An absent subject and an unusable one are different answers: one is
// unauthenticated, the other is refused as not representable.
func TestEmptyIsNotTheSameAsInvalid(t *testing.T) {
	if !(Subject{}).Empty() {
		t.Error("zero subject should be Empty")
	}
	if (Subject{Kind: "robot", ID: "x"}).Empty() {
		t.Error("a subject with a kind is not Empty, only invalid")
	}
}
