// Package encodings pins the OpenFGA behaviour builders rely on:
// the reference their output must match, and the gate for an OpenFGA upgrade.
package encodings

import (
	_ "embed"
	"fmt"
	"strings"
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"

	"github.com/ArmornetIO/identity/authz/internal/fgatest"
)

//go:embed testdata/s1.fga
var s1Model string

var (
	levels       = []string{"public", "internal", "confidential", "restricted"}
	compartments = []string{"finance", "legal"}
)

// label is a MAC label: level is an index into levels (-1 is no label at all),
// comps a bit per compartment.
type label struct {
	level int
	comps uint8
}

var none = label{level: -1}

// dominates is the oracle: read is dominates(clearance, classification), write
// is dominates(classification, clearance), both refused when either is absent.
func dominates(a, b label) bool {
	if a.level < 0 || b.level < 0 {
		return false
	}
	return a.level >= b.level && a.comps&b.comps == b.comps
}

func (l label) String() string {
	if l.level < 0 {
		return "none"
	}
	s := levels[l.level]
	for i, c := range compartments {
		if l.comps&(1<<i) != 0 {
			s += "+" + c
		}
	}
	return s
}

// allLabels is every label, none included: 4 levels × 4 compartment sets + 1.
func allLabels() []label {
	ls := []label{none}
	for l := range levels {
		for c := range uint8(1 << len(compartments)) {
			ls = append(ls, label{l, c})
		}
	}
	return ls
}

func key(object, relation, user string) *openfgav1.TupleKey {
	return &openfgav1.TupleKey{Object: object, Relation: relation, User: user}
}

// clear writes subject's clearance under org: its level (the hierarchy grants
// the ones below) and each compartment.
func clear(org, subject string, l label) []*openfgav1.TupleKey {
	if l.level < 0 {
		return nil
	}
	keys := []*openfgav1.TupleKey{key(org, "clearance_"+levels[l.level], subject)}
	for i, c := range compartments {
		if l.comps&(1<<i) != 0 {
			keys = append(keys, key(org, "clearance_"+c, subject))
		}
	}
	return keys
}

// classify writes doc's markers, each pointing at org.
func classify(doc, org string, l label) []*openfgav1.TupleKey {
	if l.level < 0 {
		return nil
	}
	keys := []*openfgav1.TupleKey{key(doc, "level_"+levels[l.level], org)}
	for i, c := range compartments {
		if l.comps&(1<<i) != 0 {
			keys = append(keys, key(doc, "compartment_"+c, org))
		}
	}
	return keys
}

const acme, beta = "organization:acme", "organization:beta"

func subjectID(holder string, i int) string { return fmt.Sprintf("%s:c%d", holder, i) }
func docID(j int) string                    { return fmt.Sprintf("document:d%d", j) }

// baseline writes one document per classification, each in acme and readable
// and writable by every grant, and one subject per clearance and holder type.
func baseline(holders []string) []*openfgav1.TupleKey {
	var keys []*openfgav1.TupleKey
	for j, cls := range allLabels() {
		d := docID(j)
		keys = append(keys, key(d, "org", acme))
		for _, h := range holders {
			keys = append(keys, key(d, "viewer", h+":*"), key(d, "editor", h+":*"))
		}
		keys = append(keys, classify(d, acme, cls)...)
	}
	for _, h := range holders {
		for i, clr := range allLabels() {
			keys = append(keys, clear(acme, subjectID(h, i), clr)...)
		}
	}
	return keys
}

// allows checks relation on doc for subject; an evaluation error fails t, since
// MAC has no conditions and must never error.
func allows(t *testing.T, st *fgatest.Store, doc, relation, subject string) bool {
	t.Helper()
	ok, err := st.Check(&openfgav1.CheckRequest{TupleKey: &openfgav1.CheckRequestTupleKey{
		Object: doc, Relation: relation, User: subject,
	}})
	if err != nil {
		t.Fatalf("check %s#%s@%s: %v", doc, relation, subject, err)
	}
	return ok
}

// want is the expected answer for one row.
type want func(clr, cls label, relation string) bool

func oracle(clr, cls label, relation string) bool {
	if relation == "read" {
		return dominates(clr, cls)
	}
	return dominates(cls, clr)
}

// table runs every clearance × classification × read/write per holder. exact
// demands the oracle; otherwise only an unbounded Permit fails (markers tighten).
func table(t *testing.T, st *fgatest.Store, holders []string, bound want, exact bool) {
	t.Helper()
	var bad []string
	for _, h := range holders {
		for i, clr := range allLabels() {
			for j, cls := range allLabels() {
				for _, rel := range []string{"read", "write"} {
					got, w := allows(t, st, docID(j), rel, subjectID(h, i)), bound(clr, cls, rel)
					if got != w && (exact || got) {
						bad = append(bad, fmt.Sprintf("%s cleared %s, %s on %s: got %v, want %v", h, clr, rel, cls, got, w))
					}
				}
			}
		}
	}
	if len(bad) > 0 {
		t.Errorf("%d rows differ:\n%s", len(bad), strings.Join(bad[:min(len(bad), 20)], "\n"))
	}
}

var holders = []string{"user", "agent"}

func TestS1Oracle(t *testing.T) {
	st := fgatest.Start(t).Load(t, s1Model)
	st.MustWrite(t, baseline(holders)...)
	table(t, st, holders, oracle, true)
}

// Foreign-org markers (all subjects cleared there) must never turn a read Permit;
// a write only where they are the recorded ceiling.
func TestS1Attacker(t *testing.T) {
	srv := fgatest.Start(t)
	full := label{len(levels) - 1, 1<<len(compartments) - 1}
	type variant struct {
		name    string
		levels  []int // level markers pointing at beta
		foreign uint8 // compartment markers pointing at beta
	}
	var variants []variant
	for l := range levels {
		variants = append(variants, variant{name: "level_" + levels[l], levels: []int{l}})
	}
	for i, c := range compartments {
		variants = append(variants, variant{name: "compartment_" + c, foreign: 1 << i})
	}
	variants = append(variants, variant{name: "all", levels: []int{0, 1, 2, 3}, foreign: 1<<len(compartments) - 1})

	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			st := srv.Load(t, s1Model)
			keys := baseline(holders)
			for _, h := range holders {
				for i := range allLabels() {
					keys = append(keys, clear(beta, subjectID(h, i), full)...)
				}
				keys = append(keys, clear(beta, h+":outsider", full)...) // cleared only under beta
			}
			for j, cls := range allLabels() {
				if cls.level < 0 {
					continue // attacker rows are on classified objects; unclassified ones are the E12 level ceiling
				}
				for _, l := range v.levels {
					keys = append(keys, key(docID(j), "level_"+levels[l], beta))
				}
				for i, c := range compartments {
					if v.foreign&(1<<i) != 0 {
						keys = append(keys, key(docID(j), "compartment_"+c, beta))
					}
				}
			}
			st.MustWrite(t, keys...)

			ceiling := func(clr, cls label, rel string) bool {
				if rel == "write" && cls.level >= 0 {
					cls.comps |= v.foreign
				}
				return oracle(clr, cls, rel)
			}
			table(t, st, holders, ceiling, false)
			for _, h := range holders {
				for j := range allLabels() {
					for _, rel := range []string{"read", "write"} {
						if allows(t, st, docID(j), rel, h+":outsider") {
							t.Errorf("%s cleared only under beta: %s on d%d permitted", h, rel, j)
						}
					}
				}
			}
		})
	}
}

// TestS1Ceilings pins the two E12 cases exactly as recorded, so a change in
// either direction fails.
func TestS1Ceilings(t *testing.T) {
	srv := fgatest.Start(t)

	t.Run("foreign level marker on an unclassified object reads", func(t *testing.T) {
		st := srv.Load(t, s1Model)
		st.MustWrite(t,
			key("document:u", "org", acme), key("document:u", "viewer", "user:*"),
			key("document:u", "level_public", beta), // the only marker, and it is foreign
			key(acme, "clearance_public", "user:ana"), key(beta, "clearance_public", "user:ana"),
		)
		if !allows(t, st, "document:u", "read", "user:ana") {
			t.Error("the recorded ceiling no longer holds: update E12 and R7")
		}
	})

	t.Run("foreign compartment marker lifts a write block", func(t *testing.T) {
		st := srv.Load(t, s1Model)
		st.MustWrite(t,
			key("document:c", "org", acme), key("document:c", "editor", "user:*"),
			key("document:c", "level_confidential", acme),
			key("document:c", "compartment_finance", beta), // foreign: the object is not finance
			key(acme, "clearance_confidential", "user:ana"), key(acme, "clearance_finance", "user:ana"),
			key(beta, "clearance_finance", "user:ana"),
		)
		if !allows(t, st, "document:c", "write", "user:ana") {
			t.Error("the recorded ceiling no longer holds: update E12 and R7")
		}
		if dominates(label{2, 0}, label{2, 1}) {
			t.Fatal("oracle: a finance writer must not write into a plain confidential object")
		}
	})
}

// A third subject type is refused under MAC until made a holder via the owner's
// clearance relations alone, then follows the oracle.
func TestS1Device(t *testing.T) {
	withDevice := strings.Replace(s1Model, "type organization", "type device\n\ntype organization", 1)
	withDevice = strings.ReplaceAll(withDevice, "[user:*, agent:*]", "[user:*, agent:*, device:*]")
	asHolder := strings.ReplaceAll(withDevice, "[user, agent]", "[user, agent, device]")
	if strings.Count(withDevice, "\n") != strings.Count(asHolder, "\n") ||
		strings.Replace(asHolder, "[user, agent, device]", "", -1) != strings.Replace(withDevice, "[user, agent]", "", -1) {
		t.Fatal("making device a holder must change only the owner's clearance type restrictions")
	}

	st := fgatest.Start(t).Load(t, withDevice)
	keys := baseline(holders)
	for j := range allLabels() {
		keys = append(keys, key(docID(j), "viewer", "device:*"), key(docID(j), "editor", "device:*"))
	}
	st.MustWrite(t, keys...) // device holds both roles and, not being a holder, no clearance
	for j := range allLabels() {
		for _, rel := range []string{"read", "write"} {
			for i := range allLabels() {
				if allows(t, st, docID(j), rel, subjectID("device", i)) {
					t.Fatalf("non-holder device: %s on d%d permitted", rel, j)
				}
			}
		}
	}

	st.Reload(t, asHolder) // no tuple written or deleted
	table(t, st, holders, oracle, true)
	var clearances []*openfgav1.TupleKey
	for i, clr := range allLabels() {
		clearances = append(clearances, clear(acme, subjectID("device", i), clr)...)
	}
	st.MustWrite(t, clearances...) // the new holder's own clearances, nothing else
	table(t, st, []string{"device"}, oracle, true)
}
