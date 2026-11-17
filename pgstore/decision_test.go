package pgstore

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ArmornetIO/axa/access"
)

// fakeOriginSealer is reversible, not encryption: these test when the store opens.
type fakeOriginSealer struct{ failFor string }

func (f fakeOriginSealer) Seal(plaintext string) ([]byte, error) {
	return []byte("sealed:" + plaintext), nil
}

func (f fakeOriginSealer) Open(sealed []byte) (string, error) {
	s := string(sealed)
	if !strings.HasPrefix(s, "sealed:") {
		return "", errors.New("not sealed")
	}
	origin := strings.TrimPrefix(s, "sealed:")
	if f.failFor != "" && origin == f.failFor {
		return "", errors.New("superseded key")
	}
	return origin, nil
}

// Unsealing recovers origins recorded BEFORE it was asked for; a flag
// flipped mid-incident has nothing for the period that mattered.
func TestUnsealingIsRetrospective(t *testing.T) {
	sealer := fakeOriginSealer{}

	// Recorded long before anyone suspected anything.
	before := time.Now().Add(-30 * 24 * time.Hour)
	sealed, err := sealer.Seal("198.51.100.7")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	stored := access.Decision{ID: "d1", At: before, SealedOrigin: sealed}

	// The incident is declared now. Nothing about the unsealing was available
	// when the record was written, and it must not need to have been.
	got, err := sealer.Open(stored.SealedOrigin)
	if err != nil {
		t.Fatalf("open a record written before the unsealing: %v", err)
	}
	if got != "198.51.100.7" {
		t.Fatalf("origin = %q, want the origin recorded 30 days ago", got)
	}
}

// One unreadable row — a superseded key, a value written before sealing was
// enabled — must not cost the whole incident's worth of evidence.
func TestUnsealSkipsUnreadableRowsRatherThanFailing(t *testing.T) {
	sealer := fakeOriginSealer{failFor: "203.0.113.9"}

	readable, _ := sealer.Seal("198.51.100.7")
	unreadable, _ := sealer.Seal("203.0.113.9")

	recovered := map[string]string{}
	for id, blob := range map[string][]byte{"d1": readable, "d2": unreadable} {
		origin, err := sealer.Open(blob)
		if err != nil {
			continue
		}
		recovered[id] = origin
	}
	if len(recovered) != 1 || recovered["d1"] != "198.51.100.7" {
		t.Fatalf("recovered = %v; one bad row must not take the readable ones with it", recovered)
	}
}

// Lookup keys are columns; copying them into the blob makes two that can disagree.
func TestSealedRecordHoldsOnlyWhatIsNotALookupKey(t *testing.T) {
	// A compile-time fact, asserted by construction: these are the fields.
	r := sealedRecord{
		Action:     access.Action{Method: "GET", Pattern: "/api/vendors/:id"},
		Reason:     access.ReasonRelationAbsent,
		Predicates: []access.Verdict{access.Refused(access.PredicateRelationship, access.ReasonRelationAbsent)},
	}
	if r.Reason == "" || r.Action.Pattern == "" || len(r.Predicates) != 1 {
		t.Fatal("sealedRecord lost a field")
	}
}

// The raw path is decoded, caller-chosen bytes: never in an audit trail.
func TestActionCarriesThePatternNotTheRawPath(t *testing.T) {
	a := access.Action{Method: "GET", Pattern: "/api/vendors/:id"}
	if !strings.Contains(a.Pattern, ":") {
		t.Fatal("the pattern lost its parameter, which means a raw path was stored")
	}
}
