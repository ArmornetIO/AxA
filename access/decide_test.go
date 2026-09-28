package access

import (
	"strings"
	"testing"
)

// allReasons must list every constant, forcing a deliberate answer on each new one.
var allReasons = []string{
	ReasonOK,
	ReasonInvalidToken,
	ReasonNotAllowed,
	ReasonWrongAudience,
	ReasonDisabled,
	ReasonSubjectNotRepresentable,
	ReasonInsufficientCredentialScope,
	ReasonConsentRequired,
	ReasonConsentNotDeployed,
	ReasonTierExcluded,
	ReasonQuotaExhausted,
	ReasonNoOrgScope,
	ReasonRelationAbsent,
	ReasonNoPolicyForRoute,
	ReasonGraphUnavailable,
	ReasonConsentUnevaluable,
	ReasonOperatorOverride,
	ReasonNotAdmitted,
}

// Nothing joins the outage allowlist by accident.
func TestOnlyDeclaredReasonsAreOutages(t *testing.T) {
	want := map[string]bool{ReasonGraphUnavailable: true, ReasonConsentUnevaluable: true}
	for _, r := range allReasons {
		isOutage := OutcomeFor(r) == Unavailable
		if isOutage != want[r] {
			t.Errorf("%s: Unavailable=%v, want %v — a dependency failure must be "+
				"declared in the outages allowlist, never inferred", r, isOutage, want[r])
		}
	}
	// Each entry names a dependency, so an operator reading the record knows
	// which one failed. That is the whole reason there is more than one.
	for r := range want {
		if !strings.Contains(r, "unavailable") && !strings.Contains(r, "unevaluable") {
			t.Errorf("%s: an outage reason must name the dependency that failed", r)
		}
	}
}

// The two permit reasons are deliberate: ok, and the consent gate that is not
// deployed. Anything else permitting is a fail-open nobody declared.
func TestOnlyDeclaredReasonsPermit(t *testing.T) {
	permits := map[string]bool{ReasonOK: true, ReasonConsentNotDeployed: true, ReasonOperatorOverride: true}
	for _, r := range allReasons {
		got := OutcomeFor(r)
		switch {
		case permits[r]:
			if got != Permit {
				t.Errorf("%s: want Permit, got %s", r, got)
			}
		case OutcomeFor(r) == Unavailable:
			// covered by TestOnlyDeclaredReasonsAreOutages
		default:
			if got != Refuse {
				t.Errorf("%s: want Refuse, got %s", r, got)
			}
		}
	}
}

// An unclassified reason costs a refusal, never an outage or a grant.
func TestUnknownReasonRefuses(t *testing.T) {
	if got := OutcomeFor("something_nobody_declared"); got != Refuse {
		t.Fatalf("unknown reason: want Refuse, got %s", got)
	}
}

// Allowed is kept only for callers not yet migrated off the boolean; it must
// never disagree with the outcome it shadows.
func TestSettleKeepsAllowedInStepWithOutcome(t *testing.T) {
	for _, r := range allReasons {
		d := Decision{}.settle(r)
		if d.Allowed != (d.Outcome == Permit) {
			t.Errorf("%s: Allowed=%v disagrees with Outcome=%s", r, d.Allowed, d.Outcome)
		}
		if d.Reason != r {
			t.Errorf("%s: reason not recorded, got %q", r, d.Reason)
		}
	}
}
