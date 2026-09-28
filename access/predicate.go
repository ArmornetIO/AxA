package access

import "context"

// Predicate names one axis of an authorization decision. The set is closed:
// four conditions, each owning exactly one question.
type Predicate string

const (
	// PredicateIdentity is the credential ceiling — what this credential may do
	// at most, regardless of who holds it.
	PredicateIdentity Predicate = "identity"
	// PredicateConsent is acceptance of current terms.
	PredicateConsent Predicate = "consent"
	// PredicateCommercial is tier and quota: one axis with two sources.
	PredicateCommercial Predicate = "commercial"
	// PredicateRelationship is the authorization graph — the only axis that is
	// a graph query, and so the most expensive one to reach.
	PredicateRelationship Predicate = "relationship"
)

// Verdict is one condition's answer.
type Verdict struct {
	Predicate Predicate `json:"predicate"`
	Outcome   Outcome   `json:"outcome"`
	Reason    string    `json:"reason"`
}

// Permitted takes a reason so a non-OK permit (consent not deployed) stays visible.
func Permitted(p Predicate, reason string) Verdict {
	if reason == "" {
		reason = ReasonOK
	}
	return Verdict{Predicate: p, Outcome: OutcomeFor(reason), Reason: reason}
}

// Refused derives the outcome from the reason: no refusal can claim to be an outage.
func Refused(p Predicate, reason string) Verdict {
	if reason == "" {
		// A predicate that forgets its reason still names a condition rather
		// than emitting an empty one, because no refusal may go out without one.
		reason = ReasonRelationAbsent
	}
	return Verdict{Predicate: p, Outcome: OutcomeFor(reason), Reason: reason}
}

// Action holds the DECLARED pattern, never the raw, attacker-influenced path.
type Action struct {
	Method  string `json:"method"`
	Pattern string `json:"pattern"`
}

// Resource is what the action was attempted against, as the rule resolved it.
type Resource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Rule is the only place a condition is declared; one in a handler chain is a
// defect. Object-id resolution stays with the front door.
type Rule struct {
	// Declared's zero value makes a forgotten lookup deny, not pass empty.
	Declared bool
	// Scope is the credential ceiling; "" declares no ceiling.
	Scope string
	// Tier is the commercial tier required; "" declares no tier requirement.
	Tier string
	// Quota names a metered capability; "" declares no meter.
	Quota string
	// Consent requires acceptance of current terms.
	Consent bool
	// Relation is the relationship required on the resource; "" declares no
	// relationship check, so the graph is never consulted.
	Relation string
	// Operator marks a route only a platform operator may reach.
	Operator bool
	// MachineOnly: no org param to bind a role to, so otherwise any session or
	// API key could post as an agent.
	MachineOnly bool
}

// Evaluator MUST return a verdict, never abort; Refuse (not Unavailable) bad
// input; use vocabulary reasons; and be skippable via Declared.
type Evaluator interface {
	// Predicate is the axis this evaluator owns.
	Predicate() Predicate
	// Declared false: not evaluated, recorded as absent, never as a pass.
	Declared(r Rule) bool
	// Evaluate answers the axis. It always returns a verdict.
	Evaluate(ctx context.Context, req Request) Verdict
}

// Request is one authorization question, fully resolved: who, what, against
// what, and under which declared conditions.
type Request struct {
	Subject  Subject
	Action   Action
	Resource Resource
	Rule     Rule
	// Credential is the caller's credential ceiling — what the credential
	// permits at most, independent of who holds it.
	Credential Credential
	// Operator is resolved by the HOST; never an allowlist here or a relationship.
	Operator bool
	// Origin is the raw request origin. It is used to derive the correlation
	// key and the sealed origin and is NEVER stored as given.
	Origin string
}
