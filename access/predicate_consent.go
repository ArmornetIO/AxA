package access

import "context"

// ConsentGate answers whether a person has accepted the terms currently in
// force. The host implements it over its own acceptance ledger.
type ConsentGate interface {
	// Deployed reports whether a consent gate is wired in this deployment.
	Deployed() bool
	// Accepted reports whether this subject has accepted what is in force. An
	// error means the ledger could not be read — not that nothing was accepted.
	Accepted(ctx context.Context, s Subject) (bool, error)
}

// consentEvaluator: MACHINES PASS (explicitly, nobody to accept), NOT DEPLOYED
// PASSES (recorded), and an unreadable ledger fails CLOSED. Keep all three.
type consentEvaluator struct{ gate ConsentGate }

// ConsentEvaluator returns the acceptance evaluator over the host's ledger.
func ConsentEvaluator(g ConsentGate) Evaluator { return consentEvaluator{gate: g} }

func (consentEvaluator) Predicate() Predicate { return PredicateConsent }

func (consentEvaluator) Declared(r Rule) bool { return r.Consent }

func (e consentEvaluator) Evaluate(ctx context.Context, req Request) Verdict {
	if e.gate == nil || !e.gate.Deployed() {
		return Permitted(PredicateConsent, ReasonConsentNotDeployed)
	}
	if req.Subject.Kind == KindMachine {
		return Permitted(PredicateConsent, ReasonOK)
	}
	accepted, err := e.gate.Accepted(ctx, req.Subject)
	if err != nil {
		return Refused(PredicateConsent, ReasonConsentUnevaluable)
	}
	if !accepted {
		return Refused(PredicateConsent, ReasonConsentRequired)
	}
	return Permitted(PredicateConsent, ReasonOK)
}
