package access

import "context"

// Credential is what the credential permits AT MOST: an owner's restricted key
// is still restricted.
type Credential struct {
	// Scoped: sessions have no ceiling; a machine's empty list is a ceiling of
	// nothing, refused by any scoped route.
	Scoped bool
	// Scopes is the list. Meaningful only when Scoped.
	Scopes []string
}

// Permits reports whether the credential's ceiling admits scope.
func (c Credential) Permits(scope string) bool {
	if scope == "" {
		// No scope declared, nothing subtracted; without this every AgentIngest
		// route 403'd agents (empty list, lookup of "").
		return true
	}
	if !c.Scoped {
		// No ceiling declared on this credential, so nothing is subtracted.
		return true
	}
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// identityEvaluator's ceiling only SUBTRACTS, so running it first is safe: a
// bug costs a refusal, never a grant.
type identityEvaluator struct{}

// IdentityEvaluator returns the credential-ceiling evaluator. It needs nothing
// from the host: the ceiling travels on the request.
func IdentityEvaluator() Evaluator { return identityEvaluator{} }

func (identityEvaluator) Predicate() Predicate { return PredicateIdentity }

// Declared on every route: the ceiling belongs to the credential, so a route
// that names no scope must still see it, or it would admit any token.
func (identityEvaluator) Declared(Rule) bool { return true }

func (e identityEvaluator) Evaluate(_ context.Context, req Request) Verdict {
	// An operator-only route. The permitting half is the pipeline's
	// short-circuit; this is the refusing half, which is an ordinary condition.
	if req.Rule.Operator && !req.Operator {
		return Refused(PredicateIdentity, ReasonNotAllowed)
	}
	// A machine-only route refuses a person. The refusal is about what kind of
	// caller this is, so it is not representable AS a caller of this route.
	if req.Rule.MachineOnly && req.Subject.Kind != KindMachine {
		return Refused(PredicateIdentity, ReasonSubjectNotRepresentable)
	}
	// A person's token holds only the scopes it names, and a route that names
	// none is in none of them. Agents are exempt: their routes are scopeless
	// by design and their credential carries an empty list.
	if req.Rule.Scope == "" && req.Credential.Scoped && req.Subject.Kind == KindPerson {
		return Refused(PredicateIdentity, ReasonInsufficientCredentialScope)
	}
	// Not representability: an invitee with no users row must still reach
	// identity-only routes. The relationship axis checks the subject.
	if !req.Credential.Permits(req.Rule.Scope) {
		return Refused(PredicateIdentity, ReasonInsufficientCredentialScope)
	}
	return Permitted(PredicateIdentity, ReasonOK)
}
