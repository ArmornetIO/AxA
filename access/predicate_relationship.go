package access

import (
	"context"
	"errors"
)

// ErrRelationAbsent is what a Grapher returns for a clean deny: the graph was
// consulted and the caller does not hold the relation.
var ErrRelationAbsent = errors.New("access: relation absent")

// Grapher's errors are the contract: nil holds, ErrRelationAbsent and
// ErrNotRepresentable refuse (never outages), anything else is transport.
type Grapher interface {
	Check(ctx context.Context, s Subject, relation, objectType, objectID string) error
}

// relationshipEvaluator is the only network call, so it runs last.
type relationshipEvaluator struct{ graph Grapher }

// RelationshipEvaluator returns the graph evaluator.
func RelationshipEvaluator(g Grapher) Evaluator { return relationshipEvaluator{graph: g} }

func (relationshipEvaluator) Predicate() Predicate { return PredicateRelationship }

func (relationshipEvaluator) Declared(r Rule) bool { return r.Relation != "" }

func (e relationshipEvaluator) Evaluate(ctx context.Context, req Request) Verdict {
	if err := req.Subject.Valid(); err != nil {
		return Refused(PredicateRelationship, ReasonSubjectNotRepresentable)
	}
	// No org is the one failure a client can act on: its own reason, not a role.
	if req.Resource.ID == "" {
		return Refused(PredicateRelationship, ReasonNoOrgScope)
	}
	if e.graph == nil {
		// Nothing to ask. Fail closed as an outage, not a deny: a deployment
		// with no graph wired has not decided that this caller lacks a role.
		return Refused(PredicateRelationship, ReasonGraphUnavailable)
	}
	switch err := e.graph.Check(ctx, req.Subject, req.Rule.Relation, req.Resource.Type, req.Resource.ID); {
	case err == nil:
		return Permitted(PredicateRelationship, ReasonOK)
	case errors.Is(err, ErrRelationAbsent):
		return Refused(PredicateRelationship, ReasonRelationAbsent)
	case errors.Is(err, ErrNotRepresentable):
		return Refused(PredicateRelationship, ReasonSubjectNotRepresentable)
	default:
		return Refused(PredicateRelationship, ReasonGraphUnavailable)
	}
}
