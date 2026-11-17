package access

import (
	"context"
	"errors"

	"github.com/ArmornetIO/axa/authz"
)

// RelationChecker is the one checker method the graph axis needs;
// *authz.Checker satisfies it, and so does a host's wrapper around one.
type RelationChecker interface {
	Check(ctx context.Context, sub authz.Subject, groups []string, relation, objectType, objectID string) error
}

var errGraphNotWired = errors.New("access: authorization graph not wired")

// CheckerGraph maps ErrForbidden to ErrRelationAbsent and passes the rest as
// transport; a deny sent down the failure path once paged as an outage.
func CheckerGraph(c RelationChecker, groups func(context.Context) []string) Grapher {
	return checkerGraph{checker: c, groups: groups}
}

type checkerGraph struct {
	checker RelationChecker
	groups  func(context.Context) []string
}

func (g checkerGraph) Check(ctx context.Context, sub Subject, relation, objectType, objectID string) error {
	if g.checker == nil {
		// A dependency that is absent, not a caller who lacks a role: fail
		// closed as a transport failure rather than denying.
		return errGraphNotWired
	}
	var groups []string
	if g.groups != nil {
		groups = g.groups(ctx)
	}
	switch err := g.checker.Check(ctx, sub.GraphSubject(), groups, relation, objectType, objectID); {
	case err == nil:
		return nil
	case errors.Is(err, authz.ErrForbidden):
		return ErrRelationAbsent
	default:
		return err
	}
}
