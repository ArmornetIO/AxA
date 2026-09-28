package access

import (
	"context"
	"testing"
)

// A scopeless route must admit an agent: its credential is Scoped with an empty
// list, so an unconditional Permits("") lookup refuses every AgentIngest route.
func TestAgentPermittedOnScopelessRoute(t *testing.T) {
	v := IdentityEvaluator().Evaluate(context.Background(), Request{
		Rule:       Rule{Declared: true, MachineOnly: true},
		Subject:    Machine("agent:org:uuid", "org"),
		Credential: Credential{Scoped: true},
	})
	if v.Outcome != Permit {
		t.Fatalf("agent on AgentIngest route: got %v %v, want permit", v.Outcome, v.Reason)
	}
}

// A person's restricted token reaches no route that names no scope: a
// vendors:read token must not mint agent credentials.
func TestScopedPersonRefusedOnScopelessRoute(t *testing.T) {
	route := Rule{Declared: true, Relation: "admin"}
	pat := Credential{Scoped: true, Scopes: []string{"vendors:read"}}
	if !IdentityEvaluator().Declared(route) {
		t.Fatal("identity evaluator skipped a scopeless route")
	}
	v := IdentityEvaluator().Evaluate(context.Background(), Request{
		Rule: route, Subject: Person("user", "org"), Credential: pat,
	})
	if v.Reason != ReasonInsufficientCredentialScope {
		t.Fatalf("PAT on scopeless route: got %v %v, want refusal", v.Outcome, v.Reason)
	}
	v = IdentityEvaluator().Evaluate(context.Background(), Request{
		Rule: route, Subject: Person("user", "org"),
	})
	if v.Outcome != Permit {
		t.Fatalf("session on scopeless route: got %v %v, want permit", v.Outcome, v.Reason)
	}
}

// The ceiling still bites where a scope IS named.
func TestAgentRefusedOnScopedRoute(t *testing.T) {
	v := IdentityEvaluator().Evaluate(context.Background(), Request{
		Rule:       Rule{Declared: true, Scope: "dns:read"},
		Subject:    Machine("agent:org:uuid", "org"),
		Credential: Credential{Scoped: true},
	})
	if v.Reason != ReasonInsufficientCredentialScope {
		t.Fatalf("got %v %v", v.Outcome, v.Reason)
	}
}
