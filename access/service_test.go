package access_test

import (
	"context"
	"errors"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/ArmornetIO/axa/access"
	"github.com/ArmornetIO/axa/authz"
)

var _ access.RelationChecker = (*authz.Checker)(nil)

type stubChecker struct {
	err       error
	gotGroups []string
	calls     int
}

func (s *stubChecker) Check(_ context.Context, _ authz.Subject, groups []string, _, _, _ string) error {
	s.calls++
	s.gotGroups = groups
	return s.err
}

func TestGrapherMapsTheCheckerContract(t *testing.T) {
	transport := errors.New("fga down")
	for name, tc := range map[string]struct {
		err  error
		want error
	}{
		"allow":          {err: nil, want: nil},
		"deny is absent": {err: authz.ErrForbidden, want: access.ErrRelationAbsent},
		"transport":      {err: transport, want: transport},
		"backend":        {err: authz.ErrCheckBackend, want: authz.ErrCheckBackend},
	} {
		t.Run(name, func(t *testing.T) {
			g := access.CheckerGraph(&stubChecker{err: tc.err}, nil)
			err := g.Check(context.Background(), access.Person("u1", "org-1"), "viewer", "vendor", "v1")
			if !errors.Is(err, tc.want) || (tc.want == nil) != (err == nil) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestGrapherNilCheckerFailsClosedAsOutage(t *testing.T) {
	err := access.CheckerGraph(nil, nil).Check(context.Background(), access.Person("u1", "org-1"), "viewer", "vendor", "v1")
	if err == nil || errors.Is(err, access.ErrRelationAbsent) {
		t.Fatalf("err = %v, want a non-deny failure", err)
	}
}

func TestGrapherPassesGroupsFromContext(t *testing.T) {
	c := &stubChecker{}
	groups := func(context.Context) []string { return []string{"org:1:admin"} }
	_ = access.CheckerGraph(c, groups).Check(context.Background(), access.Person("u1", "org-1"), "viewer", "vendor", "v1")
	if len(c.gotGroups) != 1 || c.gotGroups[0] != "org:1:admin" {
		t.Fatalf("groups = %v", c.gotGroups)
	}
}

func relationRequest() access.Request {
	return access.Request{
		Subject:  access.Person("u1", "org-1"),
		Action:   access.Action{Method: "GET", Pattern: "/api/vendors/:id"},
		Resource: access.Resource{Type: "vendor", ID: "v1"},
		Rule:     access.Rule{Declared: true, Relation: "viewer"},
	}
}

func TestServiceZeroConfigFailsClosed(t *testing.T) {
	d := access.NewService(access.ServiceConfig{}).Authorize(context.Background(), relationRequest())
	if d.Allowed || d.Reason != access.ReasonGraphUnavailable {
		t.Fatalf("decision = %s/%s, want refused as graph unavailable", d.Outcome, d.Reason)
	}
}

func TestServiceDecidesThroughTheGraph(t *testing.T) {
	c := &stubChecker{}
	d := access.NewService(access.ServiceConfig{Graph: access.CheckerGraph(c, nil)}).Authorize(context.Background(), relationRequest())
	if d.Outcome != access.Permit || c.calls != 1 {
		t.Fatalf("decision = %s/%s, graph calls = %d", d.Outcome, d.Reason, c.calls)
	}
}

// A decision must be findable from its trace and vice versa, without opening a
// span of its own.
func TestServiceStampsDecisionOnCallerSpan(t *testing.T) {
	spans := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))
	ctx, span := tp.Tracer("test").Start(context.Background(), "request")

	d := access.NewService(access.ServiceConfig{Graph: access.CheckerGraph(&stubChecker{}, nil)}).Authorize(ctx, relationRequest())
	span.End()

	ended := spans.Ended()
	if len(ended) != 1 {
		t.Fatalf("recorded %d spans, want only the caller's", len(ended))
	}
	attrs := map[attribute.Key]string{}
	for _, kv := range ended[0].Attributes() {
		attrs[kv.Key] = kv.Value.AsString()
	}
	if attrs["authz.decision.id"] != d.ID || d.ID == "" {
		t.Errorf("authz.decision.id = %q, decision id = %q", attrs["authz.decision.id"], d.ID)
	}
	if attrs["authz.outcome"] != string(access.Permit) {
		t.Errorf("authz.outcome = %q", attrs["authz.outcome"])
	}
	if attrs["authz.reason"] != d.Reason {
		t.Errorf("authz.reason = %q, want %q", attrs["authz.reason"], d.Reason)
	}
}
