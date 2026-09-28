package access

import (
	"context"
	"errors"
	"testing"
)

// ---- doubles ---------------------------------------------------------------

type stubGate struct {
	deployed bool
	accepted bool
	err      error
}

func (s stubGate) Deployed() bool { return s.deployed }
func (s stubGate) Accepted(context.Context, Subject) (bool, error) {
	return s.accepted, s.err
}

type stubTiers struct {
	includes bool
	err      error
}

func (s stubTiers) Includes(context.Context, Subject, string) (string, error) {
	if s.includes {
		return "", s.err
	}
	return ReasonTierExcluded, s.err
}

type stubMeter struct {
	spent bool
	err   error
}

func (s stubMeter) Exhausted(context.Context, Subject, string) (bool, error) {
	return s.spent, s.err
}

type stubGraph struct {
	err    error
	called *int
}

func (s stubGraph) Check(context.Context, Subject, string, string, string) error {
	if s.called != nil {
		*s.called++
	}
	return s.err
}

type countingSink struct {
	emitted []Decision
}

func (c *countingSink) Emit(d Decision) { c.emitted = append(c.emitted, d) }
func (c *countingSink) Dropped() uint64 { return 0 }

// person is a representable caller acting in an org.
func person() Subject { return Person("11111111-2222-3333-4444-555555555555", "org-a") }

// fullRule declares every axis, so every evaluator runs unless one refuses.
func fullRule() Rule {
	return Rule{
		Declared: true,
		Scope:    "vendors:read",
		Tier:     "starter",
		Quota:    "scans",
		Consent:  true,
		Relation: "viewer",
	}
}

func request(r Rule) Request {
	return Request{
		Subject:    person(),
		Action:     Action{Method: "GET", Pattern: "/api/vendors/:id"},
		Resource:   Resource{Type: "vendor", ID: "v1"},
		Rule:       r,
		Credential: Credential{Scoped: true, Scopes: []string{"vendors:read"}},
	}
}

// allPermitting is a pipeline whose every axis says yes.
func allPermitting(sink Sink) *Pipeline {
	return &Pipeline{
		Evaluators: StandardEvaluators(
			stubGate{deployed: true, accepted: true},
			stubTiers{includes: true},
			stubMeter{},
			stubGraph{},
		),
		Sink: sink,
	}
}

// ---- every refusal names a condition ----------------------------------------

// A reasonless refusal leaves the client and the auditor nothing to act on.
func TestNoRefusalHasAnEmptyReason(t *testing.T) {
	cases := []struct {
		name string
		p    *Pipeline
		req  Request
		want string
	}{
		{
			name: "undeclared route",
			p:    allPermitting(nil),
			req:  request(Rule{}), // Declared false
			want: ReasonNoPolicyForRoute,
		},
		{
			name: "credential ceiling",
			p:    allPermitting(nil),
			req: func() Request {
				r := request(fullRule())
				r.Credential = Credential{Scoped: true, Scopes: []string{"vendors:write"}}
				return r
			}(),
			want: ReasonInsufficientCredentialScope,
		},
		{
			name: "consent not accepted",
			p: &Pipeline{Evaluators: StandardEvaluators(
				stubGate{deployed: true, accepted: false}, stubTiers{includes: true}, stubMeter{}, stubGraph{},
			)},
			req:  request(fullRule()),
			want: ReasonConsentRequired,
		},
		{
			name: "consent ledger unreadable",
			p: &Pipeline{Evaluators: StandardEvaluators(
				stubGate{deployed: true, err: errors.New("db down")}, stubTiers{includes: true}, stubMeter{}, stubGraph{},
			)},
			req:  request(fullRule()),
			want: ReasonConsentUnevaluable,
		},
		{
			name: "tier excluded",
			p: &Pipeline{Evaluators: StandardEvaluators(
				stubGate{deployed: true, accepted: true}, stubTiers{includes: false}, stubMeter{}, stubGraph{},
			)},
			req:  request(fullRule()),
			want: ReasonTierExcluded,
		},
		{
			name: "quota exhausted",
			p: &Pipeline{Evaluators: StandardEvaluators(
				stubGate{deployed: true, accepted: true}, stubTiers{includes: true}, stubMeter{spent: true}, stubGraph{},
			)},
			req:  request(fullRule()),
			want: ReasonQuotaExhausted,
		},
		{
			name: "relation absent",
			p: &Pipeline{Evaluators: StandardEvaluators(
				stubGate{deployed: true, accepted: true}, stubTiers{includes: true}, stubMeter{},
				stubGraph{err: ErrRelationAbsent},
			)},
			req:  request(fullRule()),
			want: ReasonRelationAbsent,
		},
		{
			name: "graph transport failure",
			p: &Pipeline{Evaluators: StandardEvaluators(
				stubGate{deployed: true, accepted: true}, stubTiers{includes: true}, stubMeter{},
				stubGraph{err: errors.New("connection refused")},
			)},
			req:  request(fullRule()),
			want: ReasonGraphUnavailable,
		},
		{
			name: "unrepresentable subject",
			p:    allPermitting(nil),
			req: func() Request {
				r := request(fullRule())
				// The agent's natural identifier, which the graph cannot parse.
				r.Subject = Subject{Kind: KindMachine, ID: "agent:org-a:uuid"}
				return r
			}(),
			want: ReasonSubjectNotRepresentable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := tc.p.Authorize(context.Background(), tc.req)
			if d.Outcome == Permit {
				t.Fatalf("expected a refusal, got permit")
			}
			if d.Reason == "" {
				t.Fatal("refusal with no reason")
			}
			if d.Reason != tc.want {
				t.Fatalf("reason = %q, want %q", d.Reason, tc.want)
			}
		})
	}
}

// The six distinct refusal conditions must name six distinct codes. Collapsing
// any two of them is how "you are refused" stops being actionable.
func TestRefusalConditionsAreDistinguishable(t *testing.T) {
	seen := map[string]string{}
	add := func(cond, reason string) {
		if prev, dup := seen[reason]; dup {
			t.Errorf("%s and %s share reason %q", prev, cond, reason)
		}
		seen[reason] = cond
	}
	add("relationship", ReasonRelationAbsent)
	add("consent", ReasonConsentRequired)
	add("tier", ReasonTierExcluded)
	add("quota", ReasonQuotaExhausted)
	add("credential ceiling", ReasonInsufficientCredentialScope)
	add("policy gap", ReasonNoPolicyForRoute)
	if len(seen) != 6 {
		t.Fatalf("want 6 distinct reasons, got %d", len(seen))
	}
}

// ---- predicates reached, and only those -----------------------------------

// A predicate that was never reached is ABSENT from the record. Recording it as
// passed would tell an auditor that a condition held when nothing checked it.
func TestUnreachedPredicatesAreAbsentNotPassed(t *testing.T) {
	graphCalls := 0
	p := &Pipeline{Evaluators: StandardEvaluators(
		stubGate{deployed: true, accepted: false}, // refuses, second in order
		stubTiers{includes: true},
		stubMeter{},
		stubGraph{called: &graphCalls},
	)}

	d := p.Authorize(context.Background(), request(fullRule()))

	if got := len(d.Predicates); got != 2 {
		t.Fatalf("want 2 verdicts (identity permitted, consent refused), got %d: %+v", got, d.Predicates)
	}
	if d.Predicates[0].Predicate != PredicateIdentity || d.Predicates[0].Outcome != Permit {
		t.Errorf("first verdict = %+v, want identity permitted", d.Predicates[0])
	}
	if d.Predicates[1].Predicate != PredicateConsent || d.Predicates[1].Outcome != Refuse {
		t.Errorf("second verdict = %+v, want consent refused", d.Predicates[1])
	}
	for _, v := range d.Predicates {
		if v.Predicate == PredicateCommercial || v.Predicate == PredicateRelationship {
			t.Errorf("%s was recorded but never ran", v.Predicate)
		}
	}
	if graphCalls != 0 {
		t.Errorf("graph was consulted %d times for a request refused on consent", graphCalls)
	}
}

// An undeclared axis is not a condition on the route, so it never runs.
func TestUndeclaredAxesDoNotRun(t *testing.T) {
	graphCalls := 0
	p := &Pipeline{Evaluators: StandardEvaluators(
		stubGate{deployed: true, accepted: false}, // would refuse if it ran
		stubTiers{includes: false},                // would refuse if it ran
		stubMeter{spent: true},                    // would refuse if it ran
		stubGraph{called: &graphCalls},
	)}

	// Declares only the relationship axis. A session, because a restricted
	// token is refused on any route that names no scope; identity always runs.
	req := request(Rule{Declared: true, Relation: "viewer"})
	req.Credential = Credential{}
	d := p.Authorize(context.Background(), req)

	if d.Outcome != Permit {
		t.Fatalf("outcome = %s (%s); undeclared axes must not refuse", d.Outcome, d.Reason)
	}
	if len(d.Predicates) != 2 || d.Predicates[0].Predicate != PredicateIdentity ||
		d.Predicates[1].Predicate != PredicateRelationship {
		t.Fatalf("want only the identity and relationship verdicts, got %+v", d.Predicates)
	}
	if graphCalls != 1 {
		t.Errorf("graph calls = %d, want 1", graphCalls)
	}
}

// ---- deny by default -------------------------------------------------------

// An undeclared route refuses as a POLICY GAP, not a missing role.
func TestUndeclaredRouteDeniesByDefault(t *testing.T) {
	d := allPermitting(nil).Authorize(context.Background(), request(Rule{}))
	if d.Outcome != Refuse || d.Reason != ReasonNoPolicyForRoute {
		t.Fatalf("got %s/%s, want refuse/%s", d.Outcome, d.Reason, ReasonNoPolicyForRoute)
	}
	if len(d.Predicates) != 0 {
		t.Errorf("no predicate may run for an undeclared route, got %+v", d.Predicates)
	}
}

// The zero-value pipeline denies everything. A pipeline nobody configured must
// not be a pipeline that permits.
func TestZeroPipelineDenies(t *testing.T) {
	var p Pipeline
	if d := p.Authorize(context.Background(), request(Rule{})); d.Outcome == Permit {
		t.Fatal("zero-value pipeline permitted a request")
	}
}

// ---- emission --------------------------------------------------------------

// Exactly one record per request, permitted or refused, authenticated or not.
func TestExactlyOneRecordPerDecision(t *testing.T) {
	cases := []struct {
		name string
		req  Request
	}{
		{"permitted", request(fullRule())},
		{"refused", request(Rule{})},
		{"unauthenticated", Request{
			Action: Action{Method: "GET", Pattern: "/api/vendors"},
			Rule:   Rule{},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink := &countingSink{}
			allPermitting(sink).Authorize(context.Background(), tc.req)
			if len(sink.emitted) != 1 {
				t.Fatalf("emitted %d records, want exactly 1", len(sink.emitted))
			}
			if sink.emitted[0].Reason == "" {
				t.Error("emitted record carries no reason")
			}
		})
	}
}

// An unauthenticated refusal records no subject. There is no caller to name,
// and a placeholder would read as one.
func TestUnauthenticatedRefusalRecordsNoSubject(t *testing.T) {
	sink := &countingSink{}
	allPermitting(sink).Authorize(context.Background(), Request{
		Action: Action{Method: "GET", Pattern: "/api/vendors"},
		Rule:   Rule{},
	})
	if got := sink.emitted[0].Subject; got != nil {
		t.Fatalf("subject = %+v, want none", got)
	}
}

// ---- consent's two deliberate behaviours -----------------------------------

// Not deployed permits and says so: not a whole-API 403, not a hidden fail-open.
func TestConsentNotDeployedPermitsVisibly(t *testing.T) {
	p := &Pipeline{Evaluators: StandardEvaluators(
		stubGate{deployed: false}, stubTiers{includes: true}, stubMeter{}, stubGraph{},
	)}
	d := p.Authorize(context.Background(), request(fullRule()))
	if d.Outcome != Permit {
		t.Fatalf("outcome = %s (%s), want permit", d.Outcome, d.Reason)
	}
	var consent *Verdict
	for i := range d.Predicates {
		if d.Predicates[i].Predicate == PredicateConsent {
			consent = &d.Predicates[i]
		}
	}
	if consent == nil {
		t.Fatal("consent verdict absent; the fail-open must be visible, not silent")
	}
	if consent.Reason != ReasonConsentNotDeployed {
		t.Fatalf("consent reason = %q, want %q", consent.Reason, ReasonConsentNotDeployed)
	}
}

// A machine has nobody to accept terms: an explicit permit, not an absence.
func TestMachinePassesConsentExplicitly(t *testing.T) {
	p := &Pipeline{Evaluators: StandardEvaluators(
		stubGate{deployed: true, accepted: false}, // would refuse a person
		stubTiers{includes: true}, stubMeter{}, stubGraph{},
	)}
	req := request(fullRule())
	req.Subject = Machine("11111111-2222-3333-4444-555555555555", "org-a")
	req.Credential = Credential{Scoped: true, Scopes: []string{"vendors:read"}}

	d := p.Authorize(context.Background(), req)
	if d.Outcome != Permit {
		t.Fatalf("outcome = %s (%s), want permit", d.Outcome, d.Reason)
	}
	for _, v := range d.Predicates {
		if v.Predicate == PredicateConsent {
			if v.Outcome != Permit || v.Reason != ReasonOK {
				t.Fatalf("consent verdict = %+v, want an explicit permit", v)
			}
			return
		}
	}
	t.Fatal("consent verdict absent; a machine passing must be recorded, not skipped")
}

// An operator still needs consent; once given, an override with only that verdict.
func TestOperatorStillNeedsConsent(t *testing.T) {
	req := request(fullRule())
	req.Operator = true
	req.Credential = Credential{} // would fail the identity axis if it ran

	refusing := &Pipeline{Evaluators: StandardEvaluators(
		stubGate{deployed: true, accepted: false},
		stubTiers{includes: false}, stubMeter{spent: true}, stubGraph{err: errors.New("down")},
	)}
	if d := refusing.Authorize(context.Background(), req); d.Outcome == Permit || d.Reason != ReasonConsentRequired {
		t.Fatalf("operator without consent: outcome = %s (%s), want refused for %s", d.Outcome, d.Reason, ReasonConsentRequired)
	}

	accepted := &Pipeline{Evaluators: StandardEvaluators(
		stubGate{deployed: true, accepted: true},
		stubTiers{includes: false}, stubMeter{spent: true}, stubGraph{err: errors.New("down")},
	)}
	d := accepted.Authorize(context.Background(), req)
	if d.Outcome != Permit || d.Reason != ReasonOperatorOverride {
		t.Fatalf("operator with consent: outcome = %s (%s), want permit by %s", d.Outcome, d.Reason, ReasonOperatorOverride)
	}
	if len(d.Predicates) != 1 || d.Predicates[0].Predicate != PredicateConsent {
		t.Fatalf("predicates = %+v, want only the consent verdict", d.Predicates)
	}
}

// ---- refusal is not an outage ---------------------------------------------

// Only graph transport failure is Unavailable; an unrepresentable caller refuses.
func TestOnlyDependencyFailuresAreUnavailable(t *testing.T) {
	unrepresentable := request(fullRule())
	unrepresentable.Subject = Subject{Kind: KindMachine, ID: "agent:org-a:uuid"}
	if d := allPermitting(nil).Authorize(context.Background(), unrepresentable); d.Outcome != Refuse {
		t.Errorf("unrepresentable subject: outcome = %s, want refuse", d.Outcome)
	}

	broken := &Pipeline{Evaluators: StandardEvaluators(
		stubGate{deployed: true, accepted: true}, stubTiers{includes: true}, stubMeter{},
		stubGraph{err: errors.New("connection refused")},
	)}
	if d := broken.Authorize(context.Background(), request(fullRule())); d.Outcome != Unavailable {
		t.Errorf("graph transport failure: outcome = %s, want unavailable", d.Outcome)
	}
}
