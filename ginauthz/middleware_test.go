package ginauthz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// These test translation only (request → question, verdict → response); what
// each condition decides is tested in identity/access.

type fakePolicy struct {
	rule Rule
	ok   bool
}

func (f fakePolicy) Lookup(_, _ string) (Rule, bool) { return f.rule, f.ok }

type fakePrincipals struct {
	p  Principal
	ok bool
}

func (f fakePrincipals) Principal(_ *gin.Context) (Principal, bool) { return f.p, f.ok }

// fakeDecider returns a fixed verdict and records the question it was asked, so
// a test can assert the translation in both directions.
type fakeDecider struct {
	v    Verdict
	seen *Request
}

func (f *fakeDecider) Authorize(_ context.Context, req Request) Verdict {
	if f.seen != nil {
		*f.seen = req
	}
	return f.v
}

func decider(d Decision, reason string) *fakeDecider {
	return &fakeDecider{v: Verdict{Decision: d, Reason: reason}}
}

// serve wires an Authorizer in front of a 200 handler on a parameterized route
// and returns the status and body for GET /vendors/v1.
func serve(t *testing.T, d Deps) (int, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(Middleware(d))
	r.GET("/vendors/:id", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/vendors/v1", nil))
	return w.Code, w.Body.String()
}

func member() Principal {
	return Principal{Subject: "sub-1", UserID: "u1", OrgIDs: []string{"orgA"}, ActiveOrgID: "orgA"}
}

func objectRule() Rule {
	return Rule{Kind: KindObject, ObjectType: "vendor", ObjectIDSpec: ":id", Relation: "editor"}
}

// ---- outcome → response ----------------------------------------------------

// The three outcomes must map to three distinct responses. Collapsing refuse
// and unavailable is the defect this feature exists to remove.
func TestOutcomesMapToDistinctStatuses(t *testing.T) {
	cases := []struct {
		name string
		d    Decision
		want int
	}{
		{"allow", Allow, http.StatusOK},
		{"deny is a client error", Deny, http.StatusForbidden},
		{"unavailable is a server error", Unavailable, http.StatusServiceUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _ := serve(t, Deps{
				Policy:     fakePolicy{rule: objectRule(), ok: true},
				Principals: fakePrincipals{p: member(), ok: true},
				Authorizer: decider(tc.d, ReasonRelationAbsent),
			})
			if code != tc.want {
				t.Fatalf("status = %d, want %d", code, tc.want)
			}
		})
	}
}

// At the wire: no refusal leaves the front door without naming its
// condition, whatever the decider returned.
func TestRefusalsAlwaysCarryACode(t *testing.T) {
	for _, reason := range []string{
		ReasonRelationAbsent, ReasonNoPolicyForRoute, ReasonInsufficientScope,
		ReasonConsentRequired, ReasonTierExcluded, ReasonQuotaExhausted,
		ErrCodeNoOrgScope, ReasonNotGodAdmin, ReasonSubjectNotRepresentable,
		"", // an adapter that forgot
	} {
		_, body := serve(t, Deps{
			Policy:     fakePolicy{rule: objectRule(), ok: true},
			Principals: fakePrincipals{p: member(), ok: true},
			Authorizer: decider(Deny, reason),
		})
		if strings.Contains(body, `"code":""`) || !strings.Contains(body, `"code":"`) {
			t.Errorf("reason %q: refusal went out without a code: %s", reason, body)
		}
	}
}

// A 503 must also name its dependency, so an operator reading a page knows
// what actually failed.
func TestUnavailableNamesItsDependency(t *testing.T) {
	_, body := serve(t, Deps{
		Policy:     fakePolicy{rule: objectRule(), ok: true},
		Principals: fakePrincipals{p: member(), ok: true},
		Authorizer: decider(Unavailable, ""),
	})
	if !strings.Contains(body, `"code":"`+ReasonGraphUnavailable+`"`) {
		t.Fatalf("want %s in body, got %s", ReasonGraphUnavailable, body)
	}
}

// ---- request → question ----------------------------------------------------

// The raw path is decoded, caller-chosen bytes; only the pattern is stable.
func TestDeciderIsAskedAboutThePatternNotThePath(t *testing.T) {
	var seen Request
	d := &fakeDecider{v: Verdict{Decision: Allow}, seen: &seen}
	serve(t, Deps{
		Policy:     fakePolicy{rule: objectRule(), ok: true},
		Principals: fakePrincipals{p: member(), ok: true},
		Authorizer: d,
	})
	if seen.Pattern != "/vendors/:id" {
		t.Errorf("pattern = %q, want the route pattern", seen.Pattern)
	}
	if seen.ObjectID != "v1" {
		t.Errorf("objectID = %q, want the resolved param", seen.ObjectID)
	}
	if seen.Method != http.MethodGet {
		t.Errorf("method = %q", seen.Method)
	}
}

// An undeclared route still reaches the decider, marked undeclared, so that
// deny-by-default is ONE rule in one place rather than a second copy here.
func TestUndeclaredRouteReachesTheDeciderAsUndeclared(t *testing.T) {
	var seen Request
	d := &fakeDecider{v: Verdict{Decision: Deny, Reason: ReasonNoPolicyForRoute}, seen: &seen}
	code, body := serve(t, Deps{
		Policy:     fakePolicy{ok: false},
		Principals: fakePrincipals{p: member(), ok: true},
		Authorizer: d,
	})
	if seen.Rule.Declared {
		t.Error("rule reached the decider marked declared")
	}
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", code)
	}
	if !strings.Contains(body, ReasonNoPolicyForRoute) {
		t.Errorf("body = %s, want %s", body, ReasonNoPolicyForRoute)
	}
}

// Operator standing is resolved by the host and passed in; identity never holds
// the allowlist, and it is never a stored relationship.
func TestOperatorStandingIsPassedToTheDecider(t *testing.T) {
	var seen Request
	d := &fakeDecider{v: Verdict{Decision: Allow}, seen: &seen}
	serve(t, Deps{
		Policy:     fakePolicy{rule: objectRule(), ok: true},
		Principals: fakePrincipals{p: member(), ok: true},
		GodAdmins:  map[string]struct{}{"sub-1": {}},
		Authorizer: d,
	})
	if !seen.Operator {
		t.Fatal("operator standing was not passed to the decider")
	}
}

// ---- the short-circuits that are genuinely transport -----------------------

// A public route asks no question: there is nothing to decide, so the decider
// must not be consulted.
func TestPublicRouteSkipsTheDecider(t *testing.T) {
	var seen Request
	d := &fakeDecider{v: Verdict{Decision: Deny, Reason: ReasonRelationAbsent}, seen: &seen}
	code, _ := serve(t, Deps{
		Policy:     fakePolicy{rule: Rule{Kind: KindPublic}, ok: true},
		Principals: fakePrincipals{ok: false},
		Authorizer: d,
	})
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if seen.Pattern != "" {
		t.Error("decider was consulted for a public route")
	}
}

// Unauthenticated is an authentication answer, not an authorization one: there
// is no subject yet for a decision to be about.
func TestUnauthenticatedOnAGatedRouteIs401(t *testing.T) {
	code, _ := serve(t, Deps{
		Policy:     fakePolicy{rule: objectRule(), ok: true},
		Principals: fakePrincipals{ok: false},
		Authorizer: decider(Allow, ReasonOK),
	})
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
}

// Off, an operator route 404s for a listed operator and an anonymous caller
// alike; a 401 would reveal it exists.
func TestGodAdminRoutesAre404WhenOff(t *testing.T) {
	for _, p := range []fakePrincipals{
		{p: member(), ok: true},
		{ok: false},
	} {
		code, _ := serve(t, Deps{
			Policy:     fakePolicy{rule: Rule{Kind: KindGodAdmin}, ok: true},
			Principals: p,
			GodAdmins:  map[string]struct{}{"sub-1": {}},
			Authorizer: decider(Allow, ReasonOK),
		})
		if code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", code)
		}
	}
}

// ---- object id resolution --------------------------------------------------

// "@org_id" is the ACTIVE org, not the first membership, which would let a
// caller reach another of their orgs by changing only the URL.
func TestResolveObjectID_AtOrgIDUsesActiveOrg(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	p := Principal{OrgIDs: []string{"orgA", "orgB"}, ActiveOrgID: "orgB"}
	got, ok := resolveObjectID(c, orgIDSpec, p)
	if !ok || got != "orgB" {
		t.Fatalf("resolveObjectID = %q,%v; want orgB,true", got, ok)
	}

	// No active org resolves to nothing. Whether that refuses is the rule's
	// business, answered by the decider, not decided here.
	if got, ok := resolveObjectID(c, orgIDSpec, Principal{OrgIDs: []string{"orgA"}}); ok || got != "" {
		t.Fatalf("resolveObjectID with no active org = %q,%v; want \"\",false", got, ok)
	}
}

// ---- credential ceiling derivation -----------------------------------------

// Scoped is derived, never set, so no construction site can forget it. PATs and
// agents are ceilinged; sessions are not.
func TestScopedIsDerivedFromCredentialKind(t *testing.T) {
	if Session("s", "u", "orgA", nil, nil).Scoped() {
		t.Error("a session must not be scope-ceilinged")
	}
	if !PAT("s", "u", "orgA", nil, nil, []string{"vendors:read"}).Scoped() {
		t.Error("a PAT must be scope-ceilinged")
	}
	// An agent's list is empty, which is a ceiling of nothing rather than the
	// absence of a ceiling: a scoped route refuses it.
	a := Agent("agent:orgA:uuid-1", "uuid-1", "orgA")
	if !a.Scoped() || len(a.Scopes) != 0 {
		t.Errorf("agent Scoped=%v scopes=%v; want true, empty", a.Scoped(), a.Scopes)
	}
	if a.AgentID != "uuid-1" {
		t.Errorf("AgentID = %q; the graph cannot parse the full client id", a.AgentID)
	}
}
