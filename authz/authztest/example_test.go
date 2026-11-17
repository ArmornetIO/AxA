//go:build contract

// Contract examples for authztest; net/http rather than gin, which the module
// does not depend on.
package authztest_test

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ArmornetIO/axa/authz"
	"github.com/ArmornetIO/axa/authz/authztest"
	"github.com/ArmornetIO/axa/authz/cbac"
	"github.com/ArmornetIO/axa/authz/mac"
	"github.com/ArmornetIO/axa/authz/model"
	"github.com/ArmornetIO/axa/authz/rbac"
)

const (
	ClearancePublic       mac.Level = "public"
	ClearanceInternal     mac.Level = "internal"
	ClearanceConfidential mac.Level = "confidential"
	ClearanceRestricted   mac.Level = "restricted"

	CompartmentFinance mac.Compartment = "finance"
	CompartmentLegal   mac.Compartment = "legal"
)

type DocID string

var (
	Doc    = model.NewType[DocID]("document")
	DocOrg = model.NewParent(Doc, "org", model.Org)
	Member = rbac.NewContextRole(model.Org, "member")
	Owner  = rbac.NewRole(Doc, "owner") // ownership is a grant, never a clearance
	Viewer = rbac.NewRole(Doc, "viewer")
	Read   = model.NewPermission(Doc, "read")
	Write  = model.NewPermission(Doc, "write")

	Clearance = mac.NewLattice(model.Org, "clearance", mac.Config{
		Levels:       []mac.Level{ClearancePublic, ClearanceInternal, ClearanceConfidential, ClearanceRestricted},
		Compartments: []mac.Compartment{CompartmentFinance, CompartmentLegal},
		Holders:      model.Assign(model.User, model.Agent),
	})
	Docs     = mac.NewClassification(Clearance, DocOrg)
	FreshDoc = cbac.NewMaxAge(model.On(Doc), "fresh_signin")
)

func Model() (*model.Model, error) {
	return model.Build(model.Config{},
		Member.Define(model.Assign(model.User)),
		Owner.Define(model.Assign(model.User)),
		Viewer.Define(model.Assign(model.Agent), model.From(DocOrg, Member)),
		Read.Define(model.Grants(Owner, Viewer), model.Requires(Docs.NoReadUp())),
		Write.Define(model.Grants(Owner), model.Requires(Docs.NoWriteDown(), FreshDoc)),
	)
}

var update = flag.Bool("update", false, "rewrite testdata")

func TestMACReference(t *testing.T) {
	built, err := Model()
	if err != nil {
		t.Fatal(err)
	}
	ana, cy, bob, bot := model.User.Ref("ana"), model.User.Ref("cy"), model.User.Ref("bob"), model.Agent.Ref("bot")
	q3, acme := Doc.Ref("q3"), model.Org.Ref("acme")
	label := func(l mac.Level, c ...mac.Compartment) mac.Label {
		lbl, err := Clearance.Label(l, c...)
		if err != nil {
			t.Fatal(err)
		}
		return lbl
	}

	srv := authztest.Start(t, built) // in-process OpenFGA, fresh store; holds t
	srv.Apply(Clearance.Clear(acme, ana, label(ClearanceRestricted, CompartmentLegal)))
	srv.Apply(Clearance.Clear(acme, cy, label(ClearanceRestricted, CompartmentFinance)))
	srv.Apply(Clearance.Clear(acme, bot, label(ClearancePublic)))
	srv.Apply(Docs.Classify(q3, acme, label(ClearanceConfidential, CompartmentFinance)))
	srv.Apply(built.Assign(Owner, bob, q3)) // Apply(u, err): a construction error fails the test
	srv.Apply(built.Assign(Viewer, bot, q3))

	inAcme := func(s model.AnyRef) model.Live { return authztest.Must(built.InContext(Member, s, acme)) }
	table := authztest.Table{
		{Name: "cleared above, right compartment", Check: authztest.Req(Read, cy, q3, inAcme(cy)), Want: authztest.Permit},
		{Name: "cleared above, wrong compartment", Check: authztest.Req(Read, ana, q3, inAcme(ana)), Want: authztest.Refuse},
		{Name: "owner without clearance", Check: authztest.Req(Read, bob, q3, inAcme(bob)), Want: authztest.Refuse},
		{Name: "agent below classification", Check: authztest.Req(Read, bot, q3), Want: authztest.Refuse},
		{Name: "fresh sign-in not sent", Check: authztest.RawReq(Write, bob, q3), Want: authztest.MissingLive("signed_in_at")},
	}
	// Fails on an empty table, a read never both permitted and refused, or an
	// Error row failing for another cause.
	srv.Run(table)

	if *update {
		srv.Export("testdata/mac.fga.yaml", table) // Error rows: a counted comment block
	}
}

// axa/access implements authz.Authorizer; authztest.Fixed does here.
type DocHandler struct{ az authz.Authorizer }

func (s *DocHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := model.Ask(Read, Doc.Ref(DocID(r.PathValue("id")))) // the one place a raw string becomes a DocID
	if err := s.az.Authorize(r.Context(), q); err != nil {  // the caller comes from ctx
		if errors.Is(err, authz.ErrDenied) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusInternalServerError) // Error: fail closed
		return
	}
	w.WriteHeader(http.StatusOK)
}

func ExampleFixed() {
	az := authztest.Fixed{ // anything unlisted is authz.ErrDenied
		model.Ask(Read, Doc.Ref("q3")): nil,
	}
	mux := http.NewServeMux()
	mux.Handle("GET /docs/{id}", &DocHandler{az: az})

	for _, path := range []string{"/docs/q3", "/docs/q4"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil))
		fmt.Println(path, rec.Code)
	}
	// Output:
}
