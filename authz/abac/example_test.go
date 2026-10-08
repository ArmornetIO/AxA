//go:build contract

// Contract examples for ABAC; see model/example_test.go for the tag and
// Output blocks.
package abac_test

import (
	"fmt"

	"github.com/ArmornetIO/identity/authz/abac"
	"github.com/ArmornetIO/identity/authz/model"
	"github.com/ArmornetIO/identity/authz/rbac"
)

type DocID string

var (
	Doc    = model.NewType[DocID]("document")
	DocOrg = model.NewParent(Doc, "org", model.Org)
	Member = rbac.NewContextRole(model.Org, "member")
	Viewer = model.NewRelation(Doc, "viewer")
	Read   = model.NewPermission(Doc, "read")

	// Generic over the attribute's value type: one shape serving several value
	// types, the use of generics the Go bible endorses.
	Dept      = abac.NewAttr[string]("department") // a live caller attribute
	LegalDept = abac.NewIn(model.On(Doc), "legal_departments", Dept)
)

func Example() {
	// An attribute grant only reaches org members, so it is not a Term and
	// grants only through abac.Gated.
	built, err := model.Build(model.Config{},
		Member.Define(model.Assign(model.User)),
		Viewer.Define(model.Assign(model.User)),
		Read.Define(model.Grants(Viewer, abac.Gated(LegalDept, model.From(DocOrg, Member)))),
	)
	if err != nil {
		fmt.Println(err)
		return
	}
	ana, q3, acme := model.User.Ref("ana"), Doc.Ref("q3"), model.Org.Ref("acme")

	u, err := LegalDept.Bind(q3, "legal", "procurement")
	if err != nil {
		fmt.Println(err)
		return
	}
	inAcme, err := built.InContext(Member, ana, acme)
	if err != nil {
		fmt.Println(err)
		return
	}
	req, err := built.Check(Read, ana, q3, Dept.Live("legal"), inAcme)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(built.DSL())
	fmt.Println(u.Requests())
	fmt.Println(req.Context()) // the attrs map, assembled from every Attr.Live in the request
	// Output:
}

// The same attribute rule as both a grant and a requirement on one type is a
// Build problem.
func Example_twoUses() {
	_, err := model.Build(model.Config{},
		Member.Define(model.Assign(model.User)),
		Viewer.Define(model.Assign(model.User)),
		Read.Define(
			model.Grants(Viewer, abac.Gated(LegalDept, model.From(DocOrg, Member))),
			model.Requires(LegalDept),
		),
	)
	fmt.Println(err)
	// Output:
}

// These do not compile:
//
//	Dept.Live(42)                          // department is a string attribute
//	model.Grants(Viewer, LegalDept)        // an ungated attribute rule is not a Term
//	abac.Gated(FreshDoc, Viewer)           // only attribute rules are gated
