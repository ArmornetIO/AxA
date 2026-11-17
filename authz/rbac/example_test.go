//go:build contract

// Contract examples for RBAC; see model/example_test.go for the tag and
// Output blocks.
package rbac_test

import (
	"fmt"

	"github.com/ArmornetIO/axa/authz/model"
	"github.com/ArmornetIO/axa/authz/rbac"
)

type DocID string

var (
	Doc    = model.NewType[DocID]("document")
	DocOrg = model.NewParent(Doc, "org", model.Org)

	// Context roles arrive with each request from the host's membership rows and
	// are never stored: Contextual, not Stored, so they cannot be assigned.
	Member = rbac.NewContextRole(model.Org, "member")
	Admin  = rbac.NewContextRole(model.Org, "admin")
	Bot    = rbac.NewRole(model.Org, "agent") // agents' org link is stored

	Viewer = rbac.NewRole(Doc, "viewer")
	Editor = rbac.NewRole(Doc, "editor")
	Reader = rbac.NewRole(Doc, "reader")

	Read  = model.NewPermission(Doc, "read")
	Write = model.NewPermission(Doc, "write")
)

func Example() {
	// Define's inclusions are OpenFGA's `or`: viewer is held directly, by any
	// editor, and by any reader.
	built, err := model.Build(model.Config{},
		Member.Define(model.Assign(model.User), Admin),
		Admin.Define(model.Assign(model.User)),
		Bot.Define(model.Assign(model.Agent)),
		Viewer.Define(model.Assign(model.User, model.Agent), Editor, Reader),
		Editor.Define(model.Assign(model.User), model.From(DocOrg, Admin)),                 // org admins edit every document in their org
		Reader.Define(model.Assign(), model.From(DocOrg, Member), model.From(DocOrg, Bot)), // no direct assignment
		Read.Define(model.Grants(Viewer)),
		Write.Define(model.Grants(Editor)),
	)
	if err != nil {
		fmt.Println(err)
		return
	}
	ana, q3, acme, beta := model.User.Ref("ana"), Doc.Ref("q3"), model.Org.Ref("acme"), model.Org.Ref("beta")

	// Every authoring call returns a model.Update; its Requests are the
	// WriteRequests to send. Every add has its remove, and nothing is read first.
	assign, err := built.Assign(Editor, ana, q3) // built.Unassign(Editor, ana, q3) takes it away
	if err != nil {
		fmt.Println(err)
		return
	}
	move, err := DocOrg.Move(q3, acme, beta) // delete old + write new, one request
	if err != nil {
		fmt.Println(err)
		return
	}
	// Membership arrives with the request, the way the host supplies it.
	inAcme, err := built.InContext(Member, ana, acme)
	if err != nil {
		fmt.Println(err)
		return
	}
	req, err := built.Check(Reader, ana, q3, inAcme)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(built.DSL())
	fmt.Println(assign.Requests(), move.Requests())
	fmt.Println(req.TupleKey())
	fmt.Println(built.ContextRelations()) // what a host checks its claim mapping against at startup
	// Output:
}

// These do not compile:
//
//	built.Assign(Member, ana, acme)    // a context role is not Stored
//	built.InContext(Editor, ana, q3)   // a stored role is not Contextual

// Vendors and assessments from a vendor-risk model, abridged; roles
// are Checkable, so no permission wraps them.
type (
	VendorID     string
	AssessmentID string
)

var (
	Vendor     = model.NewType[VendorID]("vendor")
	Assessment = model.NewType[AssessmentID]("assessment")

	Owner     = rbac.NewContextRole(model.Org, "owner")
	OrgAdmin  = rbac.NewContextRole(model.Org, "admin")
	OrgMember = rbac.NewContextRole(model.Org, "member")

	VendorOrg     = model.NewParent(Vendor, "org", model.Org) // Set when a vendor is created
	VendorContact = rbac.NewRole(Vendor, "contact")
	VendorViewer  = rbac.NewRole(Vendor, "viewer")
	VendorEditor  = rbac.NewRole(Vendor, "editor")
	VendorAdmin   = rbac.NewRole(Vendor, "admin")

	AssessmentVendor     = model.NewParent(Assessment, "vendor", Vendor)
	AssessmentAssessor   = rbac.NewRole(Assessment, "assessor")
	AssessmentRespondent = rbac.NewRole(Assessment, "respondent")
	AssessmentViewer     = rbac.NewRole(Assessment, "viewer")
	AssessmentEditor     = rbac.NewRole(Assessment, "editor")
	AssessmentAdmin      = rbac.NewRole(Assessment, "admin")
)

func armornet() (*model.Model, error) {
	return model.Build(model.Config{},
		Owner.Define(model.Assign(model.User)),
		OrgAdmin.Define(model.Assign(model.User), Owner),
		OrgMember.Define(model.Assign(model.User), OrgAdmin),

		VendorContact.Define(model.Assign(model.User)),
		VendorViewer.Define(model.Assign(), model.From(VendorOrg, OrgMember)),
		VendorEditor.Define(model.Assign(), model.From(VendorOrg, OrgMember)),
		VendorAdmin.Define(model.Assign(), model.From(VendorOrg, OrgAdmin), model.From(VendorOrg, Owner)),

		AssessmentAssessor.Define(model.Assign(model.User)),
		AssessmentRespondent.Define(model.Assign(model.User)),
		AssessmentViewer.Define(model.Assign(),
			model.From(AssessmentVendor, VendorViewer), model.From(AssessmentVendor, VendorContact),
			AssessmentAssessor, AssessmentRespondent),
		AssessmentEditor.Define(model.Assign(), model.From(AssessmentVendor, VendorEditor), AssessmentRespondent),
		AssessmentAdmin.Define(model.Assign(), model.From(AssessmentVendor, VendorAdmin)),
	)
}

func Example_armornet() {
	built, err := armornet()
	if err != nil {
		fmt.Println(err)
		return
	}
	// Today: WriteTuples(ctx, []authz.Tuple{{User: "organization:" + orgID, Relation: "org", Object: "vendor:" + vendorID}})
	u, err := VendorOrg.Set(Vendor.Ref("v1"), model.Org.Ref("acme")) // swapped arguments do not compile
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(built.DSL())
	fmt.Println(u.Requests())
	// Output:
}
