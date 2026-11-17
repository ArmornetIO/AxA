//go:build contract

// Contract examples for model. Output blocks come
// from OpenFGA's renderer once the passing story removes the tag, never by hand.
package model_test

import (
	"errors"
	"fmt"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"

	"github.com/ArmornetIO/axa/authz/cbac"
	"github.com/ArmornetIO/axa/authz/mac"
	"github.com/ArmornetIO/axa/authz/model"
)

type DocID string

// Handles are immutable and typed by their type's id; "document" is
// written once.
var (
	Doc    = model.NewType[DocID]("document")
	DocOrg = model.NewParent(Doc, "org", model.Org) // single-valued
	Viewer = model.NewRelation(Doc, "viewer")
	Editor = model.NewRelation(Doc, "editor")
	Read   = model.NewPermission(Doc, "read")
	Write  = model.NewPermission(Doc, "write")
)

func core() []model.Def {
	return []model.Def{
		Viewer.Define(model.Assign(model.User, model.Agent)),
		Editor.Define(model.Assign(model.User)),
		Read.Define(model.Grants(Viewer, Editor)),
		Write.Define(model.Grants(Editor)),
	}
}

func Example() {
	built, err := model.Build(model.Config{ConditionCost: 100}, core()...) // must match the server's --max-condition-evaluation-cost
	if err != nil {
		fmt.Println(err) // every problem at once
		return
	}
	ana, q3, acme := model.User.Ref("ana"), Doc.Ref("q3"), model.Org.Ref("acme")

	set, err := DocOrg.Set(q3, acme) // the one parent tuple
	if err != nil {
		fmt.Println(err)
		return
	}
	assign, err := built.Assign(Editor, ana, q3) // built.Unassign takes it away
	if err != nil {
		fmt.Println(err)
		return
	}
	req, err := built.Check(Read, ana, q3)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(built.DSL())
	fmt.Println(set.Requests(), assign.Requests())
	fmt.Println(req.TupleKey())
	fmt.Println(req.Context())               // live values only; a fresh copy each call
	fmt.Println(req.ModelID() == built.ID()) // send this id, never a different one
	// Output:
}

type FolderID string
type GroupID string

var (
	Folder       = model.NewType[FolderID]("folder")
	Group        = model.NewType[GroupID]("group")
	FolderParent = model.NewParent(Folder, "parent", Folder)
	FolderViewer = model.NewRelation(Folder, "viewer")
	GroupMember  = model.NewRelation(Group, "member")
	ReadFolder   = model.NewPermission(Folder, "read")
)

// Definitions are built when Build's arguments are evaluated, so a definition
// may refer to its own handle: recursion and nested groups compile.
func Example_recursion() {
	built, err := model.Build(model.Config{},
		GroupMember.Define(model.Assign(model.User, GroupMember.Members())), // [user, group#member]
		FolderViewer.Define(model.Assign(model.User, GroupMember.Members())),
		ReadFolder.Define(model.Grants(FolderViewer, model.From(FolderParent, ReadFolder))), // read from parent
	)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(built.DSL())
	// Output:
}

// What the compiler cannot know is refused where the request or update is
// built, before anything is sent.
func Example_construction() {
	built, err := model.Build(model.Config{}, core()...)
	if err != nil {
		fmt.Println(err)
		return
	}
	q3 := Doc.Ref("q3")
	_, err = built.Check(Read, model.Org.Ref("acme"), q3) // an organization cannot hold read
	fmt.Println(err)
	_, err = built.Check(Read, model.User.Ref("a:b"), q3) // ':' in an id
	fmt.Println(err)
	_, err = built.Check(Read, model.User.Ref("ana"), model.Ref[DocID]{}) // a zero Ref
	fmt.Println(err)
	_, err = built.Assign(Owner, model.User.Ref("ana"), q3) // owner is not defined in this model
	fmt.Println(err)
	// Output:
}

// These do not compile:
//
//	built.Check(Read, ana, Folder.Ref("f1"))          // an object of the wrong type
//	DocOrg.Set(acme, q3)                              // parent arguments reversed
//	Doc.Ref(FolderID("f1"))                           // a folder id as a document id
//	model.From(DocOrg, FolderViewer)                  // viewer is not on organization
//	Read.Define(model.Grants(FolderViewer))           // a folder relation granting a document permission
//	model.Ask(Read, Folder.Ref("f1"))                 // a question about the wrong type

const (
	ClearancePublic     mac.Level = "public"
	ClearanceRestricted mac.Level = "restricted"
)

var (
	Owner      = model.NewRelation(Doc, "owner")
	Auditor    = model.NewRelation(Doc, "auditor")
	Contractor = model.NewRelation(Doc, "contractor")
	Blocked    = model.NewRelation(Doc, "blocked")
	Suspended  = model.NewRelation(Doc, "suspended")

	CorpOrg  = cbac.NewInNetwork(model.Via(DocOrg), "corp_network")
	FreshDoc = cbac.NewMaxAge(model.On(Doc), "fresh_signin")

	Clearance = mac.NewLattice(model.Org, "clearance", mac.Config{
		Levels:  []mac.Level{ClearancePublic, ClearanceRestricted},
		Holders: model.Assign(model.User, model.Agent),
	})
	Docs = mac.NewClassification(Clearance, DocOrg)
)

// Composition: grants OR, requirements AND over every path, denials apply
// to every path, and an exemption skips exactly the requirements it lists.
func Example_composition() {
	built, err := model.Build(model.Config{},
		Viewer.Define(model.Assign(model.User, model.Agent)),
		Editor.Define(model.Assign(model.User)),
		Owner.Define(model.Assign(model.User)),
		Auditor.Define(model.Assign(model.User)),
		Contractor.Define(model.Assign(model.User)),
		Blocked.Define(model.Assign(model.User, model.Agent)),
		Suspended.Define(model.Assign(model.User, model.Agent)),
		Read.Define(
			model.Grants(
				Viewer,
				Editor,
				model.All(Contractor, CorpOrg),   // a context rule guarding one branch
				model.Except(Auditor, Suspended), // Any, All and Except nest freely
			),
			model.Requires(Docs.NoReadUp(), FreshDoc),
			model.Denies(Blocked),
			model.Exempt(Owner, "break-glass: owners read every classification", Docs.NoReadUp()), // still needs FreshDoc
		),
	)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(built.DSL())
	for _, e := range built.Exemptions() {
		fmt.Println(e) // and every role reaching the exempt term through inclusion
	}
	// Output:
}

// These do not compile:
//
//	model.Grants(Docs.NoReadUp())   // a MAC property is a Requirement, not a Term
//	model.Denies(Member)            // a context role is not Stored

// Build refuses the combinations that can only be mistakes, all at once,
// each naming its declarations.
func ExampleBuildError() {
	_, err := model.Build(model.Config{},
		Viewer.Define(model.Assign(model.User)),
		Owner.Define(model.Assign(model.User)),
		Read.Define(
			model.Grants(model.Any(Viewer, model.All(Viewer, CorpOrg)), Owner), // the CorpOrg branch does nothing
			model.Exempt(Owner, "", CorpOrg),                                   // no reason
		),
		Write.Define(), // a permission with no grant
	)
	if be, ok := errors.AsType[*model.BuildError](err); ok {
		for _, p := range be.Problems {
			fmt.Println(p) // document#write: grants nothing
		}
	}
	// Output:
}

type DeviceID string

// Build is a pure function: building again with other definitions returns a
// new model and leaves the first as it was.
func ExampleBuild_rebuild() {
	built, _ := model.Build(model.Config{}, core()...)
	device := model.NewType[DeviceID]("device")
	built2, err := model.Build(model.Config{},
		Viewer.Define(model.Assign(model.User, model.Agent, device)),
		Editor.Define(model.Assign(model.User)),
		Read.Define(model.Grants(Viewer, Editor)),
	)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(built.DSL() == built2.DSL(), built.ID() == built2.ID())
	// Output:
}

// OpenFGA answers allowed, not allowed, or an evaluation error; a missing live
// value is an error, not a refusal. The builders keep all three.
func ExampleOutcomeOf() {
	fmt.Println(model.OutcomeOf(true, nil))
	fmt.Println(model.OutcomeOf(false, nil))
	fmt.Println(model.OutcomeOf(false, errors.New("missing parameter signed_in_at")))
	// Output:
}

// The invariants OpenFGA cannot encode are reported over the tuples the host
// reads with AuditFilters, each with the delete that remediates it.
func ExampleAudit() {
	built, err := model.Build(model.Config{}, core()...)
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, f := range model.AuditFilters(built) {
		fmt.Println(f) // every relation an invariant reads; the host reads every page of each
	}
	tuples := []*openfgav1.Tuple{ // as another client might have written them
		{Key: &openfgav1.TupleKey{Object: "document:q3", Relation: "org", User: "organization:acme"}},
		{Key: &openfgav1.TupleKey{Object: "document:q3", Relation: "org", User: "organization:beta"}},
	}
	for _, v := range model.Audit(built, tuples) {
		fmt.Println(v) // single-parent: document:q3 has 2 tuples on org; remediate: delete …
	}
	// Output:
}
