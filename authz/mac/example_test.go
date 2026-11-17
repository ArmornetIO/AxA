//go:build contract

// Contract examples for MAC; see model/example_test.go for the tag and
// Output blocks.
package mac_test

import (
	"fmt"

	"github.com/ArmornetIO/axa/authz/mac"
	"github.com/ArmornetIO/axa/authz/model"
)

// Typed mac.Level and mac.Compartment constants (<Type><Value>, O19): a
// compartment where a level belongs does not compile.
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
	DocOrg = model.NewParent(Doc, "org", model.Org) // single-valued: MAC reads every clearance through it
	Viewer = model.NewRelation(Doc, "viewer")
	Editor = model.NewRelation(Doc, "editor")
	Read   = model.NewPermission(Doc, "read")
	Write  = model.NewPermission(Doc, "write")

	// A lattice is held on its owner type and complete once constructed.
	Clearance = mac.NewLattice(model.Org, "clearance", mac.Config{
		Levels:       []mac.Level{ClearancePublic, ClearanceInternal, ClearanceConfidential, ClearanceRestricted}, // lowest first
		Compartments: []mac.Compartment{CompartmentFinance, CompartmentLegal},
		Holders:      model.Assign(model.User, model.Agent), // the only place MAC names subject types
	})
	// The parent must lead to the lattice's owner type, or this does not compile.
	Docs = mac.NewClassification(Clearance, DocOrg)
)

func defs() []model.Def {
	return []model.Def{
		Viewer.Define(model.Assign(model.User, model.Agent)),
		Editor.Define(model.Assign(model.User, model.Agent)),
		Read.Define(model.Grants(Viewer, Editor), model.Requires(Docs.NoReadUp())), // simple security property
		Write.Define(model.Grants(Editor), model.Requires(Docs.NoWriteDown())),     // *-property, optional
	}
}

func Example() {
	built, err := model.Build(model.Config{}, defs()...)
	if err != nil {
		fmt.Println(err)
		return
	}
	ana, q3, acme := model.User.Ref("ana"), Doc.Ref("q3"), model.Org.Ref("acme")

	clr, err := Clearance.Label(ClearanceRestricted, CompartmentLegal) // compartments are a set
	if err != nil {
		fmt.Println(err) // a value not in the lattice
		return
	}
	cls, err := Clearance.Label(ClearanceConfidential, CompartmentFinance)
	if err != nil {
		fmt.Println(err)
		return
	}
	// Each is a set: it writes the label's tuples and deletes every other tuple
	// of that piece of state, in one request, reading nothing.
	clear, err := Clearance.Clear(acme, ana, clr)
	if err != nil {
		fmt.Println(err)
		return
	}
	classify, err := Docs.Classify(q3, acme, cls) // markers point at the owner, never at a subject
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(built.DSL())
	fmt.Println(clear.Requests())
	fmt.Println(classify.Requests())
	fmt.Println(mac.Dominates(clr, cls)) // false: ana lacks finance; the oracle the tests compare to
	// Output:
}

// These do not compile:
//
//	Clearance.Label(CompartmentFinance, ClearanceRestricted)   // the first argument is a mac.Level
//	mac.NewClassification(Clearance, DocFolder)                // the parent does not lead to organization
//	Clearance.Clear(q3, ana, clr)                              // the owner is an organization
//
// A constant left out of Levels compiles, and Label refuses it with an error
// naming it.

// Unclear and Unclassify take everything away: a Label always has exactly one
// level, so there is no empty label to set.
func ExampleLattice_Unclear() {
	u, err := Clearance.Unclear(model.Org.Ref("acme"), model.User.Ref("ana"))
	fmt.Println(u.Requests(), err)
	u, err = Docs.Unclassify(Doc.Ref("q3"), model.Org.Ref("acme"))
	fmt.Println(u.Requests(), err)
	// Output:
}

type DeviceID string

// A future subject type fails closed: device can reach read but is not a
// holder, so Build reports it unless the lattice records that as intended.
func ExampleLattice_neverCleared() {
	device := model.NewType[DeviceID]("device")
	build := func(cfg mac.Config) error {
		docs := mac.NewClassification(mac.NewLattice(model.Org, "clearance", cfg), DocOrg)
		_, err := model.Build(model.Config{},
			Viewer.Define(model.Assign(model.User, device)),
			Read.Define(model.Grants(Viewer), model.Requires(docs.NoReadUp())),
		)
		return err
	}
	levels := []mac.Level{ClearancePublic, ClearanceRestricted}
	fmt.Println(build(mac.Config{Levels: levels, Holders: model.Assign(model.User)})) // device can never be cleared
	fmt.Println(build(mac.Config{Levels: levels, Holders: model.Assign(model.User),
		NeverCleared: model.Assign(device)})) // recorded as intended: refused everywhere MAC guards
	// Output:
}
