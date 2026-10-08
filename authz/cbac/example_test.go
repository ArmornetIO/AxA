//go:build contract

// Contract examples for CBAC; see model/example_test.go for the tag and
// Output blocks.
package cbac_test

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/ArmornetIO/identity/authz/cbac"
	"github.com/ArmornetIO/identity/authz/model"
)

type DocID string

var (
	Doc    = model.NewType[DocID]("document")
	DocOrg = model.NewParent(Doc, "org", model.Org)
	Editor = model.NewRelation(Doc, "editor")
	Write  = model.NewPermission(Doc, "write")

	// model.On guards a type; model.Via binds on a single-valued parent.
	// Values are typed, so a wrong Go type does not compile.
	CorpOrg  = cbac.NewInNetwork(model.Via(DocOrg), "corp_network") // bound per org by its admin
	FreshDoc = cbac.NewMaxAge(model.On(Doc), "fresh_signin")        // now comes from time.Now, never the caller
)

func Example() {
	built, err := model.Build(model.Config{},
		Editor.Define(model.Assign(model.User, model.Agent)),
		Write.Define(model.Grants(Editor), model.Requires(CorpOrg, FreshDoc)),
	)
	if err != nil {
		fmt.Println(err)
		return
	}
	ana, q3, acme := model.User.Ref("ana"), Doc.Ref("q3"), model.Org.Ref("acme")

	corp, err := CorpOrg.Bind(acme, netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.168.0.0/16"))
	if err != nil {
		fmt.Println(err)
		return
	}
	// Two requests: delete the key, then write it with the new value. The rule
	// refuses between them, which fails closed. Unbind deletes.
	fresh, err := FreshDoc.Bind(q3, 12*time.Hour)
	if err != nil {
		fmt.Println(err)
		return
	}
	req, err := built.Check(Write, ana, q3,
		CorpOrg.Live(netip.MustParseAddr("::ffff:10.1.2.3")), // IPv4-mapped IPv6 is unmapped first
		FreshDoc.Live(time.Now().Add(-time.Hour)),
	)
	if err != nil {
		fmt.Println(err)
		return
	}
	_, missing := built.Check(Write, ana, q3, CorpOrg.Live(netip.MustParseAddr("10.1.2.3")))

	fmt.Println(built.DSL())
	fmt.Println(corp.Requests(), fresh.Requests())
	fmt.Println(req.Context())
	fmt.Println(missing) // fresh_signin has no live value: refused before anything is sent
	// Output:
}

// These do not compile:
//
//	CorpOrg.Bind(q3, prefix)            // CorpOrg is bound on organizations
//	CorpOrg.Bind(acme, "10.0.0.0/8")    // a bound CIDR is a netip.Prefix
//	FreshDoc.Live("yesterday")          // a live sign-in time is a time.Time
//	model.Via(DocTags)                  // rules route only through single-valued parents
