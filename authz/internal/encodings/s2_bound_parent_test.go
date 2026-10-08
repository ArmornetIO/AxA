package encodings

import (
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/ArmornetIO/identity/authz/internal/fgatest"
)

// The R8 shape: a rule placed via a single-valued parent is a wildcard
// conditional tuple on the parent, read through the tupleset per subject.
const s2Model = `model
  schema 1.1

type user

type organization
  relations
    define corp_network_ok: [user:* with corp_network]

type document
  relations
    define org: [organization]
    define editor: [user]
    define write: editor and corp_network_ok from org

condition corp_network(client_ip: ipaddress, allowed_cidrs: list<string>) {
  allowed_cidrs.exists(c, client_ip.in_cidr(c))
}
`

func TestS2BoundViaParent(t *testing.T) {
	st := fgatest.Start(t).Load(t, s2Model)
	bound, err := structpb.NewStruct(map[string]any{"allowed_cidrs": []any{"10.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	st.MustWrite(t,
		fgatest.Key("document:q3#org@organization:acme"),
		fgatest.Key("document:q3#editor@user:ana"),
		fgatest.Key("document:q3#editor@user:bob"),
		&openfgav1.TupleKey{Object: "organization:acme", Relation: "corp_network_ok", User: "user:*",
			Condition: &openfgav1.RelationshipCondition{Name: "corp_network", Context: bound}},
	)

	for _, row := range []struct {
		name, user string
		live       map[string]any
		want       bool
		wantErr    bool
	}{
		{name: "inside the bound network", user: "user:ana", live: map[string]any{"client_ip": "10.1.2.3"}, want: true},
		{name: "per subject: a second editor", user: "user:bob", live: map[string]any{"client_ip": "10.9.9.9"}, want: true},
		{name: "outside", user: "user:ana", live: map[string]any{"client_ip": "8.8.8.8"}},
		{name: "missing live value is an error, not a refusal", user: "user:ana", wantErr: true},
		{name: "request context cannot override a bound value", user: "user:ana",
			live: map[string]any{"client_ip": "8.8.8.8", "allowed_cidrs": []any{"0.0.0.0/0"}}},
		{name: "not an editor", user: "user:cy", live: map[string]any{"client_ip": "10.1.2.3"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			req := fgatest.Req("document:q3#write@" + row.user)
			if row.live != nil {
				if req.Context, err = structpb.NewStruct(row.live); err != nil {
					t.Fatal(err)
				}
			}
			got, err := st.Check(req)
			if row.wantErr {
				if err == nil {
					t.Fatalf("got %v, want an evaluation error", got)
				}
				return
			}
			if err != nil || got != row.want {
				t.Fatalf("got %v, %v; want %v", got, err, row.want)
			}
		})
	}
}
