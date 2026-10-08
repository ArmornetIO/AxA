package encodings

import (
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/openfga/language/pkg/go/transformer"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func this() *openfgav1.Userset {
	return &openfgav1.Userset{Userset: &openfgav1.Userset_This{This: &openfgav1.DirectUserset{}}}
}

func computed(rel string) *openfgav1.Userset {
	return &openfgav1.Userset{Userset: &openfgav1.Userset_ComputedUserset{ComputedUserset: &openfgav1.ObjectRelation{Relation: rel}}}
}

func union(children ...*openfgav1.Userset) *openfgav1.Userset {
	return &openfgav1.Userset{Userset: &openfgav1.Userset_Union{Union: &openfgav1.Usersets{Child: children}}}
}

func intersection(children ...*openfgav1.Userset) *openfgav1.Userset {
	return &openfgav1.Userset{Userset: &openfgav1.Userset_Intersection{Intersection: &openfgav1.Usersets{Child: children}}}
}

func difference(base, minus *openfgav1.Userset) *openfgav1.Userset {
	return &openfgav1.Userset{Userset: &openfgav1.Userset_Difference{Difference: &openfgav1.Difference{Base: base, Subtract: minus}}}
}

func direct(types ...string) *openfgav1.RelationMetadata {
	md := &openfgav1.RelationMetadata{}
	for _, t := range types {
		md.DirectlyRelatedUserTypes = append(md.DirectlyRelatedUserTypes, &openfgav1.RelationReference{Type: t})
	}
	return md
}

// TestS4RoundTrip renders the R5 shape (grants and requirements, no blocks) and
// parses it back, equal after normalising This.
func TestS4RoundTrip(t *testing.T) {
	built := &openfgav1.AuthorizationModel{
		SchemaVersion: "1.1",
		TypeDefinitions: []*openfgav1.TypeDefinition{
			{Type: "user"},
			{
				Type: "document",
				Relations: map[string]*openfgav1.Userset{
					"viewer":        this(),
					"editor":        this(),
					"fresh":         this(),
					"blocked":       this(),
					"read_grants":   union(computed("viewer"), computed("editor")),
					"read_guarded":  intersection(computed("read_grants"), computed("fresh")),
					"read":          difference(computed("read_guarded"), computed("blocked")),
					"mixed_nesting": difference(intersection(union(computed("viewer"), computed("editor")), computed("fresh")), computed("blocked")),
				},
				Metadata: &openfgav1.Metadata{Relations: map[string]*openfgav1.RelationMetadata{
					"viewer": direct("user"), "editor": direct("user"), "fresh": direct("user"), "blocked": direct("user"),
					"read_grants": {}, "read_guarded": {}, "read": {}, "mixed_nesting": {},
				}},
			},
		},
	}
	js, err := protojson.Marshal(built)
	if err != nil {
		t.Fatal(err)
	}
	dsl, err := transformer.TransformJSONStringToDSL(string(js))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	parsed, err := transformer.TransformDSLToProto(*dsl)
	if err != nil {
		t.Fatalf("parse back:\n%s\n%v", *dsl, err)
	}
	normalise(parsed)
	if !proto.Equal(strip(built), strip(parsed)) {
		t.Errorf("round trip differs\nrendered:\n%s\nbuilt:  %v\nparsed: %v", *dsl, strip(built), strip(parsed))
	}
	t.Logf("rendered:\n%s", *dsl)

	// Recorded: one operator kind per definition unless parenthesised.
	if _, err := transformer.TransformDSLToProto("model\n  schema 1.1\ntype user\ntype document\n  relations\n    define a: [user]\n    define b: [user]\n    define c: [user]\n    define r: a and b but not c\n"); err == nil {
		t.Error("unparenthesised mixed operators now parse: the helper relations may no longer be needed")
	}
}

// normalise sets This where a parsed proto left it nil, as Build will (S4).
func normalise(m *openfgav1.AuthorizationModel) {
	for _, td := range m.GetTypeDefinitions() {
		for _, us := range td.GetRelations() {
			if t, ok := us.GetUserset().(*openfgav1.Userset_This); ok && t.This == nil {
				t.This = &openfgav1.DirectUserset{}
			}
		}
	}
}

// strip drops what the parser adds and the builders do not compare: source
// positions and the model id.
func strip(m *openfgav1.AuthorizationModel) *openfgav1.AuthorizationModel {
	c := proto.Clone(m).(*openfgav1.AuthorizationModel)
	c.Id = ""
	for _, td := range c.GetTypeDefinitions() {
		if td.GetMetadata() == nil {
			continue
		}
		td.Metadata.SourceInfo, td.Metadata.Module = nil, ""
		for _, rm := range td.GetMetadata().GetRelations() {
			rm.SourceInfo, rm.Module = nil, ""
		}
	}
	return c
}
