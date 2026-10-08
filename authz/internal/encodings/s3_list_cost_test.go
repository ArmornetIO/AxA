package encodings

import (
	"fmt"
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/spf13/viper"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/ArmornetIO/identity/authz/internal/fgatest"
)

// The three list-shaped rules, as R8 renders them. Each is measured at its
// worst case, no match, where every element is visited.
const s3Model = `model
  schema 1.1

type user

type document
  relations
    define net_ok: [user:* with corp_network]
    define in_ok: [user:* with attr_in_string]
    define contains_ok: [user:* with contains_string]

condition corp_network(client_ip: ipaddress, allowed_cidrs: list<string>) {
  allowed_cidrs.exists(c, client_ip.in_cidr(c))
}

condition attr_in_string(attrs: map<string>, attr: string, allowed: list<string>) {
  attrs[attr] in allowed
}

condition contains_string(live: list<string>, required: string) {
  size(live) > 0 && required in live
}
`

func strs(n int, f string) []any {
	out := make([]any, n)
	for i := range n {
		out[i] = fmt.Sprintf(f, i)
	}
	return out
}

type listRule struct {
	relation, condition string
	bound               func(n int) map[string]any // on the tuple
	live                func(n int) map[string]any // in the request
}

var listRules = []listRule{
	{
		relation: "net_ok", condition: "corp_network",
		bound: func(n int) map[string]any { return map[string]any{"allowed_cidrs": strs(n, "10.%d.0.0/16")} },
		live:  func(int) map[string]any { return map[string]any{"client_ip": "192.168.1.1"} },
	},
	{
		relation: "in_ok", condition: "attr_in_string",
		bound: func(n int) map[string]any { return map[string]any{"attr": "dept", "allowed": strs(n, "dept-%d")} },
		live:  func(int) map[string]any { return map[string]any{"attrs": map[string]any{"dept": "nowhere"}} },
	},
	{
		relation: "contains_ok", condition: "contains_string",
		bound: func(int) map[string]any { return map[string]any{"required": "legal"} },
		live:  func(n int) map[string]any { return map[string]any{"live": strs(n, "group-%d")} },
	},
}

func mustStruct(t *testing.T, m map[string]any) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// maxElements is the longest list within budget; one more must Error, never Refuse.
func maxElements(t *testing.T, st *fgatest.Store, r listRule, limit int) int {
	t.Helper()
	for n := 1; n <= limit; n++ {
		obj := fmt.Sprintf("document:%s-%d", r.relation, n)
		st.MustWrite(t, &openfgav1.TupleKey{Object: obj, Relation: r.relation, User: "user:*",
			Condition: &openfgav1.RelationshipCondition{Name: r.condition, Context: mustStruct(t, r.bound(n))}})
		req := fgatest.Req(obj + "#" + r.relation + "@user:ana")
		req.Context = mustStruct(t, r.live(n))
		allowed, err := st.Check(req)
		if allowed {
			t.Fatalf("%s with %d elements: permitted with no match", r.relation, n)
		}
		if err != nil {
			return n - 1
		}
	}
	t.Fatalf("%s: no error within %d elements", r.relation, limit)
	return 0
}

func TestS3ListCost(t *testing.T) {
	srv := fgatest.Start(t)
	at := func(budget int) map[string]int {
		viper.Set("maxConditionEvaluationCost", budget) // OpenFGA reads it when a model is first loaded
		t.Cleanup(func() { viper.Set("maxConditionEvaluationCost", nil) })
		st := srv.Load(t, s3Model)
		got := map[string]int{}
		for _, r := range listRules {
			got[r.relation] = maxElements(t, st, r, 20*budget)
		}
		return got
	}
	base, raised := at(100), at(1000)
	for _, r := range listRules {
		b, x := base[r.relation], raised[r.relation]
		t.Logf("%s: %d elements at budget 100, %d at 1000 (%.1f per element at 100)", r.condition, b, x, 100/float64(b+1))
		// Kill criterion: caps derive from a per-element cost only if the
		// longest list scales with the budget.
		if ratio := float64(x) / float64(b); ratio < 8 || ratio > 12 {
			t.Errorf("%s: %d → %d elements for 10× the budget; caps must be pinned per budget, not derived", r.condition, b, x)
		}
	}
}
