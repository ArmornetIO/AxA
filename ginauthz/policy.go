package ginauthz

// Kind's zero value is KindDeny, so an unset or unknown rule fails closed.
type Kind int

const (
	// KindDeny is never assigned: a forgotten field can only restrict.
	KindDeny Kind = iota
	// KindPublic needs no identity; any invite token or signature is the handler's.
	KindPublic
	KindAuthenticated
	// KindOrgRole is Relation on "@org_id" (own org) or ":org_id" (route).
	KindOrgRole
	// KindObject is Relation on ObjectType:<resolved ObjectIDSpec>.
	KindObject
	KindGodAdmin
	// KindAgentIngest needs agent claims; the org comes from the token.
	KindAgentIngest
	// KindSelf is enforced by the handler's own caller-scoped query.
	KindSelf
)

// Rule is the requirement for one (method, route pattern), and the only place a
// condition lives.
type Rule struct {
	// Declared is stamped by the front door, so an undeclared route reaches the
	// decider as a deny, not a silent absence.
	Declared bool
	Kind     Kind
	// ObjectType is the FGA type ("vendor", "organization").
	ObjectType string
	// ObjectIDSpec is ":param", "@org_id" (active org) or a literal ("global").
	ObjectIDSpec string
	Relation     string
	// Scope is a credential ceiling; "" means none.
	Scope string
	// Tier is the commercial tier required; "" means none.
	Tier string
	// Quota is the metered capability spent; "" means unmetered.
	Quota string
	// Consent requires accepted current terms. It replaced a path exemption
	// table whose holes outlived their reasons.
	Consent bool
}

// Query is a struct because four of its fields are strings, and a transposed
// pair would be a silent authorization bug.
type Query struct {
	Principal  Principal
	Relation   string
	ObjectType string
	ObjectID   string
}

func (r Rule) Query(p Principal, objectID string) Query {
	return Query{Principal: p, Relation: r.Relation, ObjectType: r.ObjectType, ObjectID: objectID}
}

// Policy keys on gin's c.FullPath() ("/api/vendors/:id"); ok=false denies.
type Policy interface {
	Lookup(method, routePattern string) (Rule, bool)
}
