package access

import "github.com/ArmornetIO/axa/authz"

// Kind is what sort of caller a Subject is. The set is closed: a third kind is
// a model change, not a new string someone passes through.
type Kind string

const (
	// KindPerson is a human caller.
	KindPerson Kind = "person"
	// KindMachine is a deployed agent acting for an organization.
	KindMachine Kind = "machine"
)

// graphType's strings belong to the .fga model and must match it; only here.
var graphType = map[Kind]string{
	KindPerson:  "user",
	KindMachine: "agent",
}

// ErrNotRepresentable is authz's own, so errors.Is matches either package; it
// maps to a refusal, never an outage.
var ErrNotRepresentable = authz.ErrNotRepresentable

// Subject is any caller: ID a bare UUID with no ':' (hence OrgID apart). It
// MUST NOT carry an email or any personal identifier.
type Subject struct {
	Kind  Kind
	ID    string
	OrgID string
}

// Empty reports whether there is no subject at all — an unauthenticated
// caller. Distinct from a subject that exists but is not representable.
func (s Subject) Empty() bool { return s.Kind == "" && s.ID == "" }

// Valid reports why a subject cannot be used, or nil.
func (s Subject) Valid() error { return s.GraphSubject().Valid() }

// GraphSubject names the caller in the graph. An unknown kind has no graph
// type, so the checker refuses it rather than guessing one.
func (s Subject) GraphSubject() authz.Subject {
	return authz.Subject{Type: graphType[s.Kind], ID: s.ID}
}

// Person returns a subject for a human caller.
func Person(id, orgID string) Subject {
	return Subject{Kind: KindPerson, ID: id, OrgID: orgID}
}

// Machine returns a subject for a deployed agent. id is the agent's bare uuid,
// never its full client id.
func Machine(id, orgID string) Subject {
	return Subject{Kind: KindMachine, ID: id, OrgID: orgID}
}
