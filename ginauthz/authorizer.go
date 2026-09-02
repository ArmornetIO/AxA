package ginauthz

import "context"

// Request carries the matched Pattern, never the raw path: that is decoded,
// attacker-chosen bytes with no place in a decision or a record.
type Request struct {
	Principal Principal
	Rule      Rule
	// ObjectID is empty when the spec did not resolve (typically no org).
	ObjectID string
	Method   string
	Pattern  string
	// Operator comes from the host's allowlist, never a stored relationship.
	Operator bool
	// Origin is for correlation and sealing only; never stored as given.
	Origin string
}

// Authorizer is the ONLY thing that may refuse. identity/access implements it; the
// host wires it in, since this module depends on gin alone.
type Authorizer interface {
	Authorize(ctx context.Context, req Request) Verdict
}
