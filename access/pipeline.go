package access

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync/atomic"
	"time"
)

// Pipeline is the one place a request is refused; callers act on its Decision
// alone. The zero value denies everything.
type Pipeline struct {
	// Evaluators run cheapest first; the graph, the only network call, goes last.
	Evaluators []Evaluator
	// Sink receives one record per decision. nil counts drops rather than
	// silently discarding, so "we are not recording" is a number, not a guess.
	Sink Sink
	// Index derives the correlation key from the origin. nil records none.
	Index CorrelationIndexer
	// Seal encrypts the origin for storage. nil stores none — and never the raw
	// origin.
	Seal OriginSealer

	Now   func() time.Time
	NewID func() string
}

// StandardEvaluators: ceiling, consent, commercial, graph. The order is also
// correctness: the graph's availability can't change an answer that didn't need it.
func StandardEvaluators(g ConsentGate, t Tiers, m Meter, graph Grapher) []Evaluator {
	return []Evaluator{
		IdentityEvaluator(),
		ConsentEvaluator(g),
		CommercialEvaluator(t, m),
		RelationshipEvaluator(graph),
	}
}

// Authorize is total: every failure is already a Decision, never an error. Exactly
// one record per call, whatever the outcome.
func (p *Pipeline) Authorize(ctx context.Context, req Request) Decision {
	d := Decision{
		ID:       p.newID(),
		Action:   req.Action,
		Resource: req.Resource,
		At:       p.now(),
	}
	if !req.Subject.Empty() {
		s := req.Subject
		d.Subject = &s
	}
	p.attachOrigin(&d, req.Origin)

	// Named as a policy gap, so it isn't mistaken for a missing role.
	if !req.Rule.Declared {
		return p.emit(d.settle(ReasonNoPolicyForRoute))
	}

	for _, e := range p.Evaluators {
		if e == nil || !e.Declared(req.Rule) {
			// Absent, not passed: an auditor tells "did not run" from "passed".
			continue
		}
		// Operators skip everything but consent: they accept terms like anyone
		// (decided 2026-10-04).
		if req.Operator && e.Predicate() != PredicateConsent {
			continue
		}
		v := e.Evaluate(ctx, req)
		if v.Predicate == "" {
			v.Predicate = e.Predicate()
		}
		d.Predicates = append(d.Predicates, v)
		if v.Outcome != Permit {
			// Short-circuit on the first non-permit. Everything after it is
			// genuinely unknown, which is why it is absent rather than assumed.
			return p.emit(d.settle(v.Reason))
		}
	}
	// RECORDED: no relationship backs it, so the record is its only trace.
	if req.Operator {
		return p.emit(d.settle(ReasonOperatorOverride))
	}
	return p.emit(d.settle(ReasonOK))
}

// attachOrigin never stores the raw origin: a rotating correlation key, plus an
// optional sealed copy only a recorded unsealing opens.
func (p *Pipeline) attachOrigin(d *Decision, origin string) {
	if origin == "" {
		return
	}
	if p.Index != nil {
		d.CorrelationKey = p.Index.Index(origin)
	}
	if p.Seal != nil {
		// A sealing failure costs the forensic copy, never the decision. There
		// is deliberately no fallback to storing the origin in the clear.
		if sealed, err := p.Seal.Seal(origin); err == nil {
			d.SealedOrigin = sealed
		}
	}
}

func (p *Pipeline) emit(d Decision) Decision {
	if p.Sink != nil {
		p.Sink.Emit(d)
	}
	return d
}

func (p *Pipeline) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now().UTC()
}

// fallbackID counts ids minted when the random source failed. It only has to be
// unique, not unguessable — the id addresses a row, it does not protect one.
var fallbackID atomic.Uint64

func (p *Pipeline) newID() string {
	if p.NewID != nil {
		return p.NewID()
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Empty ids would collide and ON CONFLICT DO NOTHING would drop them
		// uncounted, breaking the drop counter.
		return fmt.Sprintf("seq-%d-%d", p.now().UnixNano(), fallbackID.Add(1))
	}
	return hex.EncodeToString(b[:])
}
