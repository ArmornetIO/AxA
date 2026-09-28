package access

// Sink writes async, off the request path; Dropped is what lets "every decision
// is recorded" be measured, not asserted.
type Sink interface {
	// Emit records one decision. It MUST NOT fail or delay the request.
	Emit(d Decision)
	// Dropped is the count of records that could not be written, for alerting.
	Dropped() uint64
}

// CorrelationIndexer groups one origin's attempts with a rotating key that MUST
// NOT be reversible; recovery is the sealer's, via a recorded unsealing.
type CorrelationIndexer interface {
	Index(value string) string
}

// OriginSealer is host-supplied; without one no origin is stored. It MUST NOT
// fall back to the raw origin.
type OriginSealer interface {
	Seal(plaintext string) ([]byte, error)
	// Open passes through rows written before sealing was on, until re-sealed.
	Open(sealed []byte) (string, error)
}

// discardSink counts its drops, so an unwired sink shows as not recording.
type discardSink struct{ dropped uint64 }

func (s *discardSink) Emit(Decision)   { s.dropped++ }
func (s *discardSink) Dropped() uint64 { return s.dropped }
