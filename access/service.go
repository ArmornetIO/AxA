package access

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// ServiceConfig: a nil axis is unwired; the graph fails closed, consent fails
// open visibly, the meter doesn't refuse.
type ServiceConfig struct {
	Graph   Grapher
	Consent ConsentGate
	Tiers   Tiers
	Meter   Meter
	Sink    Sink
	Index   CorrelationIndexer
	Seal    OriginSealer
}

// Service is StandardEvaluators assembled once, so a host wires ports, not a pipeline.
type Service struct {
	pipeline *Pipeline
}

func NewService(cfg ServiceConfig) *Service {
	return &Service{pipeline: &Pipeline{
		Evaluators: StandardEvaluators(cfg.Consent, cfg.Tiers, cfg.Meter, cfg.Graph),
		Sink:       cfg.Sink,
		Index:      cfg.Index,
		Seal:       cfg.Seal,
	}}
}

// Authorize stamps the caller's span (so a decision id finds its trace) and opens
// none: a decision is a fact, not work.
func (s *Service) Authorize(ctx context.Context, req Request) Decision {
	d := s.pipeline.Authorize(ctx, req)
	trace.SpanFromContext(ctx).SetAttributes(
		attribute.String("authz.decision.id", d.ID),
		attribute.String("authz.outcome", string(d.Outcome)),
		attribute.String("authz.reason", d.Reason),
	)
	return d
}
