package authz

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/trace"
)

// ErrForbidden is returned by Checker.Check when the FGA decision is deny.
var ErrForbidden = errors.New("forbidden")

// ErrCheckBackend wraps every non-deny Check failure in both clients, so a 503
// is positively known, never inferred from "not ErrForbidden".
var ErrCheckBackend = errors.New("authz: check backend failure")

// CheckRequest is the input type passed to FGAClientIface.Check.
// Defined here so callers and stubs share one type without importing the SDK.
type CheckRequest struct {
	User             string
	Relation         string
	Object           string
	ContextualTuples []ContextualTuple
}

// Tuple's json tags are load-bearing: the admin tuple browser reads and posts
// this lowercase shape.
type Tuple struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

// FGAClientIface is a minimal interface over the OpenFGA SDK client.
// The real implementation wraps github.com/openfga/go-sdk; tests use a stub.
type FGAClientIface interface {
	Check(ctx context.Context, req CheckRequest) (bool, error)
	// WriteTuples writes relationship tuples to the FGA store.
	WriteTuples(ctx context.Context, tuples []Tuple) error
	// DeleteTuples removes relationship tuples from the FGA store.
	DeleteTuples(ctx context.Context, tuples []Tuple) error
	// ReadTuples lists stored tuples, optionally filtered by user/relation/object.
	// Empty strings mean "no filter" on that field.
	ReadTuples(ctx context.Context, user, relation, object string) ([]Tuple, error)
	// ReadModelDSL is what is loaded, not a file that could drift.
	ReadModelDSL(ctx context.Context) (string, error)
}

// Checker performs OpenFGA authorization checks using lazy contextual tuples
// derived from IDP group claims. No tuples are written to the FGA store.
type Checker struct {
	client FGAClientIface
	mapper *ClaimMapper
	logger otellog.Logger
}

// NewChecker constructs a Checker. All three arguments are required.
func NewChecker(client FGAClientIface, mapper *ClaimMapper, logger otellog.Logger) *Checker {
	return &Checker{client: client, mapper: mapper, logger: logger}
}

// Check returns nil, ErrForbidden, ErrNotRepresentable or the client error;
// groups become contextual tuples.
func (c *Checker) Check(ctx context.Context, sub Subject, groups []string, relation, objectType, objectID string) error {
	user, err := sub.Graph()
	if err != nil {
		// A caller that cannot be represented is refused, never reported as a
		// backend failure — the graph was never asked.
		return err
	}
	ctx, span := otel.Tracer("armornet/authz").Start(ctx, "authz.check",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("authz.subject", user),
			attribute.String("authz.relation", relation),
			attribute.String("authz.object_type", objectType),
			attribute.String("authz.object_id", objectID),
		),
	)
	defer span.End()

	tuples := c.mapper.TuplesForGroups(user, groups)

	object := objectType + ":" + objectID
	req := CheckRequest{
		User:             user,
		Relation:         relation,
		Object:           object,
		ContextualTuples: tuples,
	}

	allowed, err := c.client.Check(ctx, req)
	span.SetAttributes(attribute.Bool("authz.allow", allowed && err == nil))
	c.emit(ctx, user, relation, object, allowed, err)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	if !allowed {
		span.SetStatus(codes.Error, "forbidden")
		return ErrForbidden
	}
	return nil
}

func (c *Checker) emit(ctx context.Context, subject, relation, object string, allowed bool, clientErr error) {
	severity := otellog.SeverityInfo
	if !allowed || clientErr != nil {
		severity = otellog.SeverityWarn
	}

	var rec otellog.Record
	rec.SetTimestamp(time.Now())
	rec.SetSeverity(severity)
	rec.SetBody(attribute.StringValue("authz.decision"))
	rec.AddAttributes(
		attribute.String("authz.subject", subject),
		attribute.String("authz.relation", relation),
		attribute.String("authz.object", object),
		attribute.Bool("authz.allow", allowed && clientErr == nil),
	)
	if clientErr != nil {
		rec.AddAttributes(attribute.String("error.message", clientErr.Error()))
	}
	c.logger.Emit(ctx, rec)
}
