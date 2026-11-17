package authz_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	"github.com/ArmornetIO/axa/authz"
)

var alice = authz.Subject{Type: "user", ID: "alice"}

// ---- OTel log collector (mirrors auth_test.go pattern) ----------------------

type logCollector struct {
	mu      sync.Mutex
	records []sdklog.Record
}

func (c *logCollector) OnEmit(_ context.Context, r *sdklog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, r.Clone())
	return nil
}

func (c *logCollector) Enabled(_ context.Context, _ sdklog.EnabledParameters) bool { return true }
func (c *logCollector) Shutdown(_ context.Context) error                           { return nil }
func (c *logCollector) ForceFlush(_ context.Context) error                         { return nil }

func (c *logCollector) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.records)
}

func (c *logCollector) Last() sdklog.Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.records[len(c.records)-1]
}

func recordAttrChecker(r sdklog.Record, key string) (attribute.Value, bool) {
	var val attribute.Value
	var found bool
	r.WalkAttributes(func(kv attribute.KeyValue) bool {
		if string(kv.Key) == key {
			val = kv.Value
			found = true
			return false
		}
		return true
	})
	return val, found
}

func newCheckerLogger(c *logCollector) otellog.Logger {
	lp := sdklog.NewLoggerProvider(sdklog.WithProcessor(c))
	return lp.Logger("authz-test")
}

// ---- stub FGA client --------------------------------------------------------

type stubFGAClient struct {
	allowed bool
	err     error
	lastReq authz.CheckRequest
}

func (s *stubFGAClient) Check(_ context.Context, req authz.CheckRequest) (bool, error) {
	s.lastReq = req
	return s.allowed, s.err
}

func (s *stubFGAClient) WriteTuples(_ context.Context, _ []authz.Tuple) error  { return nil }
func (s *stubFGAClient) DeleteTuples(_ context.Context, _ []authz.Tuple) error { return nil }
func (s *stubFGAClient) ReadTuples(_ context.Context, _, _, _ string) ([]authz.Tuple, error) {
	return nil, nil
}
func (s *stubFGAClient) ReadModelDSL(_ context.Context) (string, error) { return "", nil }

// ---- mapper helper ----------------------------------------------------------

func mustMapper(t *testing.T) *authz.ClaimMapper {
	t.Helper()
	m, err := authz.ParseMapper([]byte(testMappingYAML))
	require.NoError(t, err)
	return m
}

// ---- tests ------------------------------------------------------------------

func TestFGAChecker_AllowedWhenClientReturnsTrue(t *testing.T) {
	t.Parallel()
	stub := &stubFGAClient{allowed: true}
	col := &logCollector{}
	c := authz.NewChecker(stub, mustMapper(t), newCheckerLogger(col))

	err := c.Check(context.Background(), alice, []string{"armornet:org:acme:admin"}, "admin", "assessment_bank", "global")
	require.NoError(t, err)
}

func TestFGAChecker_DeniedWhenClientReturnsFalse(t *testing.T) {
	t.Parallel()
	stub := &stubFGAClient{allowed: false}
	col := &logCollector{}
	c := authz.NewChecker(stub, mustMapper(t), newCheckerLogger(col))

	err := c.Check(context.Background(), alice, []string{"armornet:org:acme:member"}, "admin", "assessment_bank", "global")
	require.Error(t, err)
	assert.ErrorIs(t, err, authz.ErrForbidden)
}

func TestFGAChecker_ClientErrorPropagates(t *testing.T) {
	t.Parallel()
	clientErr := errors.New("fga unavailable")
	stub := &stubFGAClient{err: clientErr}
	col := &logCollector{}
	c := authz.NewChecker(stub, mustMapper(t), newCheckerLogger(col))

	err := c.Check(context.Background(), alice, nil, "admin", "assessment_bank", "global")
	require.Error(t, err)
	assert.ErrorIs(t, err, clientErr)
}

func TestFGAChecker_ContextualTuplesPassedToClient(t *testing.T) {
	t.Parallel()
	stub := &stubFGAClient{allowed: true}
	col := &logCollector{}
	c := authz.NewChecker(stub, mustMapper(t), newCheckerLogger(col))

	_ = c.Check(context.Background(), alice, []string{"armornet:org:acme:admin"}, "admin", "assessment_bank", "global")

	require.Len(t, stub.lastReq.ContextualTuples, 1)
	assert.Equal(t, "user:alice", stub.lastReq.ContextualTuples[0].User)
	assert.Equal(t, "admin", stub.lastReq.ContextualTuples[0].Relation)
	assert.Equal(t, "organization:acme", stub.lastReq.ContextualTuples[0].Object)
}

func TestFGAChecker_EmitsAllowAuditRecord(t *testing.T) {
	t.Parallel()
	stub := &stubFGAClient{allowed: true}
	col := &logCollector{}
	c := authz.NewChecker(stub, mustMapper(t), newCheckerLogger(col))

	_ = c.Check(context.Background(), alice, []string{"armornet:org:acme:admin"}, "admin", "assessment_bank", "global")

	require.Equal(t, 1, col.Len())
	rec := col.Last()

	v, ok := recordAttrChecker(rec, "authz.allow")
	require.True(t, ok)
	assert.True(t, v.AsBool())

	v, ok = recordAttrChecker(rec, "authz.subject")
	require.True(t, ok)
	// The typed subject keeps a machine and a person with one uuid apart in audit.
	assert.Equal(t, "user:alice", v.AsString())
}

func TestFGAChecker_EmitsDenyAuditRecord(t *testing.T) {
	t.Parallel()
	stub := &stubFGAClient{allowed: false}
	col := &logCollector{}
	c := authz.NewChecker(stub, mustMapper(t), newCheckerLogger(col))

	_ = c.Check(context.Background(), alice, nil, "admin", "assessment_bank", "global")

	require.Equal(t, 1, col.Len())
	rec := col.Last()
	assert.Equal(t, otellog.SeverityWarn, rec.Severity())

	v, ok := recordAttrChecker(rec, "authz.allow")
	require.True(t, ok)
	assert.False(t, v.AsBool())
}

// Exactly one "user:" on the check and every contextual tuple; "user:user:<id>"
// would silently match nothing.
func TestFGAChecker_SubjectTypedExactlyOnce(t *testing.T) {
	t.Parallel()
	stub := &stubFGAClient{allowed: true}
	c := authz.NewChecker(stub, mustMapper(t), newCheckerLogger(&logCollector{}))

	err := c.Check(context.Background(), alice, []string{"armornet:org:acme:admin"}, "admin", "assessment_bank", "global")
	require.NoError(t, err)

	assert.Equal(t, "user:alice", stub.lastReq.User, "check user must be typed exactly once")
	require.Len(t, stub.lastReq.ContextualTuples, 1)
	assert.Equal(t, "user:alice", stub.lastReq.ContextualTuples[0].User, "tuple user must be typed exactly once")
}

// A backend failure stays ErrCheckBackend (503), never a deny (403).
func TestFGAChecker_BackendErrorIsDistinguishableFromDeny(t *testing.T) {
	t.Parallel()
	stub := &stubFGAClient{err: fmt.Errorf("dial tcp: connection refused: %w", authz.ErrCheckBackend)}
	c := authz.NewChecker(stub, mustMapper(t), newCheckerLogger(&logCollector{}))

	err := c.Check(context.Background(), alice, nil, "admin", "assessment_bank", "global")
	require.Error(t, err)
	assert.ErrorIs(t, err, authz.ErrCheckBackend, "backend failure must carry ErrCheckBackend")
	assert.NotErrorIs(t, err, authz.ErrForbidden, "backend failure must not look like a deny")
}
