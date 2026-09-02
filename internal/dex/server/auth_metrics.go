package server

import (
	"context"
	"fmt"
	"sync"
	"time"

	healthpkg "github.com/ArmornetIO/ota/health"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	authRingSize = 60 // one bucket per minute, one hour of history

	// Error-rate thresholds for health tier derivation.
	permanentErrorRate   = 0.50 // ≥50% → PermanentError
	recoverableErrorRate = 0.10 // ≥10% → RecoverableError
)

type minBucket struct {
	minute    int64 // Unix epoch / 60
	authCount int64
	errCount  int64
	latencyMS int64 // sum
}

// AuthMetrics is a concurrent-safe ring buffer recording auth outcomes per
// minute. Call Record after each authentication attempt. DeriveHealth maps
// the sliding window to an OTel ComponentHealth.
type AuthMetrics struct {
	mu      sync.Mutex
	ring    [authRingSize]minBucket
	counter metric.Int64Counter
	errors  metric.Int64Counter
	latency metric.Int64Histogram
}

// NewAuthMetrics creates an AuthMetrics wired to the given OTel meter.
// Pass metric.NewNoopMeter() in tests.
func NewAuthMetrics(meter metric.Meter) (*AuthMetrics, error) {
	m := &AuthMetrics{}
	var err error

	m.counter, err = meter.Int64Counter("dex.auth.total",
		metric.WithDescription("Total authentication attempts"))
	if err != nil {
		return nil, fmt.Errorf("dex auth counter: %w", err)
	}

	m.errors, err = meter.Int64Counter("dex.auth.errors",
		metric.WithDescription("Failed authentication attempts"))
	if err != nil {
		return nil, fmt.Errorf("dex auth error counter: %w", err)
	}

	m.latency, err = meter.Int64Histogram("dex.auth.latency_ms",
		metric.WithDescription("Authentication callback latency"),
		metric.WithUnit("ms"))
	if err != nil {
		return nil, fmt.Errorf("dex auth latency histogram: %w", err)
	}

	return m, nil
}

// Record writes one authentication event into the current minute bucket and
// emits the corresponding OTel counters/histogram.
func (m *AuthMetrics) Record(connectorID string, latencyMS int64, isError bool) {
	now := time.Now().Unix() / 60
	idx := int(now % authRingSize)

	m.mu.Lock()
	b := &m.ring[idx]
	if b.minute != now {
		*b = minBucket{minute: now}
	}
	b.authCount++
	b.latencyMS += latencyMS
	if isError {
		b.errCount++
	}
	m.mu.Unlock()

	ctx := context.Background()
	attr := metric.WithAttributes(attribute.String("connector", connectorID))
	m.counter.Add(ctx, 1, attr)
	if isError {
		m.errors.Add(ctx, 1, attr)
	}
	m.latency.Record(ctx, latencyMS, attr)
}

// DeriveHealth aggregates the last windowMinutes buckets and returns a
// ComponentHealth suitable for registration with a health.Server.
func (m *AuthMetrics) DeriveHealth(windowMinutes int) healthpkg.ComponentHealth {
	if windowMinutes <= 0 || windowMinutes > authRingSize {
		windowMinutes = authRingSize
	}

	now := time.Now().Unix() / 60
	cutoff := now - int64(windowMinutes)

	m.mu.Lock()
	var total, errs int64
	for i := range m.ring {
		b := m.ring[i]
		if b.minute > cutoff && b.authCount > 0 {
			total += b.authCount
			errs += b.errCount
		}
	}
	m.mu.Unlock()

	if total == 0 {
		return healthpkg.ComponentHealth{Status: healthpkg.StatusOK}
	}

	rate := float64(errs) / float64(total)
	switch {
	case rate >= permanentErrorRate:
		return healthpkg.ComponentHealth{
			Status: healthpkg.StatusPermanentError,
			Reason: fmt.Sprintf("%.0f%% of %d auth attempts failed in last %dm", rate*100, total, windowMinutes),
		}
	case rate >= recoverableErrorRate:
		return healthpkg.ComponentHealth{
			Status: healthpkg.StatusRecoverableError,
			Reason: fmt.Sprintf("%.0f%% of %d auth attempts failed in last %dm", rate*100, total, windowMinutes),
		}
	default:
		return healthpkg.ComponentHealth{Status: healthpkg.StatusOK}
	}
}
