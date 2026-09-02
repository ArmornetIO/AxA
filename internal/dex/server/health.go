package server

import healthpkg "github.com/ArmornetIO/ota/health"

// HealthChecker reports overall server health for the /healthz endpoint.
// Replaces the gosundheit.Health dependency — only IsHealthy() was ever called
// in production code, so a minimal interface is sufficient.
type HealthChecker interface {
	IsHealthy() bool
}

// staticHealthChecker returns a fixed health value. Used in tests and as the
// default when no HealthChecker is supplied to Config.
type staticHealthChecker struct{ healthy bool }

func (s *staticHealthChecker) IsHealthy() bool { return s.healthy }

// AlwaysHealthy returns a HealthChecker that unconditionally reports healthy.
func AlwaysHealthy() HealthChecker { return &staticHealthChecker{healthy: true} }

// AuthHealth returns a ComponentHealth derived from the sliding window of
// recent authentication attempts. Returns OK when no data has been recorded yet.
func (s *Server) AuthHealth() healthpkg.ComponentHealth {
	if s.authMetrics == nil {
		return healthpkg.ComponentHealth{Status: healthpkg.StatusOK}
	}
	return s.authMetrics.DeriveHealth(5)
}
