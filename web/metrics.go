package web

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// signupMeterScope is the OpenTelemetry instrumentation-scope name for account
// creation, mirroring the tracer-name registry in telemetry/CLAUDE.md.
const signupMeterScope = "armornet/auth/signup"

// AttrConnector is bounded by the Dex connector set. No subject, email or org:
// per-user labels are forbidden; who signed up is the auth.event log's job.
var AttrConnector = attribute.Key("auth.connector")

var signupsTotal metric.Int64Counter

// InitSignupMetrics is called once. Signups are events, so a counter (survives
// redeploys under increase()); the all-time total is a database question.
func InitSignupMetrics() error {
	c, err := otel.Meter(signupMeterScope).Int64Counter(
		"armornet.auth.signups",
		metric.WithDescription("Accounts created through self-service signup — counted once the org, user and membership all exist"),
		metric.WithUnit("{account}"),
	)
	if err != nil {
		return err
	}
	signupsTotal = c
	return nil
}

const sessionMeterScope = "armornet/auth/session"

// AttrRotationOutcome is what the cookie a sign-in displaced turned out to be.
var AttrRotationOutcome = attribute.Key("auth.rotation_outcome")

const (
	// RotationSelf is the same person re-authenticating — the denominator.
	RotationSelf = "self"
	// RotationSubjectMismatch is the session-fixation signal: someone else's
	// live session was in the browser a different person just signed into.
	RotationSubjectMismatch = "subject_mismatch"
	// RotationUnknown is a cookie naming no live session. Weak alone (an
	// expired tab does it); a burst is somebody trying tokens.
	RotationUnknown = "unknown"
)

var sessionRotationsTotal metric.Int64Counter

func InitSessionMetrics() error {
	c, err := otel.Meter(sessionMeterScope).Int64Counter(
		"armornet.auth.session_rotations",
		metric.WithDescription("Sign-ins that arrived carrying an existing session cookie, by what that cookie turned out to be"),
		metric.WithUnit("{rotation}"),
	)
	if err != nil {
		return err
	}
	sessionRotationsTotal = c
	return nil
}

// RecordSessionRotation is called only when a cookie was presented: a first
// sign-in displaces nothing, and counting it would bury the mismatch rate.
func RecordSessionRotation(ctx context.Context, outcome string) {
	if sessionRotationsTotal == nil {
		return
	}
	sessionRotationsTotal.Add(ctx, 1, metric.WithAttributes(AttrRotationOutcome.String(outcome)))
}

// RecordSignup counts one completed signup. Safe before InitSignupMetrics: a
// server wired without telemetry still serves signups.
func RecordSignup(ctx context.Context, connector string) {
	if signupsTotal == nil {
		return
	}
	if connector == "" {
		connector = "unknown"
	}
	signupsTotal.Add(ctx, 1, metric.WithAttributes(AttrConnector.String(connector)))
}
