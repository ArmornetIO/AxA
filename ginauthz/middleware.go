// Package ginauthz is the deny-by-default front door: it turns a request into a
// question for the Authorizer and a Verdict into a response, refusing nothing itself.
package ginauthz

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// Decision stays transport-agnostic so the decision core knows no HTTP codes.
type Decision int

const (
	Allow Decision = iota
	// Deny is authenticated but not permitted: 403.
	Deny
	// Unavailable is a check that could not run: 503.
	Unavailable
)

// Verdict's Reason is a plain string: axa/access owns the vocabulary and
// this module depends on gin alone.
type Verdict struct {
	Decision Decision
	// Reason is required unless Allow.
	Reason string
}

// PermissionChecker is the relationship axis alone (the Line live-document check
// uses it). It takes the whole Principal: only the adapter may derive a subject.
type PermissionChecker interface {
	Check(ctx context.Context, q Query) Verdict
}

// Deps are all required except GodAdmins, so a nil fails at wiring, not mid-request.
type Deps struct {
	Policy     Policy
	Principals PrincipalExtractor
	Authorizer Authorizer
	GodAdmins  map[string]struct{}
	// GodAdminRoutes false 404s every KindGodAdmin route before auth, so a
	// deployment without god-admin does not reveal the routes exist.
	GodAdminRoutes bool
}

// Middleware goes after authentication and org scoping; PrincipalExtractor reads both.
func Middleware(d Deps) gin.HandlerFunc {
	return func(c *gin.Context) {
		rule, declared := d.Policy.Lookup(c.Request.Method, c.FullPath())
		rule.Declared = declared

		// Nothing to decide, so nothing to record.
		if declared && rule.Kind == KindPublic {
			c.Next()
			return
		}

		// Before auth: a 401 or 403 would reveal the route exists.
		if declared && rule.Kind == KindGodAdmin && !d.GodAdminRoutes {
			abort(c, http.StatusNotFound, "not found")
			return
		}

		principal, authed := d.Principals.Principal(c)
		if declared && !authed {
			abort(c, http.StatusUnauthorized, "unauthenticated")
			return
		}

		_, isOperator := d.GodAdmins[principal.Subject]
		objectID, _ := resolveObjectID(c, rule.ObjectIDSpec, principal)

		v := d.Authorizer.Authorize(c.Request.Context(), Request{
			Principal: principal,
			Rule:      rule,
			ObjectID:  objectID,
			Method:    c.Request.Method,
			Pattern:   c.FullPath(),
			Operator:  isOperator,
			Origin:    c.ClientIP(),
		})

		switch v.Decision {
		case Allow:
			c.Next()
		case Deny:
			// An unrepresentable caller lands here too: a 503 would page an
			// operator for something no operator can fix.
			abortCode(c, refusalStatus(v.Reason), refusalText(v.Reason), reasonOr(v.Reason, ReasonRelationAbsent))
		default:
			abortCode(c, http.StatusServiceUnavailable, "authorization service unavailable",
				reasonOr(v.Reason, ReasonGraphUnavailable))
		}
	}
}

// refusalStatus is 403, except a spent quota: clients already read 429 for it.
func refusalStatus(reason string) int {
	if reason == ReasonQuotaExhausted {
		return http.StatusTooManyRequests
	}
	return http.StatusForbidden
}

// refusalText is prose; clients branch on the code, never on this.
func refusalText(reason string) string {
	switch reason {
	case ReasonNoPolicyForRoute:
		return "no policy for route"
	case ReasonInsufficientScope:
		return "insufficient token scope"
	case ErrCodeNoOrgScope:
		return "no organization scope on this session"
	case ReasonConsentRequired:
		return "legal acceptance required"
	case ReasonTierExcluded:
		return "not included in this plan"
	case ReasonQuotaExhausted:
		return "org quota exceeded"
	default:
		return "forbidden"
	}
}

// reasonOr: no refusal goes out without a code, whatever an adapter forgot.
func reasonOr(reason, fallback string) string {
	if reason == "" {
		return fallback
	}
	return reason
}

// orgIDSpec means "whichever org the caller is acting in".
const orgIDSpec = "@org_id"

// Copies of axa/access's reason codes (this module depends on gin alone).
// A code added there without a match here is one no client sees.
const (
	ReasonOK = "ok"
	// ErrCodeNoOrgScope is about the org, not the identity: clients say "not a
	// member" instead of bouncing to a login that changes nothing.
	ErrCodeNoOrgScope = "no_org_scope"
	// ReasonNoPolicyForRoute is a policy gap to close, not a missing role.
	ReasonNoPolicyForRoute        = "no_policy_for_route"
	ReasonInsufficientScope       = "insufficient_credential_scope"
	ReasonRelationAbsent          = "relation_absent"
	ReasonGraphUnavailable        = "graph_unavailable"
	ReasonNotGodAdmin             = "not_god_admin"
	ReasonSubjectNotRepresentable = "subject_not_representable"
	// ReasonConsentRequired is the one code the SPA redirects on; every other
	// refusal is a 403 too.
	ReasonConsentRequired = "legal_acceptance_required"
	ReasonTierExcluded    = "tier_excluded"
	ReasonQuotaExhausted  = "quota_exceeded"
)

// resolveObjectID reads ":param", "@org_id" or a literal. An empty id is passed
// on, not refused: whether it matters is the decider's call.
func resolveObjectID(c *gin.Context, spec string, p Principal) (string, bool) {
	switch {
	case strings.HasPrefix(spec, ":"):
		v := c.Param(spec[1:])
		return v, v != ""
	case spec == orgIDSpec:
		if p.ActiveOrgID == "" {
			return "", false
		}
		return p.ActiveOrgID, true
	default:
		return spec, spec != ""
	}
}

func abort(c *gin.Context, code int, msg string) {
	c.AbortWithStatusJSON(code, gin.H{"error": msg})
}

func abortCode(c *gin.Context, code int, msg, errCode string) {
	c.AbortWithStatusJSON(code, gin.H{"error": msg, "code": errCode})
}
