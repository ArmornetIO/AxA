package access

import (
	"context"
	"errors"
	"time"
)

// TokenVerifier turns a person's identity token into a verified subject. The
// host supplies it; armornet's verifies a Dex ID token for the CLI client.
type TokenVerifier interface {
	VerifySubject(ctx context.Context, token string) (string, error)
}

// Outcome has three values so a permissions bug (Refuse) never pages anyone;
// only a real dependency failure is Unavailable.
type Outcome string

const (
	// Permit allows the request.
	Permit Outcome = "permit"
	// Refuse is an authorization answer: the caller may not do this.
	Refuse Outcome = "refuse"
	// Unavailable means the answer could not be computed because something the
	// decision depends on failed. Reserved for exactly one reason.
	Unavailable Outcome = "unavailable"
)

// Reason codes are closed as a privacy control: an enum cannot carry an email.
// Never introduce a free-form reason string.
const (
	ReasonOK            = "ok"
	ReasonInvalidToken  = "invalid_token"
	ReasonNotAllowed    = "not_god_admin"
	ReasonWrongAudience = "wrong_audience"
	ReasonDisabled      = "disabled"

	// ReasonSubjectNotRepresentable is the agent case: a caller that cannot be
	// reduced to a valid Subject. A refusal, never an outage.
	ReasonSubjectNotRepresentable = "subject_not_representable"
	// ReasonInsufficientCredentialScope means the credential ceiling excludes
	// this action.
	ReasonInsufficientCredentialScope = "insufficient_credential_scope"
	// ReasonConsentRequired's value is the wire code the SPA and the Line
	// handshake share: one rule, one word on both transports.
	ReasonConsentRequired = "legal_acceptance_required"
	// ReasonConsentNotDeployed permits, visibly: 403ing the whole API over a
	// skipped wiring step is worse than no gate.
	ReasonConsentNotDeployed = "consent_not_deployed"
	// ReasonTierExcluded means an ADMITTED org reached outside the slice its
	// tier bought.
	ReasonTierExcluded = "tier_excluded"
	// ReasonNotAdmitted ("not in": holding page) is not tier_excluded ("in, not
	// this part"). The value is the wire code the SPA branches on.
	ReasonNotAdmitted = "alpha_access_required"
	// ReasonQuotaExhausted's value is a wire code the console reads, and it stays
	// 429 at the front door: clients read that status.
	ReasonQuotaExhausted = "quota_exceeded"
	// ReasonNoOrgScope means authenticated but acting in no organization. The
	// identity is fine and the scope is not, so re-authenticating cannot fix it.
	ReasonNoOrgScope = "no_org_scope"
	// ReasonRelationAbsent means the caller lacks the required relationship.
	ReasonRelationAbsent = "relation_absent"
	// ReasonNoPolicyForRoute is deny-by-default on an undeclared route. It is a
	// reported policy gap, deliberately distinct from a permission failure.
	ReasonNoPolicyForRoute = "no_policy_for_route"
	// ReasonOperatorOverride is always recorded, or nobody could audit it. Never
	// stored as a relationship: every deployment sharing the graph would see it.
	ReasonOperatorOverride = "operator_override"
	// ReasonGraphUnavailable is a genuine transport failure to the graph.
	ReasonGraphUnavailable = "graph_unavailable"
	// ReasonConsentUnevaluable fails CLOSED (a DB blip must not open the gate). A
	// deliberate second outage reason, so the record names the right dependency.
	ReasonConsentUnevaluable = "consent_unevaluable"
)

// outages: adding a reason here deliberately says "this wakes someone up".
var outages = map[string]bool{
	ReasonGraphUnavailable:   true,
	ReasonConsentUnevaluable: true,
}

// OutcomeFor defaults to Refuse, so a new reason can never silently page anyone.
func OutcomeFor(reason string) Outcome {
	switch {
	case reason == ReasonOK, reason == ReasonConsentNotDeployed, reason == ReasonOperatorOverride:
		return Permit
	case outages[reason]:
		return Unavailable
	default:
		return Refuse
	}
}

// Decision's json tags are the audit shape, pinned by a guard test; Assertion is
// set only on allow.
type Decision struct {
	ID string `json:"id"`
	// Subject is absent for an unauthenticated refusal — there is no caller to
	// name, and inventing one would be worse than recording none.
	Subject  *Subject  `json:"subject,omitempty"`
	Action   Action    `json:"action"`
	Resource Resource  `json:"resource"`
	Outcome  Outcome   `json:"outcome"`
	Reason   string    `json:"reason"`
	At       time.Time `json:"at"`
	// Predicates are those reached, in order; an unreached one is ABSENT, never passed.
	Predicates []Verdict `json:"predicates,omitempty"`
	// CorrelationKey is a rotating, non-reversible stand-in for the request
	// origin, so repeated attempts group without the origin being stored.
	CorrelationKey string `json:"correlation_key,omitempty"`
	// SealedOrigin is the origin encrypted with the host's cipher, recoverable
	// only through a recorded unsealing.
	SealedOrigin []byte `json:"sealed_origin,omitempty"`

	// Allowed is kept in step with Outcome for callers not yet migrated off the
	// boolean. Not part of the record: it says nothing Outcome does not.
	Allowed bool `json:"-"`
	// Never stored: an assertion is a bearer token; the jti (ID) ties the record.
	Audience  string    `json:"-"`
	Source    string    `json:"-"`
	Assertion string    `json:"-"`
	ExpiresAt time.Time `json:"-"`
}

// AssertionMinter answers "may this person reach this destination?" and, when yes,
// signs the assertion that says so.
type AssertionMinter struct {
	Verify   TokenVerifier
	Allow    func(subject string) bool
	Keys     *KeySet
	Audience string        // the one destination this minter speaks for
	TTL      time.Duration // defaults to MaxTTL
	Now      func() time.Time
}

// Mint never returns an allow without a minted assertion. src is recorded,
// never trusted: it is whatever the caller reports as the agent it came through.
func (d *AssertionMinter) Mint(ctx context.Context, token, aud, src string) Decision {
	out := Decision{Audience: aud, Source: src}
	if d == nil || d.Allow == nil || !d.Keys.CanSign() {
		return out.settle(ReasonDisabled)
	}
	if aud != d.Audience {
		return out.settle(ReasonWrongAudience)
	}
	sub, err := d.Verify.VerifySubject(ctx, token)
	if err != nil || sub == "" {
		return out.settle(ReasonInvalidToken)
	}
	out.Subject = &Subject{Kind: KindPerson, ID: sub}
	if !d.Allow(sub) {
		return out.settle(ReasonNotAllowed)
	}
	ttl := d.TTL
	if ttl <= 0 {
		ttl = MaxTTL
	}
	now := time.Now()
	if d.Now != nil {
		now = d.Now()
	}
	tok, exp, err := d.Keys.Mint(sub, aud, src, ttl, now)
	if err != nil {
		return out.settle(ReasonDisabled)
	}
	// The jti is read back rather than threaded out of Mint so the audit record
	// carries exactly what the destination will see.
	if c, err := d.Keys.Verify(tok, aud, now); err == nil {
		out.ID = c.ID
	}
	out.Assertion, out.ExpiresAt = tok, exp
	return out.settle(ReasonOK)
}

// settle records the reason and derives everything that follows from it, so no
// call site can set an outcome that disagrees with its own reason.
func (d Decision) settle(reason string) Decision {
	d.Reason = reason
	d.Outcome = OutcomeFor(reason)
	d.Allowed = d.Outcome == Permit
	return d
}

// ErrNoToken is returned by verifiers given an empty token.
var ErrNoToken = errors.New("access: no token")
