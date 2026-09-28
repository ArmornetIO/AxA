package access

import "context"

// Tiers is the host's: identity only asks.
type Tiers interface {
	// Includes takes the Subject because a MACHINE is never refused commercially
	// (it is deployed infra). reason: "", ReasonNotAdmitted or ReasonTierExcluded.
	Includes(ctx context.Context, s Subject, required string) (reason string, err error)
}

// Meter answers whether a metered capability is spent for the current period.
type Meter interface {
	// Exhausted reports whether the subject's organization has spent its
	// allowance of quota for the current period.
	Exhausted(ctx context.Context, s Subject, quota string) (bool, error)
}

// commercialEvaluator is tier and quota: one question to the caller, two
// reasons in the record (upgrade vs wait).
type commercialEvaluator struct {
	tiers Tiers
	meter Meter
}

// CommercialEvaluator: a nil source skips its half, so no metering never means
// refusing every metered route.
func CommercialEvaluator(t Tiers, m Meter) Evaluator {
	return commercialEvaluator{tiers: t, meter: m}
}

func (commercialEvaluator) Predicate() Predicate { return PredicateCommercial }

func (commercialEvaluator) Declared(r Rule) bool { return r.Tier != "" || r.Quota != "" }

func (e commercialEvaluator) Evaluate(ctx context.Context, req Request) Verdict {
	// Fail OPEN, unlike consent: a blip locking out every paying customer costs
	// more than briefly admitting a waitlister. Legal exposure can't be risked.
	if req.Rule.Tier != "" && e.tiers != nil {
		if reason, err := e.tiers.Includes(ctx, req.Subject, req.Rule.Tier); err == nil && reason != "" {
			return Refused(PredicateCommercial, reason)
		}
	}
	if req.Rule.Quota != "" && e.meter != nil {
		if spent, err := e.meter.Exhausted(ctx, req.Subject, req.Rule.Quota); err == nil && spent {
			return Refused(PredicateCommercial, ReasonQuotaExhausted)
		}
	}
	return Permitted(PredicateCommercial, ReasonOK)
}
