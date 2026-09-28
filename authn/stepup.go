package authn

import (
	"context"
	"net/http"
)

// UpstreamProof is what a step-up round trip establishes: the person holding a
// live session also controls a given account at an upstream provider, right
// now. It is handed to a consumer in memory and never persisted — identity
// stores no upstream identities.
type UpstreamProof struct {
	ConnectorID string
	// UpstreamUserID is the provider's stable id (Dex federated_claims.user_id),
	// not the login, which the account holder can rename.
	UpstreamUserID string
	Username       string
	SessionSubject string
	OrgID          string
}

// StepUpConsumer acts on a proof for the intent it is registered under. It
// returns the path to send the browser to; it may set cookies on w, which is
// the only way a result survives the hop back to the page that asked.
type StepUpConsumer func(ctx context.Context, w http.ResponseWriter, p UpstreamProof) (returnTo string)
