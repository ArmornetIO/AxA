package ginauthz

import "github.com/gin-gonic/gin"

// Principal arrives fully resolved by the host; the Authorizer never re-resolves
// org membership.
type Principal struct {
	// Subject is the Dex sub, the god-admin allowlist key.
	Subject string
	// UserID is the FGA subject ("user:<id>"); empty if unprovisioned.
	UserID string
	OrgIDs []string
	// ActiveOrgID backs "@org_id"; empty when ambiguous, and "@org_id" then denies.
	ActiveOrgID string
	// Groups are armornet:org:<org>:<role> contextual-tuple sources.
	Groups []string
	// Scopes are PAT scopes; nil for sessions.
	Scopes []string
	IsPAT  bool
	// IsAgent is a client-credentials machine; KindAgentIngest requires it so a
	// human session cannot post as an agent.
	IsAgent bool
	// AgentID is the bare uuid, never "agent:<org>:<uuid>": the graph cannot parse ':'.
	AgentID string
}

// Scoped makes Rule.Scope apply (PATs, and agents, whose empty list refuses any
// scoped route). Derived so no constructor can forget it.
func (p Principal) Scoped() bool { return p.IsPAT || p.IsAgent }

func Session(subject, userID, activeOrgID string, orgIDs, groups []string) Principal {
	return Principal{
		Subject: subject, UserID: userID, ActiveOrgID: activeOrgID,
		OrgIDs: orgIDs, Groups: groups,
	}
}

func PAT(subject, userID, activeOrgID string, orgIDs, groups, scopes []string) Principal {
	p := Session(subject, userID, activeOrgID, orgIDs, groups)
	p.IsPAT, p.Scopes = true, scopes
	return p
}

// Agent takes the org from its own verified token: a machine has no users row.
func Agent(subject, agentID, orgID string) Principal {
	return Principal{
		Subject: subject, ActiveOrgID: orgID, OrgIDs: []string{orgID},
		IsAgent: true, AgentID: agentID,
	}
}

// PrincipalExtractor's ok is false when the request carries no valid identity.
type PrincipalExtractor interface {
	Principal(c *gin.Context) (Principal, bool)
}
