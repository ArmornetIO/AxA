package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/ArmornetIO/identity/authn"
)

// The host's facts join their own org's entry and no other, the host is asked
// once for every membership so it can batch, and an org the host says nothing
// about still lists: the picker can switch to it by id.
func TestListMyOrgs_DecorateOrgs(t *testing.T) {
	type facts struct {
		Admitted bool `json:"admitted"`
	}
	var asked []string
	h := &Handlers{
		Users: &stubUsers{memberships: []authn.OrgMembership{{OrgID: "org-a", Role: "admin"}, {OrgID: "org-b"}}},
		DecorateOrgs: func(_ *http.Request, s SessionView, orgIDs []string) map[string]any {
			if s.Subject != "sub" {
				t.Errorf("decorated for subject %q", s.Subject)
			}
			asked = append(asked, orgIDs...)
			return map[string]any{"org-a": facts{Admitted: true}}
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/orgs", nil)
	req = req.WithContext(context.WithValue(req.Context(), sessionKey{}, authn.SessionRecord{Subject: "sub"}))
	rec := httptest.NewRecorder()
	h.handleListMyOrgs(rec, req)

	var resp struct {
		Orgs []struct {
			OrgID    string `json:"org_id"`
			Role     string `json:"role"`
			Admitted *bool  `json:"admitted"`
		} `json:"orgs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(asked, []string{"org-a", "org-b"}) {
		t.Fatalf("asked about %v in one call, want both memberships", asked)
	}
	if len(resp.Orgs) != 2 {
		t.Fatalf("got %d orgs, want 2: %s", len(resp.Orgs), rec.Body)
	}
	a, b := resp.Orgs[0], resp.Orgs[1]
	if a.Role != "admin" || a.Admitted == nil || !*a.Admitted {
		t.Fatalf("org-a lost its entry or its facts: %s", rec.Body)
	}
	if b.OrgID != "org-b" || b.Admitted != nil {
		t.Fatalf("org-b should list bare: %s", rec.Body)
	}
}
