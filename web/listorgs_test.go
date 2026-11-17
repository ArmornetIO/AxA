package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/ArmornetIO/axa/authn"
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

// namedOrgs is an OrgStore holding org-a, org-b and org-x, counting reads.
type namedOrgs struct {
	authn.OrgStore
	reads int
}

var orgNames = map[string]string{"org-a": "Alpha", "org-b": "Beta", "org-x": "Other"}

func (s *namedOrgs) GetOrg(_ context.Context, id string) (authn.Organization, error) {
	s.reads++
	if n, ok := orgNames[id]; ok {
		return authn.Organization{ID: id, Name: n, Slug: id}, nil
	}
	return authn.Organization{}, authn.ErrNoOrg
}

// batchOrgs adds GetOrgs, bound to the ids asked for as the SQL is.
type batchOrgs struct{ namedOrgs }

func (s *batchOrgs) GetOrgs(_ context.Context, ids []string) ([]authn.Organization, error) {
	s.reads++
	var out []authn.Organization
	for _, id := range ids {
		if n, ok := orgNames[id]; ok {
			out = append(out, authn.Organization{ID: id, Name: n, Slug: id})
		}
	}
	return out, nil
}

// Names are read in one query whatever the number of memberships when the
// store can batch, and per membership when it cannot; either way each entry
// carries its own org's name, and an org the caller is not in never appears.
func TestListMyOrgs_Names(t *testing.T) {
	memberships := []authn.OrgMembership{{OrgID: "org-a"}, {OrgID: "org-b"}, {OrgID: "org-gone"}}
	batch, single := &batchOrgs{}, &namedOrgs{}
	for _, tc := range []struct {
		name      string
		store     authn.OrgStore
		reads     func() int
		wantReads int
	}{
		{"batched", batch, func() int { return batch.reads }, 1},
		{"per membership", single, func() int { return single.reads }, 3},
	} {
		h := &Handlers{Users: &stubUsers{memberships: memberships}, Orgs: tc.store}
		req := httptest.NewRequest(http.MethodGet, "/orgs", nil)
		req = req.WithContext(context.WithValue(req.Context(), sessionKey{}, authn.SessionRecord{Subject: "sub"}))
		rec := httptest.NewRecorder()
		h.handleListMyOrgs(rec, req)

		var resp struct {
			Orgs []struct {
				OrgID string `json:"org_id"`
				Name  string `json:"name"`
			} `json:"orgs"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, o := range resp.Orgs {
			got = append(got, o.OrgID+"="+o.Name)
		}
		if want := []string{"org-a=Alpha", "org-b=Beta", "org-gone="}; !slices.Equal(got, want) {
			t.Errorf("%s: orgs %v, want %v", tc.name, got, want)
		}
		if tc.reads() != tc.wantReads {
			t.Errorf("%s: %d reads, want %d", tc.name, tc.reads(), tc.wantReads)
		}
	}
}
