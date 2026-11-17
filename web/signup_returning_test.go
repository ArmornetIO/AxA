package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArmornetIO/axa/authn"
)

// /login offers the global providers through signup, so a signup callback for
// an existing member must sign them in, not hand them another empty org.
func TestCallback_SignupForExistingMemberSignsIn(t *testing.T) {
	cases := []struct {
		name        string
		memberships []authn.OrgMembership
		wantOrg     string // "new" means the org the callback created
		wantCreated bool
	}{
		{"new account gets an org", nil, "new", true},
		{"one workspace signs straight in", []authn.OrgMembership{{OrgID: "org-a", Role: "owner"}}, "org-a", false},
		{"several workspaces go org-less to the picker", []authn.OrgMembership{{OrgID: "org-a"}, {OrgID: "org-b"}}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orgs := &stubOrgs{}
			users := &stubUsers{memberships: tc.memberships}
			h := &Handlers{
				PreAuth: &stubPreAuth{p: authn.PreAuthSession{
					ID: "p1", ConnectorID: "github", State: "s", Nonce: "n", IsSignup: true,
				}},
				Sessions: &stubSessions{},
				Dex:      stubDex{claims: IDTokenClaims{Subject: "sub", Nonce: "n", ConnectorID: "github"}},
				Orgs:     orgs,
				Users:    users,
			}

			req := httptest.NewRequest(http.MethodPost, "/callback", strings.NewReader(`{"code":"c","state":"s"}`))
			req.AddCookie(&http.Cookie{Name: DefaultCookies.PreAuth, Value: "p1"})
			rec := httptest.NewRecorder()
			h.handleCallback(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rec.Code, rec.Body)
			}
			var resp struct {
				OrgID      string `json:"org_id"`
				FirstLogin bool   `json:"first_login"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if (len(orgs.created) == 1) != tc.wantCreated || len(orgs.created) > 1 {
				t.Fatalf("created orgs %v, want created=%v", orgs.created, tc.wantCreated)
			}
			want := tc.wantOrg
			if want == "new" {
				want = orgs.created[0]
			}
			if resp.OrgID != want || resp.FirstLogin != tc.wantCreated {
				t.Fatalf("org_id=%q first_login=%v, want %q %v", resp.OrgID, resp.FirstLogin, want, tc.wantCreated)
			}
			if !tc.wantCreated && len(users.linked) != 0 {
				t.Fatalf("returning member was linked to %v", users.linked)
			}
		})
	}
}

// Embedding the interface leaves every method the callback does not reach
// unimplemented, so a new call into one panics instead of passing silently.

type stubDex struct{ claims IDTokenClaims }

func (d stubDex) Exchange(context.Context, string, string) (*TokenSet, error) {
	return &TokenSet{IDToken: "t", Expiry: time.Now().Add(time.Hour)}, nil
}

func (d stubDex) ValidateIDToken(context.Context, string) (*IDTokenClaims, error) {
	c := d.claims
	return &c, nil
}

type stubPreAuth struct {
	authn.PreAuthStore
	p authn.PreAuthSession
}

func (s *stubPreAuth) Get(context.Context, string) (authn.PreAuthSession, error) { return s.p, nil }
func (s *stubPreAuth) Delete(context.Context, string) error                      { return nil }

type stubSessions struct{ authn.SessionStore }

func (s *stubSessions) Create(context.Context, authn.SessionRecord, string) error { return nil }

type stubOrgs struct {
	authn.OrgStore
	created []string
}

func (s *stubOrgs) CreateOrg(_ context.Context, o authn.Organization) error {
	s.created = append(s.created, o.ID)
	return nil
}

type stubUsers struct {
	authn.UserStore
	memberships []authn.OrgMembership
	linked      []string
}

func (s *stubUsers) UpsertUser(context.Context, authn.UserRecord) (string, error) { return "u1", nil }

func (s *stubUsers) ResolveOrgScope(context.Context, string) (authn.OrgScope, error) {
	return authn.OrgScope{UserID: "u1", Provisioned: true, Memberships: append([]authn.OrgMembership{}, s.memberships...)}, nil
}

func (s *stubUsers) LinkOrgUser(_ context.Context, orgID, _, _ string) error {
	s.linked = append(s.linked, orgID)
	return nil
}
