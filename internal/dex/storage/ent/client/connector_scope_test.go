// ARMORNET FORK: this whole file is armornet's, with no upstream counterpart.
// Keep it on an upstream Dex pull.
package client

import "testing"

// The embedded instance has no org and must find an org-claimed connector by id;
// filtering on an empty org_id forced every org connector to stay global.
func TestConnectorScope(t *testing.T) {
	if got := (&Database{}).connectorScope(); len(got) != 0 {
		t.Errorf("no-org scope has %d predicates, want none", len(got))
	}
	if got := (&Database{orgID: "org-1"}).connectorScope(); len(got) != 1 {
		t.Errorf("org scope has %d predicates, want one", len(got))
	}
}
