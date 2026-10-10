package dex

import (
	"encoding/base64"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func TestConnectorOfSubject(t *testing.T) {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendString(b, "1234567")
	b = protowire.AppendTag(b, 2, protowire.BytesType)
	b = protowire.AppendString(b, "oidc-org_7f3a91")
	sub := base64.RawURLEncoding.EncodeToString(b)

	for _, tc := range []struct{ sub, want string }{
		{sub, "oidc-org_7f3a91"},
		{"", ""},
		{"not base64!", ""},
		{"user@example.com", ""},
	} {
		if got := ConnectorOfSubject(tc.sub); got != tc.want {
			t.Errorf("ConnectorOfSubject(%q) = %q, want %q", tc.sub, got, tc.want)
		}
	}
}

func subjectOf(userID, connID string) string {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendString(b, userID)
	b = protowire.AppendTag(b, 2, protowire.BytesType)
	b = protowire.AppendString(b, connID)
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestUpstreamOfSubject(t *testing.T) {
	if id, conn := UpstreamOfSubject(subjectOf("583231", "github")); id != "583231" || conn != "github" {
		t.Fatalf("github subject = %q %q", id, conn)
	}
	if id, conn := UpstreamOfSubject(subjectOf("100000000000000000001", "google")); id != "100000000000000000001" || conn != "google" {
		t.Fatalf("google subject = %q %q", id, conn)
	}
	for _, sub := range []string{"", "not base64!", "plain-subject"} {
		if id, conn := UpstreamOfSubject(sub); id != "" || conn != "" {
			t.Errorf("%q = %q %q, want nothing", sub, id, conn)
		}
	}
}
