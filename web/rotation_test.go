package web_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ArmornetIO/identity/authn"
	"github.com/ArmornetIO/identity/web"
)

func TestClassifyRotation(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	live := now.Add(time.Hour)
	expired := now.Add(-time.Hour)

	for _, tc := range []struct {
		name  string
		prior authn.SessionRecord
		err   error
		want  string
	}{
		{
			name:  "same subject re-authenticating is an ordinary switch",
			prior: authn.SessionRecord{Subject: "alice", ExpiresAt: live},
			want:  web.RotationSelf,
		},
		{
			name:  "live session for a different subject is the fixation signal",
			prior: authn.SessionRecord{Subject: "mallory", ExpiresAt: live},
			want:  web.RotationSubjectMismatch,
		},
		{
			name:  "expired session for a different subject is not an alert",
			prior: authn.SessionRecord{Subject: "previous-user", ExpiresAt: expired},
			want:  web.RotationUnknown,
		},
		{
			name: "cookie naming no session at all",
			err:  errors.New("not found"),
			want: web.RotationUnknown,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := web.ClassifyRotation(tc.prior, tc.err, "alice", now); got != tc.want {
				t.Errorf("ClassifyRotation = %q, want %q", got, tc.want)
			}
		})
	}
}
