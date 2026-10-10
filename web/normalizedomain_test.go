package web_test

import (
	"errors"
	"testing"

	"github.com/ArmornetIO/identity/web"
)

func TestNormalizeDomain(t *testing.T) {
	cases := []struct {
		in, want string
		err      error
	}{
		{"Acme.COM", "acme.com", nil},
		{" @acme.com. ", "acme.com", nil},
		{"eng.acme.co.uk", "eng.acme.co.uk", nil},
		{"münchen.de", "xn--mnchen-3ya.de", nil},
		{"", "", web.ErrInvalidDomain},
		{"acme..com", "", web.ErrInvalidDomain},
		{"-acme.com", "", web.ErrInvalidDomain},
		{"acme.com/x", "", web.ErrInvalidDomain},
		{"*.acme.com", "", web.ErrInvalidDomain},
		{"user@acme.com", "", web.ErrInvalidDomain},
		{"localhost", "", web.ErrSharedDomain},
		{"com", "", web.ErrSharedDomain},
		{"co.uk", "", web.ErrSharedDomain},
		{"github.io", "", web.ErrSharedDomain},
		{"gmail.com", "", web.ErrSharedDomain},
		{"GMAIL.com", "", web.ErrSharedDomain},
	}
	for _, tc := range cases {
		got, err := web.NormalizeDomain(tc.in)
		if got != tc.want || !errors.Is(err, tc.err) {
			t.Errorf("NormalizeDomain(%q) = %q, %v; want %q, %v", tc.in, got, err, tc.want, tc.err)
		}
	}
}
