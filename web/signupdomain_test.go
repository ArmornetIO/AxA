package web_test

import (
	"testing"

	"github.com/ArmornetIO/axa/web"
)

func TestSignupDomainAllowed(t *testing.T) {
	cases := []struct {
		name    string
		allowed []string
		email   string
		want    bool
	}{
		{"empty allowlist is off", nil, "anyone@evil.com", true},
		{"match", []string{"acme.io"}, "ada@acme.io", true},
		{"case-insensitive both sides", []string{"AcMe.IO"}, "Ada@ACME.io", true},
		{"whitespace tolerated", []string{" acme.io "}, "ada@acme.io", true},
		{"non-match rejected", []string{"acme.io"}, "randomer@gmail.com", false},
		// A subdomain is a different tenant of DNS; matching it would let anyone
		// with mail at evil.acme.io.attacker.com style names slip through.
		{"subdomain is not a match", []string{"acme.io"}, "x@mail.acme.io", false},
		{"suffix is not a match", []string{"acme.io"}, "x@notacme.io", false},
		{"multiple domains", []string{"acme.io", "example.com"}, "x@example.com", true},
		{"no at-sign", []string{"acme.io"}, "acme.io", false},
		{"empty email", []string{"acme.io"}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := web.SignupDomainAllowed(tc.allowed, tc.email); got != tc.want {
				t.Errorf("SignupDomainAllowed(%v, %q) = %v, want %v", tc.allowed, tc.email, got, tc.want)
			}
		})
	}
}
