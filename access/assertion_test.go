package access

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func newKey(t *testing.T, kid string) (signing, verify string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.StdEncoding.EncodeToString
	return kid + ":" + enc(priv.Seed()), kid + ":" + enc(pub)
}

func mustKeys(t *testing.T, signing, verify string) *KeySet {
	t.Helper()
	ks, err := ParseKeySet(signing, verify)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

var now = time.Unix(1_800_000_000, 0)

func TestRoundTrip(t *testing.T) {
	s, _ := newKey(t, "k1")
	ks := mustKeys(t, s, "")
	tok, exp, err := ks.Mint("dex|alice", "god.dev", "agent:ops:1", MaxTTL, now)
	if err != nil {
		t.Fatal(err)
	}
	if !exp.Equal(now.Add(MaxTTL)) {
		t.Fatalf("exp = %s", exp)
	}
	c, err := ks.Verify(tok, "god.dev", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "dex|alice" || c.Source != "agent:ops:1" || c.ID == "" {
		t.Fatalf("claims = %+v", c)
	}
}

func TestMintRefusesLongTTL(t *testing.T) {
	s, _ := newKey(t, "k1")
	if _, _, err := mustKeys(t, s, "").Mint("a", "b", "", MaxTTL+time.Second, now); err == nil {
		t.Fatal("minted past MaxTTL")
	}
}

// forge builds a token with an arbitrary header and claims, signed by priv (or
// unsigned when priv is nil), to drive the refusals Mint would never produce.
func forge(t *testing.T, hdr map[string]string, c Claims, priv ed25519.PrivateKey) string {
	t.Helper()
	h, _ := json.Marshal(hdr)
	b, _ := json.Marshal(c)
	signing := b64(h) + "." + b64(b)
	if priv == nil {
		return signing + "."
	}
	return signing + "." + b64(ed25519.Sign(priv, []byte(signing)))
}

func TestVerifyRefusals(t *testing.T) {
	s, _ := newKey(t, "k1")
	ks := mustKeys(t, s, "")
	good, _, _ := ks.Mint("dex|alice", "god.dev", "", MaxTTL, now)

	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	valid := Claims{Issuer: Issuer, Subject: "dex|alice", Audience: "god.dev", IssuedAt: now.Unix(), Expiry: now.Add(time.Minute).Unix(), ID: "x"}

	cases := map[string]struct {
		tok  string
		aud  string
		at   time.Time
		want error
	}{
		"wrong audience":       {good, "god.stage", now, ErrInvalid},
		"expired past leeway":  {good, "god.dev", now.Add(MaxTTL + Leeway + time.Second), ErrExpired},
		"alg none":             {forge(t, map[string]string{"alg": "none", "typ": "JWT", "kid": "k1"}, valid, nil), "god.dev", now, ErrInvalid},
		"alg HS256":            {forge(t, map[string]string{"alg": "HS256", "typ": "JWT", "kid": "k1"}, valid, otherPriv), "god.dev", now, ErrInvalid},
		"unknown kid":          {forge(t, map[string]string{"alg": alg, "typ": "JWT", "kid": "k9"}, valid, otherPriv), "god.dev", now, ErrInvalid},
		"signed by other key":  {forge(t, map[string]string{"alg": alg, "typ": "JWT", "kid": "k1"}, valid, otherPriv), "god.dev", now, ErrInvalid},
		"tampered claims":      {strings.Replace(good, strings.Split(good, ".")[1], b64([]byte(`{"iss":"armornet-access","sub":"dex|mallory","aud":"god.dev","iat":1800000000,"exp":1800000060,"jti":"x"}`)), 1), "god.dev", now, ErrInvalid},
		"not three segments":   {"a.b", "god.dev", now, ErrInvalid},
		"empty verifier aud":   {good, "", now, ErrInvalid},
		"issued in the future": {good, "god.dev", now.Add(-Leeway - time.Second), ErrInvalid},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ks.Verify(c.tok, c.aud, c.at); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

// A leaked signing key must not mint something that outlives MaxTTL.
func TestVerifyRefusesOverlongLifetime(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ks := mustKeys(t, "", "k1:"+base64.StdEncoding.EncodeToString(pub))
	long := Claims{Issuer: Issuer, Subject: "s", Audience: "a", IssuedAt: now.Unix(), Expiry: now.Add(24 * time.Hour).Unix(), ID: "x"}
	tok := forge(t, map[string]string{"alg": alg, "typ": "JWT", "kid": "k1"}, long, priv)
	if _, err := ks.Verify(tok, "a", now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("overlong token accepted: %v", err)
	}
}

// Rotation: a token from the previous key verifies while that key is listed,
// and stops the moment it is removed.
func TestRotation(t *testing.T) {
	oldSign, oldVerify := newKey(t, "k1")
	newSign, _ := newKey(t, "k2")
	tok, _, _ := mustKeys(t, oldSign, "").Mint("s", "a", "", MaxTTL, now)

	during := mustKeys(t, newSign, oldVerify)
	if _, err := during.Verify(tok, "a", now); err != nil {
		t.Fatalf("old key refused during rotation: %v", err)
	}
	after := mustKeys(t, newSign, "")
	if _, err := after.Verify(tok, "a", now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("old key still accepted after removal: %v", err)
	}
}

func TestParseKeySetRejectsBadKeys(t *testing.T) {
	for _, bad := range []struct{ s, v string }{
		{"k1:not-base64!", ""},
		{"nokid", ""},
		{"k1:" + base64.StdEncoding.EncodeToString([]byte("short")), ""},
		{"", "k1:" + base64.StdEncoding.EncodeToString([]byte("short"))},
	} {
		if _, err := ParseKeySet(bad.s, bad.v); err == nil {
			t.Errorf("ParseKeySet(%q, %q) accepted", bad.s, bad.v)
		}
	}
}
