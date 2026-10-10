package dex

import (
	"encoding/base64"

	"google.golang.org/protobuf/encoding/protowire"
)

// ConnectorOfSubject returns the connector id a Dex subject was issued through,
// or "" when sub is not a Dex subject.
//
// A Dex sub is base64url(proto IDTokenSubject{user_id = 1, conn_id = 2}), so
// the connector is in the subject itself and survives every session: it is
// authoritative for "how does this person sign in" in a way the sessions table,
// which expires, is not. The codec is in Dex's internal package, so this reads
// the two fields with protowire rather than importing it.
func ConnectorOfSubject(sub string) string {
	_, conn := UpstreamOfSubject(sub)
	return conn
}

// UpstreamOfSubject returns the upstream user id and connector id a Dex
// subject was issued for, or two empty strings when sub is not a Dex subject.
// For the GitHub connector the user id is the person's numeric GitHub id.
func UpstreamOfSubject(sub string) (userID, connID string) {
	b, err := base64.RawURLEncoding.DecodeString(sub)
	if err != nil {
		return "", ""
	}
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return "", ""
		}
		b = b[n:]
		if typ != protowire.BytesType {
			if n = protowire.ConsumeFieldValue(num, typ, b); n < 0 {
				return "", ""
			}
			b = b[n:]
			continue
		}
		v, n := protowire.ConsumeBytes(b)
		if n < 0 {
			return "", ""
		}
		switch num {
		case 1:
			userID = string(v)
		case 2:
			connID = string(v)
		}
		b = b[n:]
	}
	if connID == "" {
		return "", ""
	}
	return userID, connID
}
