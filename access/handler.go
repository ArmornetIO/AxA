package access

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"
)

// maxCheckBody bounds the check request. An ID token is a few KiB; anything
// much larger is not a caller we serve.
const maxCheckBody = 16 << 10

type checkRequest struct {
	SubjectToken string `json:"subject_token"`
	Audience     string `json:"audience"`
	SourceAgent  string `json:"source_agent"`
}

type checkResponse struct {
	Assertion string    `json:"assertion,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
	Error     string    `json:"error,omitempty"`
}

// CheckHandler audits every request exactly once; errors carry only a reason
// code, never what the caller sent.
func CheckHandler(d *AssertionMinter, audit func(*http.Request, Decision)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "", http.StatusMethodNotAllowed)
			return
		}
		var req checkRequest
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCheckBody))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				http.Error(w, "", http.StatusRequestEntityTooLarge)
				return
			}
			writeCheck(w, http.StatusBadRequest, checkResponse{Error: "bad_request"})
			return
		}
		dn := d.Mint(r.Context(), req.SubjectToken, req.Audience, req.SourceAgent)
		if audit != nil {
			audit(r, dn)
		}
		if dn.Allowed {
			writeCheck(w, http.StatusOK, checkResponse{Assertion: dn.Assertion, ExpiresAt: dn.ExpiresAt})
			return
		}
		writeCheck(w, statusFor(dn.Reason), checkResponse{Error: dn.Reason})
	})
}

func statusFor(reason string) int {
	switch reason {
	case ReasonInvalidToken:
		return http.StatusUnauthorized
	case ReasonNotAllowed, ReasonWrongAudience:
		return http.StatusForbidden
	default:
		return http.StatusServiceUnavailable
	}
}

func writeCheck(w http.ResponseWriter, status int, body checkResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// KeysHandler serves GET /access/v1/keys: the verify set as a JWKS, for a
// verifier outside this process.
func KeysHandler(k *KeySet) http.Handler {
	type jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		Kid string `json:"kid"`
		X   string `json:"x"`
		Use string `json:"use"`
		Alg string `json:"alg"`
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "", http.StatusMethodNotAllowed)
			return
		}
		keys := []jwk{}
		if k != nil {
			kids := make([]string, 0, len(k.verify))
			for kid := range k.verify {
				kids = append(kids, kid)
			}
			sort.Strings(kids)
			for _, kid := range kids {
				keys = append(keys, jwk{Kty: "OKP", Crv: "Ed25519", Kid: kid, Use: "sig", Alg: alg,
					X: base64.RawURLEncoding.EncodeToString([]byte(ed25519.PublicKey(k.verify[kid])))})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	})
}
