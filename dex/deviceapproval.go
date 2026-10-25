package dex

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ArmornetIO/identity"
)

// A device code's sign-in is Dex's own: it proves an upstream account and
// nothing the host checks after that, such as a second factor. With
// Config.DeviceApprover set, a code completes only when someone signed in to
// the host approved it AND Dex's sign-in named that same person; without the
// second half, one person's session could approve a token for another
// person's upstream account.
//
// The host's session cookie is SameSite=Strict, so it rides the code-entry
// POST (sent from the host's own page) but not the callback, which ends a
// redirect chain that began at the upstream IdP. The approval crosses that gap
// in a sealed, short-lived Lax cookie bound to the user code.

const (
	approvalCookie = "dex_device_approval"
	approvalTTL    = 10 * time.Minute
	// The fork's status for a granted code; unexported there.
	deviceTokenComplete = "complete"
)

type deviceApproval struct {
	UserCode string `json:"u"`
	Subject  string `json:"s"`
	Expiry   int64  `json:"e"`
}

type approverKey struct{}

type deviceGate struct {
	approver func(*http.Request) string
	sealer   identity.ConfigSealer
	secure   bool
	spa      bool
	now      func() time.Time
}

func (g deviceGate) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/device/auth/verify_code"):
			if !g.approve(w, r) {
				return
			}
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/device/callback"):
			subject, ok := g.approved(r)
			http.SetCookie(w, g.cookie(r.URL.Path, "", -1))
			if !ok {
				g.refuse(w, r, "This approval expired or was made in another browser. Enter the code again.")
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), approverKey{}, subject))
		}
		next.ServeHTTP(w, r)
	})
}

func (g deviceGate) approve(w http.ResponseWriter, r *http.Request) bool {
	subject := g.approver(r)
	if subject == "" {
		g.refuse(w, r, "Sign in to Armornet in this browser first, then enter the code again.")
		return false
	}
	value, err := g.seal(deviceApproval{
		// Dex upper-cases the code before it becomes the callback's state.
		UserCode: strings.ToUpper(r.FormValue("user_code")),
		Subject:  subject,
		Expiry:   g.now().Add(approvalTTL).Unix(),
	})
	if err != nil {
		slog.ErrorContext(r.Context(), "dex: device approval not sealed", "err", err)
		g.refuse(w, r, "This server cannot approve device sign-ins.")
		return false
	}
	callback := strings.TrimSuffix(r.URL.Path, "/auth/verify_code") + "/callback"
	http.SetCookie(w, g.cookie(callback, value, int(approvalTTL.Seconds())))
	return true
}

func (g deviceGate) approved(r *http.Request) (string, bool) {
	ck, err := r.Cookie(approvalCookie)
	if err != nil {
		return "", false
	}
	a, err := g.open(ck.Value)
	if err != nil || g.now().Unix() > a.Expiry || a.UserCode != r.FormValue("state") {
		return "", false
	}
	return a.Subject, true
}

func (g deviceGate) cookie(path, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     approvalCookie,
		Value:    value,
		Path:     path,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   g.secure,
		SameSite: http.SameSiteLaxMode,
	}
}

func (g deviceGate) refuse(w http.ResponseWriter, r *http.Request, msg string) {
	if g.spa {
		q := url.Values{"code": {"403"}, "type": {http.StatusText(http.StatusForbidden)}, "msg": {msg}}
		http.Redirect(w, r, "/dex-error?"+q.Encode(), http.StatusFound)
		return
	}
	http.Error(w, msg, http.StatusForbidden)
}

func (g deviceGate) seal(a deviceApproval) (string, error) {
	if g.sealer == nil {
		return "", errors.New("no ConfigSealer to seal approvals with")
	}
	plain, err := json.Marshal(a)
	if err != nil {
		return "", err
	}
	sealed, err := g.sealer.Seal(plain)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (g deviceGate) open(value string) (deviceApproval, error) {
	var a deviceApproval
	if g.sealer == nil {
		return a, errors.New("no ConfigSealer to open approvals with")
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return a, err
	}
	plain, err := g.sealer.Open(raw)
	if err != nil {
		return a, err
	}
	return a, json.Unmarshal(plain, &a)
}

// approvedFor refuses a device grant whose ID token names anyone but the
// approver deviceGate put on ctx.
func approvedFor(ctx context.Context, tokenResponse string) error {
	want, _ := ctx.Value(approverKey{}).(string)
	if want == "" {
		return errors.New("dex: device code completed without a host approval")
	}
	var resp struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal([]byte(tokenResponse), &resp); err != nil {
		return fmt.Errorf("dex: device token response: %w", err)
	}
	got, err := unverifiedSubject(resp.IDToken)
	if err != nil {
		return err
	}
	if got != want {
		return errors.New("dex: device code signed in as someone other than its approver")
	}
	return nil
}

// unverifiedSubject reads sub without checking the signature: the token was
// minted by this process a moment ago and never left it.
func unverifiedSubject(jwt string) (string, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return "", errors.New("dex: device grant has no ID token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("dex: device ID token payload: %w", err)
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("dex: device ID token claims: %w", err)
	}
	return claims.Sub, nil
}
