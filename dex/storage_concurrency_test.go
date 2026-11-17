package dex

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	dexstorage "github.com/ArmornetIO/axa/internal/dex/storage"
)

// Concurrent sign-ins must not fail each other. Storage transactions are
// SERIALIZABLE, and on a small table Postgres's predicate locks cover whole
// pages, so two logins touching different auth requests still abort one
// another with 40001. Each sign-in finishes with exactly this update
// (finalizeLogin), and an aborted one was a "Login error" page.
//
// Needs a database with the armornet schema applied; it writes and then
// deletes its own rows.
//
//	DEX_TEST_DATABASE_URL=postgres://…/armornet_e2e?sslmode=disable go test ./dex/ -run Concurrent
func TestConcurrentAuthRequestUpdates(t *testing.T) {
	dsn := os.Getenv("DEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("DEX_TEST_DATABASE_URL unset")
	}
	s, err := newStorage(dsn, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()

	const logins = 16
	ids := make([]string, logins)
	for i := range ids {
		ids[i] = uuid.NewString()
		if err := s.CreateAuthRequest(ctx, dexstorage.AuthRequest{
			ID: ids[i], ClientID: "concurrency-test", ResponseTypes: []string{"code"},
			Scopes: []string{"openid"}, RedirectURI: "http://localhost/callback",
			Expiry: time.Now().Add(time.Minute), HMACKey: []byte("k"),
		}); err != nil {
			t.Fatalf("create auth request: %v", err)
		}
		t.Cleanup(func() { _ = s.DeleteAuthRequest(context.Background(), ids[i]) })
	}

	var wg sync.WaitGroup
	errs := make(chan error, logins)
	start := make(chan struct{})
	for i, id := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- s.UpdateAuthRequest(ctx, id, func(a dexstorage.AuthRequest) (dexstorage.AuthRequest, error) {
				a.LoggedIn = true
				a.ConnectorID = "github"
				// User id only: the other claim columns must be sealed, and no
				// sealer is wired here.
				a.Claims = dexstorage.Claims{UserID: fmt.Sprint(i)}
				return a, nil
			})
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("a concurrent sign-in failed: %v", err)
		}
	}

	for _, id := range ids {
		a, err := s.GetAuthRequest(ctx, id)
		if err != nil || !a.LoggedIn {
			t.Errorf("auth request %s: logged_in=%v err=%v", id, a.LoggedIn, err)
		}
	}
}
