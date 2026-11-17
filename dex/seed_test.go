package dex

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/lib/pq"

	"github.com/ArmornetIO/axa"
)

// Two servers seeding one database: the loser of the serialization race runs
// its seeder again; any other failure stops startup at once.
func TestSeed_RetriesOnlyASerializationFailure(t *testing.T) {
	calls := 0
	racy := axa.Named("racy", func(context.Context, axa.Broker) error {
		calls++
		if calls < 3 {
			return fmt.Errorf("update client uploading: %w", &pq.Error{Code: "40001"})
		}
		return nil
	})
	if err := seed(context.Background(), racy, nil); err != nil || calls != 3 {
		t.Fatalf("err %v after %d calls, want success on the third", err, calls)
	}

	calls = 0
	broken := axa.Named("broken", func(context.Context, axa.Broker) error {
		calls++
		return errors.New("bad config")
	})
	if err := seed(context.Background(), broken, nil); err == nil || calls != 1 {
		t.Fatalf("err %v after %d calls, want one failed call", err, calls)
	}
}
