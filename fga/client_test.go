package fga

import (
	"context"
	"errors"
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"

	"github.com/ArmornetIO/axa/authz"
)

// fakeFGASvr returns the configured errors, to drive the error paths with no store.
type fakeFGASvr struct {
	checkErr error
	modelErr error
}

func (f fakeFGASvr) Check(context.Context, *openfgav1.CheckRequest) (*openfgav1.CheckResponse, error) {
	if f.checkErr != nil {
		return nil, f.checkErr
	}
	return &openfgav1.CheckResponse{Allowed: true}, nil
}

func (f fakeFGASvr) Write(context.Context, *openfgav1.WriteRequest) (*openfgav1.WriteResponse, error) {
	return &openfgav1.WriteResponse{}, nil
}

func (f fakeFGASvr) Read(context.Context, *openfgav1.ReadRequest) (*openfgav1.ReadResponse, error) {
	return &openfgav1.ReadResponse{}, nil
}

func (f fakeFGASvr) ReadAuthorizationModel(context.Context, *openfgav1.ReadAuthorizationModelRequest) (*openfgav1.ReadAuthorizationModelResponse, error) {
	if f.modelErr != nil {
		return nil, f.modelErr
	}
	return &openfgav1.ReadAuthorizationModelResponse{}, nil
}

// ErrCheckBackend is what the middleware maps to 503; the cause stays for logs.
func TestInProcessClient_CheckWrapsBackendError(t *testing.T) {
	backend := errors.New("store unavailable")
	c := &inProcessClient{svr: fakeFGASvr{checkErr: backend}, storeID: "s", modelID: "m"}

	_, err := c.Check(context.Background(), authz.CheckRequest{
		User: "user:alice", Relation: "admin", Object: "organization:acme",
	})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !errors.Is(err, authz.ErrCheckBackend) {
		t.Errorf("error %q does not wrap ErrCheckBackend", err)
	}
	if !errors.Is(err, backend) {
		t.Errorf("error %q does not wrap the underlying backend error", err)
	}
}

// The admin model browser must see a store error, not an empty model.
func TestInProcessClient_ReadModelDSLPropagatesReadError(t *testing.T) {
	c := &inProcessClient{svr: fakeFGASvr{modelErr: errors.New("no model in store")}, storeID: "s", modelID: "m"}

	dsl, err := c.ReadModelDSL(context.Background())
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if dsl != "" {
		t.Errorf("expected empty DSL on error, got %q", dsl)
	}
}

// pagingFGASvr serves tuples one page at a time, the way a real OpenFGA store
// does once a store holds more than a page's worth.
type pagingFGASvr struct {
	pages [][]string // each page's object names
	calls []string   // continuation token received per call
	// stuck replays the same token forever, standing in for a backend that
	// never advances.
	stuck bool
}

func (f *pagingFGASvr) Check(context.Context, *openfgav1.CheckRequest) (*openfgav1.CheckResponse, error) {
	return &openfgav1.CheckResponse{Allowed: true}, nil
}

func (f *pagingFGASvr) Write(context.Context, *openfgav1.WriteRequest) (*openfgav1.WriteResponse, error) {
	return &openfgav1.WriteResponse{}, nil
}

func (f *pagingFGASvr) ReadAuthorizationModel(context.Context, *openfgav1.ReadAuthorizationModelRequest) (*openfgav1.ReadAuthorizationModelResponse, error) {
	return &openfgav1.ReadAuthorizationModelResponse{}, nil
}

func (f *pagingFGASvr) Read(_ context.Context, req *openfgav1.ReadRequest) (*openfgav1.ReadResponse, error) {
	f.calls = append(f.calls, req.GetContinuationToken())
	if f.stuck {
		return &openfgav1.ReadResponse{
			Tuples:            []*openfgav1.Tuple{{Key: &openfgav1.TupleKey{User: "user:a", Relation: "admin", Object: "organization:x"}}},
			ContinuationToken: "same",
		}, nil
	}
	idx := len(f.calls) - 1
	if idx >= len(f.pages) {
		return &openfgav1.ReadResponse{}, nil
	}
	tuples := make([]*openfgav1.Tuple, 0, len(f.pages[idx]))
	for _, obj := range f.pages[idx] {
		tuples = append(tuples, &openfgav1.Tuple{Key: &openfgav1.TupleKey{
			User: "user:a", Relation: "admin", Object: obj,
		}})
	}
	token := ""
	if idx+1 < len(f.pages) {
		token = "page" + string(rune('1'+idx))
	}
	return &openfgav1.ReadResponse{Tuples: tuples, ContinuationToken: token}, nil
}

// Regression: the admin tuple browser showed only the first page.
func TestInProcessClient_ReadTuplesPagesToExhaustion(t *testing.T) {
	svr := &pagingFGASvr{pages: [][]string{
		{"organization:a", "organization:b"},
		{"organization:c"},
	}}
	c := &inProcessClient{svr: svr, storeID: "s", modelID: "m"}

	got, err := c.ReadTuples(context.Background(), "", "", "")
	if err != nil {
		t.Fatalf("ReadTuples: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d tuples, want 3 across both pages: %+v", len(got), got)
	}
	if len(svr.calls) != 2 {
		t.Fatalf("got %d Read calls, want 2: %q", len(svr.calls), svr.calls)
	}
	if svr.calls[0] != "" || svr.calls[1] != "page1" {
		t.Errorf("continuation tokens = %q, want [\"\" \"page1\"]", svr.calls)
	}
}

// TestInProcessClient_ReadTuplesStopsOnRepeatedToken keeps a backend that never
// advances from spinning the page loop forever.
func TestInProcessClient_ReadTuplesStopsOnRepeatedToken(t *testing.T) {
	svr := &pagingFGASvr{stuck: true}
	c := &inProcessClient{svr: svr, storeID: "s", modelID: "m"}

	got, err := c.ReadTuples(context.Background(), "", "", "")
	if err != nil {
		t.Fatalf("ReadTuples: %v", err)
	}
	if len(svr.calls) > 2 {
		t.Fatalf("page loop did not terminate: %d Read calls", len(svr.calls))
	}
	if len(got) == 0 {
		t.Error("want the tuples read before bailing out, got none")
	}
}
