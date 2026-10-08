// Package fgatest is in-memory OpenFGA: DSL in, raw answers out. The spikes use
// it directly; authztest wraps it for built models.
package fgatest

import (
	"context"
	"slices"
	"strings"
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/openfga/language/pkg/go/transformer"
	"github.com/openfga/openfga/pkg/encoder"
	"github.com/openfga/openfga/pkg/server"
	"github.com/openfga/openfga/pkg/storage/memory"
)

// Server is one in-process OpenFGA. Stores are cheap, so tests share a server
// and take a fresh store each.
type Server struct{ svr *server.Server }

// Start runs a server that closes when t ends.
func Start(t testing.TB) *Server {
	t.Helper()
	ds := memory.New()
	svr, err := server.NewServerWithOpts(
		server.WithDatastore(ds),
		server.WithContinuationTokenSerializer(encoder.NewStringContinuationTokenSerializer()),
	)
	if err != nil {
		t.Fatalf("fgatest: start server: %v", err)
	}
	t.Cleanup(func() {
		svr.Close()
		ds.Close()
	})
	return &Server{svr: svr}
}

// Store is a fresh store holding one model.
type Store struct {
	svr         *server.Server
	ID, ModelID string
}

// Load creates a store and writes the model parsed from dsl.
func (s *Server) Load(t testing.TB, dsl string) *Store {
	t.Helper()
	m, err := transformer.TransformDSLToProto(dsl)
	if err != nil {
		t.Fatalf("fgatest: parse model: %v", err)
	}
	return s.LoadProto(t, m)
}

// LoadProto creates a store and writes m as its model.
func (s *Server) LoadProto(t testing.TB, m *openfgav1.AuthorizationModel) *Store {
	t.Helper()
	ctx := context.Background()
	st, err := s.svr.CreateStore(ctx, &openfgav1.CreateStoreRequest{Name: "fgatest"})
	if err != nil {
		t.Fatalf("fgatest: create store: %v", err)
	}
	wm, err := s.svr.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{
		StoreId:         st.GetId(),
		SchemaVersion:   m.GetSchemaVersion(),
		TypeDefinitions: m.GetTypeDefinitions(),
		Conditions:      m.GetConditions(),
	})
	if err != nil {
		t.Fatalf("fgatest: write model: %v", err)
	}
	return &Store{svr: s.svr, ID: st.GetId(), ModelID: wm.GetAuthorizationModelId()}
}

// Write sends one write request; OpenFGA's error is returned, not fatal, so a
// test can assert that a write is refused.
func (st *Store) Write(writes []*openfgav1.TupleKey, deletes []*openfgav1.TupleKeyWithoutCondition) error {
	req := &openfgav1.WriteRequest{StoreId: st.ID, AuthorizationModelId: st.ModelID}
	if len(writes) > 0 {
		req.Writes = &openfgav1.WriteRequestWrites{TupleKeys: writes}
	}
	if len(deletes) > 0 {
		req.Deletes = &openfgav1.WriteRequestDeletes{TupleKeys: deletes}
	}
	_, err := st.svr.Write(context.Background(), req)
	return err
}

// maxTuplesPerWrite is OpenFGA's default per-request limit.
const maxTuplesPerWrite = 100

// MustWrite writes the tuples, as many requests as the limit needs, failing t
// on any error.
func (st *Store) MustWrite(t testing.TB, keys ...*openfgav1.TupleKey) {
	t.Helper()
	for chunk := range slices.Chunk(keys, maxTuplesPerWrite) {
		if err := st.Write(chunk, nil); err != nil {
			t.Fatalf("fgatest: write: %v", err)
		}
	}
}

// Reload writes a new model into this store and checks against it from now on;
// the tuples stay as they are.
func (st *Store) Reload(t testing.TB, dsl string) {
	t.Helper()
	m, err := transformer.TransformDSLToProto(dsl)
	if err != nil {
		t.Fatalf("fgatest: parse model: %v", err)
	}
	wm, err := st.svr.WriteAuthorizationModel(context.Background(), &openfgav1.WriteAuthorizationModelRequest{
		StoreId:         st.ID,
		SchemaVersion:   m.GetSchemaVersion(),
		TypeDefinitions: m.GetTypeDefinitions(),
		Conditions:      m.GetConditions(),
	})
	if err != nil {
		t.Fatalf("fgatest: write model: %v", err)
	}
	st.ModelID = wm.GetAuthorizationModelId()
}

// Check asks req against this store and its model. The error is OpenFGA's, so
// a caller can tell an evaluation error from a refusal.
func (st *Store) Check(req *openfgav1.CheckRequest) (bool, error) {
	req.StoreId, req.AuthorizationModelId = st.ID, st.ModelID
	resp, err := st.svr.Check(context.Background(), req)
	return resp.GetAllowed(), err
}

// Key parses "type:id#relation@user", where user may be a userset
// ("organization:acme#member") or a wildcard ("user:*").
func Key(s string) *openfgav1.TupleKey {
	obj, user, _ := strings.Cut(s, "@")
	object, relation, _ := strings.Cut(obj, "#")
	return &openfgav1.TupleKey{Object: object, Relation: relation, User: user}
}

// Req is the check request for "type:id#relation@user".
func Req(s string) *openfgav1.CheckRequest {
	k := Key(s)
	return &openfgav1.CheckRequest{TupleKey: &openfgav1.CheckRequestTupleKey{
		Object: k.GetObject(), Relation: k.GetRelation(), User: k.GetUser(),
	}}
}
