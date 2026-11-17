package fga

import (
	"context"
	"fmt"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	parser "github.com/openfga/language/pkg/go/transformer"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/ArmornetIO/axa/authz"
)

// OpenFGA caps a Read page at 100; one page once truncated the admin tuple
// browser, so reads page to exhaustion.
const readPageSize = 100

type inProcessClient struct {
	svr interface {
		Check(context.Context, *openfgav1.CheckRequest) (*openfgav1.CheckResponse, error)
		Write(context.Context, *openfgav1.WriteRequest) (*openfgav1.WriteResponse, error)
		Read(context.Context, *openfgav1.ReadRequest) (*openfgav1.ReadResponse, error)
		ReadAuthorizationModel(context.Context, *openfgav1.ReadAuthorizationModelRequest) (*openfgav1.ReadAuthorizationModelResponse, error)
	}
	storeID string
	modelID string
}

func (c *inProcessClient) Check(ctx context.Context, req authz.CheckRequest) (bool, error) {
	tupleKeys := make([]*openfgav1.TupleKey, len(req.ContextualTuples))
	for i, t := range req.ContextualTuples {
		tupleKeys[i] = &openfgav1.TupleKey{
			User:     t.User,
			Relation: t.Relation,
			Object:   t.Object,
		}
	}

	fgaReq := &openfgav1.CheckRequest{
		StoreId:              c.storeID,
		AuthorizationModelId: c.modelID,
		TupleKey: &openfgav1.CheckRequestTupleKey{
			User:     req.User,
			Relation: req.Relation,
			Object:   req.Object,
		},
		ContextualTuples: &openfgav1.ContextualTupleKeys{
			TupleKeys: tupleKeys,
		},
	}

	resp, err := c.svr.Check(ctx, fgaReq)
	if err != nil {
		return false, fmt.Errorf("fga: check: %w: %w", authz.ErrCheckBackend, err)
	}
	return resp.GetAllowed(), nil
}

func (c *inProcessClient) WriteTuples(ctx context.Context, tuples []authz.Tuple) error {
	writes := make([]*openfgav1.TupleKey, len(tuples))
	for i, t := range tuples {
		writes[i] = &openfgav1.TupleKey{User: t.User, Relation: t.Relation, Object: t.Object}
	}
	_, err := c.svr.Write(ctx, &openfgav1.WriteRequest{
		StoreId:              c.storeID,
		AuthorizationModelId: c.modelID,
		// Idempotent: two writers granting the same edge (a create racing a boot
		// backfill) must both succeed, not fail the whole batch.
		Writes: &openfgav1.WriteRequestWrites{TupleKeys: writes, OnDuplicate: "ignore"},
	})
	if err != nil {
		return fmt.Errorf("fga: write tuples: %w", err)
	}
	return nil
}

func (c *inProcessClient) ReadTuples(ctx context.Context, user, relation, object string) ([]authz.Tuple, error) {
	var out []authz.Tuple
	token := ""
	for {
		req := &openfgav1.ReadRequest{
			StoreId:           c.storeID,
			PageSize:          wrapperspb.Int32(readPageSize),
			ContinuationToken: token,
		}
		// Read rejects a tuple_key filter without an object, so without one we read
		// everything and filter user/relation below.
		if object != "" {
			req.TupleKey = &openfgav1.ReadRequestTupleKey{User: user, Relation: relation, Object: object}
		}
		resp, err := c.svr.Read(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("fga: read tuples: %w", err)
		}
		for _, t := range resp.GetTuples() {
			k := t.GetKey()
			if object == "" && user != "" && k.GetUser() != user {
				continue
			}
			if object == "" && relation != "" && k.GetRelation() != relation {
				continue
			}
			out = append(out, authz.Tuple{User: k.GetUser(), Relation: k.GetRelation(), Object: k.GetObject()})
		}
		// An unchanged token means the server stopped advancing; don't spin.
		next := resp.GetContinuationToken()
		if next == "" || next == token {
			break
		}
		token = next
	}
	if out == nil {
		out = []authz.Tuple{}
	}
	return out, nil
}

// ReadModelDSL renders the loaded model, so the admin browser shows what runs.
func (c *inProcessClient) ReadModelDSL(ctx context.Context) (string, error) {
	resp, err := c.svr.ReadAuthorizationModel(ctx, &openfgav1.ReadAuthorizationModelRequest{
		StoreId: c.storeID,
		Id:      c.modelID,
	})
	if err != nil {
		return "", fmt.Errorf("fga: read authorization model: %w", err)
	}
	dsl, err := parser.TransformJSONProtoToDSL(resp.GetAuthorizationModel())
	if err != nil {
		return "", fmt.Errorf("fga: model proto to dsl: %w", err)
	}
	return dsl, nil
}

func (c *inProcessClient) DeleteTuples(ctx context.Context, tuples []authz.Tuple) error {
	deletes := make([]*openfgav1.TupleKeyWithoutCondition, len(tuples))
	for i, t := range tuples {
		deletes[i] = &openfgav1.TupleKeyWithoutCondition{User: t.User, Relation: t.Relation, Object: t.Object}
	}
	_, err := c.svr.Write(ctx, &openfgav1.WriteRequest{
		StoreId:              c.storeID,
		AuthorizationModelId: c.modelID,
		Deletes:              &openfgav1.WriteRequestDeletes{TupleKeys: deletes},
	})
	if err != nil {
		return fmt.Errorf("fga: delete tuples: %w", err)
	}
	return nil
}
