package authz

import (
	"context"
	"encoding/json"
	"fmt"

	openfga "github.com/openfga/go-sdk"
	fgaclient "github.com/openfga/go-sdk/client"
	parser "github.com/openfga/language/pkg/go/transformer"
)

// FGAConfig holds the connection settings for the OpenFGA server.
type FGAConfig struct {
	// ApiURL is the base URL of the OpenFGA server, e.g. "http://openfga:8080".
	ApiURL string
	// StoreID is the OpenFGA store ULID.
	StoreID string
	// AuthorizationModelID is the active model ULID. If empty, FGA uses the
	// latest model in the store.
	AuthorizationModelID string
}

// sdkClient wraps *fgaclient.OpenFgaClient to satisfy FGAClientIface.
type sdkClient struct {
	inner *fgaclient.OpenFgaClient
	// modelID is the pinned authorization model ULID, if configured. When set,
	// ReadModelDSL reads exactly that model; when empty, it reads the latest.
	modelID string
}

// NewSDKClient constructs a real FGAClientIface backed by the OpenFGA Go SDK.
// Use this in production; tests inject a stub via NewChecker directly.
func NewSDKClient(cfg FGAConfig) (FGAClientIface, error) {
	c, err := fgaclient.NewSdkClient(&fgaclient.ClientConfiguration{
		ApiUrl:               cfg.ApiURL,
		StoreId:              cfg.StoreID,
		AuthorizationModelId: cfg.AuthorizationModelID,
	})
	if err != nil {
		return nil, fmt.Errorf("authz: create fga client: %w", err)
	}
	return &sdkClient{inner: c, modelID: cfg.AuthorizationModelID}, nil
}

// WriteTuples writes relationship tuples to the FGA store. An already-present
// tuple is not an error, so concurrent writers granting the same edge both succeed.
func (s *sdkClient) WriteTuples(ctx context.Context, tuples []Tuple) error {
	keys := make([]openfga.TupleKey, len(tuples))
	for i, t := range tuples {
		keys[i] = openfga.TupleKey{User: t.User, Relation: t.Relation, Object: t.Object}
	}
	_, err := s.inner.WriteTuples(ctx).Options(fgaclient.ClientWriteOptions{
		Conflict: fgaclient.ClientWriteConflictOptions{OnDuplicateWrites: fgaclient.CLIENT_WRITE_REQUEST_ON_DUPLICATE_WRITES_IGNORE},
	}).Body(keys).Execute()
	if err != nil {
		return fmt.Errorf("authz: fga write tuples: %w", err)
	}
	return nil
}

// DeleteTuples removes relationship tuples from the FGA store.
func (s *sdkClient) DeleteTuples(ctx context.Context, tuples []Tuple) error {
	keys := make([]openfga.TupleKeyWithoutCondition, len(tuples))
	for i, t := range tuples {
		keys[i] = openfga.TupleKeyWithoutCondition{User: t.User, Relation: t.Relation, Object: t.Object}
	}
	_, err := s.inner.DeleteTuples(ctx).Body(keys).Execute()
	if err != nil {
		return fmt.Errorf("authz: fga delete tuples: %w", err)
	}
	return nil
}

// OpenFGA caps a Read page at 100; one page once truncated the admin tuple
// browser, so reads page to exhaustion.
const readPageSize = 100

// ReadTuples lists stored tuples from the FGA store, optionally filtered.
// Empty strings omit the corresponding filter field.
func (s *sdkClient) ReadTuples(ctx context.Context, user, relation, object string) ([]Tuple, error) {
	req := fgaclient.ClientReadRequest{}
	if user != "" {
		req.User = &user
	}
	if relation != "" {
		req.Relation = &relation
	}
	if object != "" {
		req.Object = &object
	}
	out := []Tuple{}
	token := ""
	for {
		pageSize := int32(readPageSize)
		opts := fgaclient.ClientReadOptions{PageSize: &pageSize}
		if token != "" {
			opts.ContinuationToken = &token
		}
		resp, err := s.inner.Read(ctx).Body(req).Options(opts).Execute()
		if err != nil {
			return nil, fmt.Errorf("authz: fga read tuples: %w", err)
		}
		for _, t := range resp.GetTuples() {
			k := t.GetKey()
			out = append(out, Tuple{User: k.GetUser(), Relation: k.GetRelation(), Object: k.GetObject()})
		}
		// An unchanged token means the server is not advancing; stop rather than
		// spin. The page loop must terminate on a misbehaving backend.
		next := resp.GetContinuationToken()
		if next == "" || next == token {
			break
		}
		token = next
	}
	return out, nil
}

// Check implements FGAClientIface using the high-level OpenFGA SDK client.
// Contextual tuples are passed inline — no tuples are written to the store.
func (s *sdkClient) Check(ctx context.Context, req CheckRequest) (bool, error) {
	tuples := make([]fgaclient.ClientContextualTupleKey, len(req.ContextualTuples))
	for i, t := range req.ContextualTuples {
		tuples[i] = fgaclient.ClientContextualTupleKey{
			User:     t.User,
			Relation: t.Relation,
			Object:   t.Object,
		}
	}

	resp, err := s.inner.Check(ctx).Body(fgaclient.ClientCheckRequest{
		User:             req.User,
		Relation:         req.Relation,
		Object:           req.Object,
		ContextualTuples: tuples,
	}).Execute()
	if err != nil {
		return false, fmt.Errorf("authz: fga check: %w: %w", ErrCheckBackend, err)
	}
	return resp.GetAllowed(), nil
}

// ReadModelDSL reads the pinned model, else the store's latest.
func (s *sdkClient) ReadModelDSL(ctx context.Context) (string, error) {
	var (
		model *openfga.AuthorizationModel
		err   error
	)
	if s.modelID != "" {
		resp, e := s.inner.ReadAuthorizationModel(ctx).Execute()
		err = e
		if resp != nil {
			model = resp.AuthorizationModel
		}
	} else {
		resp, e := s.inner.ReadLatestAuthorizationModel(ctx).Execute()
		err = e
		if resp != nil {
			model = resp.AuthorizationModel
		}
	}
	if err != nil {
		return "", fmt.Errorf("authz: fga read model: %w", err)
	}
	if model == nil {
		return "", fmt.Errorf("authz: fga read model: no model in store")
	}
	// The SDK model type marshals to the standard OpenFGA JSON model shape, which
	// the language transformer converts back to DSL.
	buf, err := json.Marshal(model)
	if err != nil {
		return "", fmt.Errorf("authz: marshal model: %w", err)
	}
	dsl, err := parser.TransformJSONStringToDSL(string(buf))
	if err != nil {
		return "", fmt.Errorf("authz: model json to dsl: %w", err)
	}
	return *dsl, nil
}
