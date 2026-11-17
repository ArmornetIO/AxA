// Package fga embeds OpenFGA in process; Client() calls it with no network hop.
package fga

import (
	"context"
	"fmt"
	"time"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	parser "github.com/openfga/language/pkg/go/transformer"
	fgalogger "github.com/openfga/openfga/pkg/logger"
	fgaserver "github.com/openfga/openfga/pkg/server"
	"github.com/openfga/openfga/pkg/storage/postgres"
	"github.com/openfga/openfga/pkg/storage/sqlcommon"

	"github.com/ArmornetIO/axa/authz"
)

type Config struct {
	// DatastoreURI is the Postgres DSN. Required.
	DatastoreURI string
	// ModelData is .fga DSL; empty uses DefaultModel() so it boots standalone.
	ModelData []byte
	// StoreName defaults to "armornet".
	StoreName string
}

type Server struct {
	svr     *fgaserver.Server
	ds      *postgres.Datastore
	storeID string
	modelID string
}

// New returns only once the store and model are written and Check works.
func New(ctx context.Context, cfg Config) (*Server, error) {
	if cfg.DatastoreURI == "" {
		return nil, fmt.Errorf("fga: DatastoreURI is required")
	}
	if cfg.StoreName == "" {
		cfg.StoreName = "armornet"
	}
	if len(cfg.ModelData) == 0 {
		cfg.ModelData = DefaultModel()
	}

	log := fgalogger.NewNoopLogger()

	// The host migrates the schema. Cap the pool: FGA shares the host's Postgres,
	// and pgxpool's NumCPU default with 30m idle conns starves everyone else.
	ds, err := postgres.New(cfg.DatastoreURI, sqlcommon.NewConfig(
		sqlcommon.WithLogger(log),
		sqlcommon.WithMaxOpenConns(5),
		sqlcommon.WithConnMaxIdleTime(2*time.Minute),
	))
	if err != nil {
		return nil, fmt.Errorf("fga: create datastore: %w", err)
	}

	svr, err := fgaserver.NewServerWithOpts(
		fgaserver.WithDatastore(ds),
		fgaserver.WithLogger(log),
		fgaserver.WithContinuationTokenSerializer(sqlcommon.NewSQLContinuationTokenSerializer()),
	)
	if err != nil {
		ds.Close()
		return nil, fmt.Errorf("fga: create server: %w", err)
	}

	s := &Server{svr: svr, ds: ds}
	if err := s.bootstrap(ctx, cfg); err != nil {
		svr.Close()
		ds.Close()
		return nil, err
	}
	return s, nil
}

// Start only blocks: the engine already runs from New. It exists for app.Add.
func (s *Server) Start(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

func (s *Server) Stop(_ context.Context) error {
	s.svr.Close()
	s.ds.Close()
	return nil
}

func (s *Server) Client() authz.FGAClientIface {
	return &inProcessClient{svr: s.svr, storeID: s.storeID, modelID: s.modelID}
}

func (s *Server) StoreID() string { return s.storeID }
func (s *Server) ModelID() string { return s.modelID }

// bootstrap finds or creates the named store and writes the authorization model.
func (s *Server) bootstrap(ctx context.Context, cfg Config) error {
	resp, err := s.svr.ListStores(ctx, &openfgav1.ListStoresRequest{})
	if err != nil {
		return fmt.Errorf("fga: list stores: %w", err)
	}
	for _, store := range resp.GetStores() {
		if store.GetName() == cfg.StoreName {
			s.storeID = store.GetId()
			break
		}
	}
	if s.storeID == "" {
		cr, err := s.svr.CreateStore(ctx, &openfgav1.CreateStoreRequest{Name: cfg.StoreName})
		if err != nil {
			return fmt.Errorf("fga: create store %q: %w", cfg.StoreName, err)
		}
		s.storeID = cr.GetId()
	}
	return s.writeModel(ctx, cfg.ModelData)
}

func (s *Server) writeModel(ctx context.Context, dsl []byte) error {
	model, err := parser.TransformDSLToProto(string(dsl))
	if err != nil {
		return fmt.Errorf("fga: parse model: %w", err)
	}
	wr, err := s.svr.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{
		StoreId:         s.storeID,
		SchemaVersion:   model.GetSchemaVersion(),
		TypeDefinitions: model.GetTypeDefinitions(),
		Conditions:      model.GetConditions(),
	})
	if err != nil {
		return fmt.Errorf("fga: write authorization model: %w", err)
	}
	s.modelID = wr.GetAuthorizationModelId()
	return nil
}
