package dbProviders

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/i2-open/i2goSignals/internal/envcompat"
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/memory_provider"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/mongo_provider"
	"github.com/i2-open/i2goSignals/internal/providers/storage"
	"github.com/i2-open/i2goSignals/internal/wal"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/nodeid"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

var factoryLog = logger.Sub("dbProviders")

// Persistence is the composition root the server uses for everything that
// ultimately reaches the database. After PRD #39 it bundles the per-domain
// services, the cluster coordinator, and the lifecycle storage seam — no
// more god-interface façade.
//
// Callers that only need one concern should depend on the narrowest type
// available (one service, or Coordinator, or Storage).
type Persistence struct {
	StreamService        *services.StreamService
	KeyService           *services.KeyService
	EventService         *services.EventService
	ClientService        *services.ClientService
	ServerService        *services.ServerService
	TokenService         *services.TokenService
	SubjectFilterService *services.SubjectFilterService
	SubjectRelayService  *services.SubjectRelayService

	// EventDAO is the live, storage-backed EventDAO — the SAME instance the
	// EventService above writes through — exposed so an enterprise embedder can
	// bind services.NewRetentionEngine(p.EventDAO) to the running store (issue
	// #229, ADR 0055 A5.2). Additive and off the SSF wire.
	//
	// Lifecycle: like the service references above, the memory adapter swaps
	// this instance on Storage.ResetDb(true) (Mongo rebinds in place). Callers
	// must re-read p.EventDAO after Refresh(); a RetentionEngine captured from
	// the pre-reset value keeps operating on the discarded store, so rebuild it
	// after a reset on a memory-backed server.
	EventDAO interfaces.EventDAO

	Coordinator cluster.ClusterCoordinator
	Storage     storage.Storage

	// WAL is the node-local write-ahead log opened when I2SIG_STORE_WAL=local
	// (ADR 0045); nil in the default majority mode. Hand it to the event
	// router (RouterDeps.WAL), which owns and closes it.
	WAL wal.Log
	// WALRingFed is I2SIG_STORE_WAL_RING_FED (#342): with a WAL, the router
	// serves undrained WAL entries to its delivery runners. Always false in
	// majority mode. Hand it to the router (RouterDeps.WALRingFed).
	WALRingFed bool

	// src is the underlying provider used to refresh service references
	// after a Storage.ResetDb(true) call. The memory adapter rebuilds its
	// services on reset; without Refresh the cached service pointers above
	// would dangle. Mongo's reconnect rebinds in place so Refresh is a no-op
	// there.
	src serviceSource
}

// Refresh re-pulls the per-domain service references from the underlying
// provider. Call this after Storage.ResetDb(true) on the in-memory adapter
// (the only path that swaps service instances on reset).
func (p *Persistence) Refresh() {
	if p == nil || p.src == nil {
		return
	}
	p.StreamService = p.src.GetStreamService()
	p.KeyService = p.src.GetKeyService()
	p.EventService = p.src.GetEventService()
	p.ClientService = p.src.GetClientService()
	p.ServerService = p.src.GetServerService()
	p.TokenService = p.src.GetTokenService()
	p.SubjectFilterService = p.src.GetSubjectFilterService()
	p.SubjectRelayService = p.src.GetSubjectRelayService()
	p.EventDAO = p.src.GetEventDAO()
	if p.WAL != nil && p.StreamService != nil {
		p.StreamService.SetDeploymentDurabilityLocal(true)
	}
}

// serviceSource is the accessor surface present on both *MemoryProvider and
// *MongoProvider. Both expose per-domain service getters; we use this to
// hydrate the Persistence record without importing the concrete provider
// packages from anywhere else.
type serviceSource interface {
	GetStreamService() *services.StreamService
	GetKeyService() *services.KeyService
	GetEventService() *services.EventService
	GetClientService() *services.ClientService
	GetServerService() *services.ServerService
	GetTokenService() *services.TokenService
	GetSubjectFilterService() *services.SubjectFilterService
	GetSubjectRelayService() *services.SubjectRelayService
	GetEventDAO() interfaces.EventDAO
}

// OpenPersistence detects the database URL and returns the Persistence record
// (services + Coordinator + Storage) with no lifecycle context. Prefer
// OpenPersistenceWithContext from any caller that owns a shutdown signal --
// this form is the convenience entry point for tests and one-shot tools, and
// is the signature re-exported to out-of-tree embedders via pkg/eventRouter.
func OpenPersistence(mongoUrl string, dbName string) (*Persistence, error) {
	return OpenPersistenceWithContext(context.Background(), mongoUrl, dbName)
}

// OpenPersistenceWithContext is OpenPersistence bound to the server lifecycle
// ctx (seam S4). The ctx reaches the Mongo provider and, through it, the
// cluster coordinator: cancelling it at shutdown cancels in-flight lease
// heartbeats rather than letting each run out its own 5s budget. The memory
// provider has no round-trips to cancel and ignores it.
func OpenPersistenceWithContext(ctx context.Context, mongoUrl string, dbName string) (*Persistence, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	// Validate the durability mode before touching the store: an unknown value
	// refuses startup rather than silently picking a contract (ADR 0045).
	walMode, err := wal.ModeFromEnv()
	if err != nil {
		factoryLog.Error("Invalid ingest durability mode", "error", err)
		return nil, err
	}
	ringFed, err := wal.RingFedFromEnv()
	if err != nil {
		factoryLog.Error("Invalid ring-fed delivery setting", "error", err)
		return nil, err
	}
	p, err := openPersistence(ctx, mongoUrl, dbName)
	if err != nil || walMode != wal.ModeLocal {
		return p, err
	}
	if err := attachLocalWal(p, nodeid.Resolve(), wal.DirFromEnv(), ringFed); err != nil {
		if p.Storage != nil {
			_ = p.Storage.Close()
		}
		return nil, err
	}
	p.WALRingFed = ringFed
	p.StreamService.SetDeploymentDurabilityLocal(true)
	return p, nil
}

// PeerNodes returns the ids of the active cluster nodes other than selfID.
// selfID is excluded so a quick restart does not count its own stale entry.
// It is the membership read behind the multi-node guard for
// I2SIG_STORE_WAL=local (#343), at startup (CheckLocalModeCluster) and on
// every heartbeat afterwards (the server's enforcement).
func PeerNodes(coord cluster.ClusterCoordinator, selfID string) ([]string, error) {
	nodes, err := coord.GetActiveNodes()
	if err != nil {
		return nil, err
	}
	var peers []string
	for _, n := range nodes {
		if n.Id != selfID {
			peers = append(peers, n.Id)
		}
	}
	return peers, nil
}

// CheckLocalModeCluster is the multi-node refuse-to-start guard for
// I2SIG_STORE_WAL=local (spec #111 Stage 3, issue #343). A node in local mode
// may join a cluster with other active nodes only when ring-fed delivery
// (I2SIG_STORE_WAL_RING_FED=true, #342) is enabled, so a SET acked into this
// node's WAL is still delivered before the drain lands it in the shared store.
// Without it the node refuses to enable local ingest (and so refuses to
// start); it also refuses when it cannot tell how many nodes are active.
// The check is startup-only; a peer that joins later is caught by the
// server's heartbeat enforcement, which suspends local ingest on the running
// node (see SignalsApplication.enforceLocalModeCluster).
func CheckLocalModeCluster(coord cluster.ClusterCoordinator, selfID string, ringFed bool) error {
	if coord == nil || ringFed {
		return nil
	}
	peers, err := PeerNodes(coord, selfID)
	if err != nil {
		return fmt.Errorf("%s=local: cannot confirm the active cluster node count: %w; either enable ring-fed delivery (%s=true) or run in majority mode (unset %s)",
			wal.EnvMode, err, wal.EnvRingFed, wal.EnvMode)
	}
	if len(peers) > 0 {
		return fmt.Errorf("%s=local refused: %d active cluster nodes (peer %q, this node %q) and ring-fed delivery is disabled; either enable ring-fed delivery (%s=true) or run in majority mode (unset %s)",
			wal.EnvMode, len(peers)+1, peers[0], selfID, wal.EnvRingFed, wal.EnvMode)
	}
	return nil
}

// announceNode registers selfID with the coordinator before the multi-node
// guard reads membership, so two local-mode nodes started at the same time
// see each other instead of both passing an empty read (#343). The server's
// backgroundSync upserts the full record (address, version) moments later.
// A node the guard then refuses leaves this entry behind; it ages out of the
// active window, and until then a peer starting in the same state also
// refuses, which is the safe side of the race.
func announceNode(coord cluster.ClusterCoordinator, selfID string) {
	if coord == nil {
		return
	}
	now := time.Now().UTC()
	if err := coord.RegisterNode(model.ClusterNode{Id: selfID, StartedAt: now, LastSeenAt: now}); err != nil {
		factoryLog.Warn("Could not register this node before the local-mode cluster check", "error", err, "nodeID", selfID)
	}
}

// attachLocalWal opens the local WAL for I2SIG_STORE_WAL=local after the
// multi-node guard (CheckLocalModeCluster) passes.
func attachLocalWal(p *Persistence, selfID string, dir string, ringFed bool) error {
	if !ringFed {
		announceNode(p.Coordinator, selfID)
	}
	if err := CheckLocalModeCluster(p.Coordinator, selfID, ringFed); err != nil {
		factoryLog.Error("Refusing to enable local ingest durability", "error", err)
		return err
	}
	l, err := wal.OpenBolt(dir)
	if err != nil {
		return err
	}
	p.WAL = l
	factoryLog.Warn("Ingest durability is LOCAL for streams with durability=local: SETs are acknowledged after a node-local fsync, before the store write (ADR 0045). Acknowledged SETs not yet drained are lost if this node's disk is lost.", "dir", dir, "ringFed", ringFed)
	return nil
}

func openPersistence(ctx context.Context, mongoUrl string, dbName string) (*Persistence, error) {
	if strings.HasPrefix(mongoUrl, "memorydb:") || mongoUrl == "" {
		mp, err := memory_provider.Open(mongoUrl, dbName)
		if err != nil {
			return nil, err
		}
		return persistenceFromMemory(mp), nil
	}

	mp, err := mongo_provider.OpenWithContext(ctx, mongoUrl, dbName)
	if err != nil {
		if strings.ToUpper(envcompat.Lookup("I2SIG_STORE_MONGO_BACKGROUND_RECONNECT", "MONGO_BACKGROUND_RECONNECT")) == "TRUE" {
			factoryLog.Warn("Mongo connection failed. Background reconnect enabled.", "error", err)
			return persistenceFromMongo(mp), nil
		}

		failToMem := strings.ToUpper(envcompat.Lookup("I2SIG_STORE_MONGO_FALLBACK_MEM", "MONGO_FAILTOMEM"))
		if failToMem == "FALSE" {
			factoryLog.Error("Mongo Server connection failed. Exiting.", "error", err)
			return nil, err
		}

		factoryLog.Warn("Mongo Server connection failed, falling back to memory provider", "error", err)
		if mp != nil {
			_ = mp.Close()
		}
		fb, ferr := memory_provider.Open("memorydb:", dbName)
		if ferr != nil {
			return nil, ferr
		}
		return persistenceFromMemory(fb), nil
	}

	return persistenceFromMongo(mp), nil
}

func persistenceFromMemory(mp *memory_provider.MemoryProvider) *Persistence {
	return &Persistence{
		StreamService:        mp.GetStreamService(),
		KeyService:           mp.GetKeyService(),
		EventService:         mp.GetEventService(),
		ClientService:        mp.GetClientService(),
		ServerService:        mp.GetServerService(),
		TokenService:         mp.GetTokenService(),
		SubjectFilterService: mp.GetSubjectFilterService(),
		SubjectRelayService:  mp.GetSubjectRelayService(),
		EventDAO:             mp.GetEventDAO(),
		Coordinator:          mp.Coordinator(),
		Storage:              memory_provider.NewMemoryStorage(mp),
		src:                  mp,
	}
}

func persistenceFromMongo(mp *mongo_provider.MongoProvider) *Persistence {
	var svcSrc serviceSource = mp
	return &Persistence{
		StreamService:        svcSrc.GetStreamService(),
		KeyService:           svcSrc.GetKeyService(),
		EventService:         svcSrc.GetEventService(),
		ClientService:        svcSrc.GetClientService(),
		ServerService:        svcSrc.GetServerService(),
		TokenService:         svcSrc.GetTokenService(),
		SubjectFilterService: svcSrc.GetSubjectFilterService(),
		SubjectRelayService:  svcSrc.GetSubjectRelayService(),
		EventDAO:             svcSrc.GetEventDAO(),
		Coordinator:          mp.Coordinator(),
		Storage:              mongo_provider.NewMongoStorage(mp),
		src:                  mp,
	}
}
