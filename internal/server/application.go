package server

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/i2-open/i2goSignals/internal/envcompat"
	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/internal/eventRouter/delivery"
	"github.com/i2-open/i2goSignals/internal/eventRouter/peer"
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/internal/providers/storage"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/constants"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/nodeid"
	"github.com/i2-open/i2goSignals/pkg/oauthClient"
	"github.com/i2-open/i2goSignals/pkg/services"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
)

// var sa *SignalsApplication

var serverLog = logger.Sub("SERVER")

type SsfApplicationInterface interface {
	GetEventRouter() eventRouter.EventRouter
	GetAuth() *authSupport.AuthIssuer
	GetBaseUrl() *url.URL
	GetDefIssuer() string
	Name() string
	CloseReceiver(sid string)
	DrainReceiver(sid string)
	CascadeReceiverStreamDelete(ctx context.Context, state *model.StreamStateRecord)
	HandleReceiver(streamState *model.StreamStateRecord) *ClientPollStream

	// Service accessors. Handlers depend on these directly.
	GetStreamService() *services.StreamService
	GetKeyService() *services.KeyService
	GetEventService() *services.EventService
	GetClientService() *services.ClientService
	GetServerService() *services.ServerService
	GetTokenService() *services.TokenService
	GetSubjectFilterService() *services.SubjectFilterService
	GetSubjectRelayService() *services.SubjectRelayService
	GetCoordinator() cluster.ClusterCoordinator
	GetStorage() storage.Storage
}

type SignalsApplication struct {
	Coordinator          cluster.ClusterCoordinator
	Storage              storage.Storage
	StreamService        *services.StreamService
	KeyService           *services.KeyService
	EventService         *services.EventService
	ClientService        *services.ClientService
	ServerService        *services.ServerService
	TokenService         *services.TokenService
	SubjectFilterService *services.SubjectFilterService
	SubjectRelayService  *services.SubjectRelayService
	Server               *http.Server
	Handler              http.Handler
	EventRouter          eventRouter.EventRouter
	SstpDialer           *SstpDialer
	BaseUrl              *url.URL
	HostName             string
	DefIssuer            string
	AdminRole            string
	Auth                 *authSupport.AuthIssuer
	pollClients          map[string]*ClientPollStream
	pushClients          map[string]*ReceiverPushStream
	pushReceivers        map[string]model.StreamStateRecord
	mu                   sync.RWMutex
	Stats                *PrometheusHandler
	NodeID               string
	// localModeUnfenced is true when this node runs I2SIG_STORE_WAL=local
	// without ring-fed delivery, the only configuration the multi-node guard
	// applies to (#343). localIngestSuspended records that the guard fired at
	// runtime; it is set once and never cleared.
	localModeUnfenced    bool
	localIngestSuspended bool
	StartedAt            time.Time
	stopSync             chan struct{}
	InternalServer       *http.Server
	// PprofServer is the optional net/http/pprof listener (I2SIG_PPROF_ADDR).
	PprofServer *http.Server
	// dupAddrWarned holds the peers already warned about for advertising this
	// node's wake-up address (#348), so each clash is logged once. Touched
	// only from registerNode on the backgroundSync goroutine.
	dupAddrWarned map[string]bool
	// syncMu serializes stream-table syncs: the periodic one on the
	// backgroundSync goroutine and those a peer's stream-changed call runs.
	syncMu sync.Mutex
}

func (sa *SignalsApplication) Name() string {
	if sa.Storage != nil {
		return sa.Storage.Name()
	}
	return "goSignals"
}

func (sa *SignalsApplication) GetEventRouter() eventRouter.EventRouter {
	return sa.EventRouter
}

func (sa *SignalsApplication) GetStreamService() *services.StreamService { return sa.StreamService }
func (sa *SignalsApplication) GetKeyService() *services.KeyService       { return sa.KeyService }
func (sa *SignalsApplication) GetEventService() *services.EventService   { return sa.EventService }
func (sa *SignalsApplication) GetClientService() *services.ClientService { return sa.ClientService }
func (sa *SignalsApplication) GetServerService() *services.ServerService { return sa.ServerService }
func (sa *SignalsApplication) GetTokenService() *services.TokenService   { return sa.TokenService }
func (sa *SignalsApplication) GetSubjectFilterService() *services.SubjectFilterService {
	return sa.SubjectFilterService
}
func (sa *SignalsApplication) GetSubjectRelayService() *services.SubjectRelayService {
	return sa.SubjectRelayService
}
func (sa *SignalsApplication) GetCoordinator() cluster.ClusterCoordinator { return sa.Coordinator }
func (sa *SignalsApplication) GetStorage() storage.Storage                { return sa.Storage }

func (sa *SignalsApplication) GetAuth() *authSupport.AuthIssuer {
	if sa.KeyService == nil {
		return nil
	}
	auth := sa.KeyService.GetAuthIssuer()
	if auth != nil {
		sa.mu.Lock()
		sa.Auth = auth
		sa.mu.Unlock()
	}
	return auth
}

func (sa *SignalsApplication) GetDefIssuer() string {
	return sa.DefIssuer
}

func (sa *SignalsApplication) GetBaseUrl() *url.URL {
	sa.mu.RLock()
	defer sa.mu.RUnlock()
	return sa.BaseUrl
}

func (sa *SignalsApplication) SetBaseUrl(u *url.URL) {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	sa.BaseUrl = u
	if sa.Storage != nil {
		sa.Storage.SetBaseUrl(u)
	}
}

func (sa *SignalsApplication) HealthCheck() bool {
	if sa.Storage == nil {
		return false
	}
	err := sa.Storage.Check()
	if err != nil {
		serverLog.Error("Storage ping failed", "error", err)
		return false
	}
	auth := sa.GetAuth()
	if auth == nil || !auth.IsReady() {
		serverLog.Warn("Health check: token keys not yet initialized")
		return false
	}
	return true
}

func (sa *SignalsApplication) Health(w http.ResponseWriter, r *http.Request) {
	if sa.HealthCheck() {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("Service Unavailable"))
	}
}

// testPeerTransportFor and testPeerRegister are the two-node test harness's
// seam (#358, cluster_harness_test.go): when set, the router is built on the
// harness's in-process PeerTransport and registered with it. Both are nil in
// production, which leaves RouterDeps.PeerTransport nil so the router builds
// peer.NewHTTP.
var (
	testPeerTransportFor func(nodeID string) peer.PeerTransport
	testPeerRegister     func(nodeID string, router eventRouter.EventRouter)
	// testSstpDialerConfig lets the harness shrink the SSTP dialer's lease
	// timing so a takeover runs in seconds. Nil in production.
	testSstpDialerConfig func(cfg *SstpDialerConfig)
)

func testPeerTransport(nodeID string) peer.PeerTransport {
	if testPeerTransportFor == nil {
		return nil
	}
	return testPeerTransportFor(nodeID)
}

func NewApplication(persistence *dbProviders.Persistence, baseUrlString string) *SignalsApplication {
	// Ensure the default HTTP client trusts configured CAs for outbound OAuth/token discovery calls
	tlsSupport.CheckCaInstalled(http.DefaultClient)

	role := envcompat.Lookup("I2SIG_AUTH_ADMIN_ROLE", "SSEF_ADMIN_ROLE")
	if role == "" {
		role = "ADMIN"
	}

	nodeID := nodeid.Resolve()

	sa := &SignalsApplication{
		Coordinator:          persistence.Coordinator,
		Storage:              persistence.Storage,
		StreamService:        persistence.StreamService,
		KeyService:           persistence.KeyService,
		EventService:         persistence.EventService,
		ClientService:        persistence.ClientService,
		ServerService:        persistence.ServerService,
		TokenService:         persistence.TokenService,
		SubjectFilterService: persistence.SubjectFilterService,
		SubjectRelayService:  persistence.SubjectRelayService,
		AdminRole:            role,
		pollClients:          map[string]*ClientPollStream{},
		pushClients:          map[string]*ReceiverPushStream{},
		pushReceivers:        map[string]model.StreamStateRecord{},
		NodeID:               nodeID,
		StartedAt:            time.Now().UTC(),
		stopSync:             make(chan struct{}),
		localModeUnfenced:    persistence.WAL != nil && !persistence.WALRingFed,
	}

	// Initialize Auth if available
	if sa.KeyService != nil {
		sa.Auth = sa.KeyService.GetAuthIssuer()
	}

	serverLog.Info("Starting goSignalsApplication", "nodeID", nodeID)

	httpRouter := NewRouter(sa)
	// expose the handler for external server usage (e.g., httptest.Server)
	sa.Handler = httpRouter.router

	// SSTP-client dialer (PRD #49 slice 2a). AC 3: the production server
	// boot path in internal/server is the caller that registers/starts the
	// SSTP dialer loop — internal/eventRouter no longer starts any SSTP
	// dialer goroutine. Constructed first (unbound outbound); NewRouter's
	// startup UpdateStreamState iteration calls sstpDialer.RegisterPair on
	// every existing SSTP-client pair, which queues them until Bind late-
	// binds the outbound surface below and drains the queue.
	// Wire the SSTP dialer to the transmitter credential-selection chain
	// (PRD 49 slice 2b, AC 2): the dialer resolves per-cycle HTTP client
	// + Authorization through sa.ResolveTransmitterClient so
	// PeerServerAlias-configured TLS/OAuth transport posture applies and
	// the per-pair bearer wins the Authorization header (AC 3).
	sstpDialerCfg := LoadSstpDialerConfig()
	sstpDialerCfg.ResolveClient = sa.ResolveTransmitterClient
	// Spec #247 #254: the dialer's inbound half is a receiver, so it inherits
	// the same server-wide event_validation default (I2SIG_STREAM_EVENT_VALIDATION)
	// the acceptor resolves through the StreamService — one policy per pair
	// regardless of which side dialed.
	if persistence.StreamService != nil {
		sstpDialerCfg.EventValidationDefault = persistence.StreamService.EventValidationDefault()
	}
	if testSstpDialerConfig != nil {
		testSstpDialerConfig(&sstpDialerCfg)
	}
	sstpDialer := NewSstpDialer(persistence.Coordinator, nodeID, nil, sstpDialerCfg)
	sa.SstpDialer = sstpDialer

	sa.EventRouter = eventRouter.NewRouter(eventRouter.RouterDeps{
		StreamService:        persistence.StreamService,
		KeyService:           persistence.KeyService,
		EventService:         persistence.EventService,
		Coordinator:          persistence.Coordinator,
		SubjectFilterService: persistence.SubjectFilterService,
		SubjectRelayService:  persistence.SubjectRelayService,
		// The HTTP push adapter is wired at the composition root. NewRouter
		// late-binds itself as the KeyReloader so the adapter can drive the
		// RFC8935 jws_signature_failed rotate-and-retry sub-policy.
		PushDelivery:    delivery.NewHTTPAdapter(persistence.StreamService, nil),
		SstpDialerHooks: sstpDialer,
		// This server serves poll and accepted SSTP requests and mounts
		// /_cluster/claim, so it takes the poll-transmitter and sstp-server
		// leases (#365).
		ServesClaims: true,
		// Non-nil only when I2SIG_STORE_WAL=local (ADR 0045).
		WAL: persistence.WAL,
		// I2SIG_STORE_WAL_RING_FED (#342); only meaningful with a WAL.
		WALRingFed: persistence.WALRingFed,
		// Nil in production, so the router builds the HTTP adapter (#358).
		PeerTransport: testPeerTransport(nodeID),
	}, nodeID)
	if testPeerRegister != nil {
		testPeerRegister(nodeID, sa.EventRouter)
	}

	// Late-bind the router as the dialer's narrow outbound surface. The
	// router satisfies eventRouter.SstpOutbound (see internal/eventRouter/
	// sstp_outbound.go). This closes the two-way wiring: router →
	// SstpDialerHooks (Register/UnregisterPair), dialer → SstpOutbound
	// (buffer/claim/ack/wake/refresh/pause/key/second-push).
	if outbound, ok := sa.EventRouter.(eventRouter.SstpOutbound); ok {
		sstpDialer.Bind(outbound)
	} else {
		serverLog.Error("EventRouter does not implement eventRouter.SstpOutbound; SSTP dialer will not function")
	}

	var baseUrl *url.URL
	var err error
	if baseUrlString != "" {
		baseUrl, err = url.Parse(baseUrlString)
		if err != nil {
			serverLog.Error("FATAL: Invalid BaseUrl", "url", baseUrlString, "error", err)
		}
	}
	sa.BaseUrl = baseUrl
	if sa.Storage != nil {
		sa.Storage.SetBaseUrl(baseUrl)
	}

	sa.InitializePrometheus()

	// Set defaults
	defaultIssuer := envcompat.Lookup("I2SIG_ISSUER_DEFAULT", "I2SIG_ISSUER")
	if defaultIssuer == "" {
		if sa.BaseUrl != nil {
			defaultIssuer = sa.BaseUrl.String()
		} else {
			defaultIssuer = "DEFAULT"
		}
	}
	sa.DefIssuer = defaultIssuer
	serverLog.Info("Selected issuer id", "issuer", sa.DefIssuer)

	sa.InitializeReceivers()

	// One-line record of whether this server will ever expire an event.
	// Keep-forever is community's silent default, so without this the growth
	// posture is invisible until the collections are already large (#291).
	sa.logRetentionPosture()

	// Start background sync for clustering
	go sa.backgroundSync()

	// Start internal cluster server if requested on a different port
	sa.startInternalServer()

	// Start the pprof listener if requested (dev/profiling only)
	sa.startPprofServer()

	return sa
}

// logRetentionPosture emits the startup record of this server's event-retention
// posture at INFO — a steady-state operational fact per the CONTEXT.md log-level
// policy, not a warning: keep-forever is INTENTIONAL in community (ADR 0055
// decision 3), it is merely silent. Two independent things keep it silent — the
// default resolver returns a window only when a per-stream override was set, and
// community binds no RetentionEngine to the live store — so an operator reading
// `keep_forever` here should size `events` and `deliveries` for unbounded
// growth. See docs/operations.md#event-retention.
//
// Cost is one extra StreamDAO.List at startup — the same query InitializeReceivers
// just ran, not shared with it because that call holds sa.mu and keeps its map.
// A store error is swallowed by GetStateMap (which returns nil and logs); a nil
// or empty map summarizes to the zero posture, so this can never fail startup.
func (sa *SignalsApplication) logRetentionPosture() {
	states := sa.StreamService.GetStateMap(context.Background())

	streams := make([]model.StreamStateRecord, 0, len(states))
	for _, state := range states {
		streams = append(streams, state)
	}

	posture := services.SummarizeRetention(streams, services.DefaultEffectiveWindow)
	serverLog.Info("Event retention posture: no purge engine is bound, so no event expires",
		"streams", posture.Streams,
		"keep_forever", posture.KeepForever,
		"windowed", posture.Windowed,
		"doc", "docs/operations.md#event-retention")
}

// backgroundSync handles periodic tasks such as cluster node registration and state synchronization for event streams.
func (sa *SignalsApplication) backgroundSync() {
	ticker := time.NewTicker(10 * time.Second) // Heartbeat every 10s
	defer ticker.Stop()

	// Initial registration
	sa.registerNode()
	sa.enforceLocalModeCluster()

	syncCounter := 0
	for {
		select {
		case <-ticker.C:
			sa.registerNode()
			sa.enforceLocalModeCluster()

			syncCounter++
			if syncCounter >= 4 { // Every 40s
				syncCounter = 0
				serverLog.Debug("Periodic background sync starting")
				// The fallback for a missed stream-changed call: start new
				// streams, drop deleted ones, purge stale cluster rows.
				sa.syncStreamTable()
			}
		case <-sa.stopSync:
			return
		}
	}
}

// enforceLocalModeCluster is the runtime half of the I2SIG_STORE_WAL=local
// multi-node guard (#343). The startup check (dbProviders.CheckLocalModeCluster)
// only stops the node that joins; the node already running would keep acking
// SETs into a WAL that the joiner's delivery runners cannot see. So after
// every heartbeat a local-mode node without ring-fed delivery reads the active
// peers, and the first time it finds one it suspends local ingest on itself:
// streams with durability=local are acked at majority from then on, the WAL
// keeps draining, and the node stays that way until it restarts. Runs on the
// backgroundSync goroutine only, so the one-shot flag needs no lock.
func (sa *SignalsApplication) enforceLocalModeCluster() {
	if !sa.localModeUnfenced || sa.localIngestSuspended || sa.Coordinator == nil {
		return
	}
	peers, err := dbProviders.PeerNodes(sa.Coordinator, sa.NodeID)
	if err != nil {
		serverLog.Warn("Local-mode cluster check skipped: cannot read active cluster nodes; retrying on the next heartbeat", "error", err)
		return
	}
	if len(peers) == 0 {
		return
	}
	sa.localIngestSuspended = true
	serverLog.Error("I2SIG_STORE_WAL=local: another active cluster node was found and ring-fed delivery is disabled; local ingest is suspended on this node until restart and streams with durability=local run at majority (#343). Either enable ring-fed delivery (I2SIG_STORE_WAL_RING_FED=true) on every node or run in majority mode (unset I2SIG_STORE_WAL).",
		"peer", peers[0], "activeNodes", len(peers)+1, "nodeID", sa.NodeID)
	if sa.StreamService != nil {
		sa.StreamService.SetDeploymentDurabilityLocal(false)
	}
	if s, ok := sa.EventRouter.(eventRouter.LocalIngestSuspender); ok {
		s.SuspendLocalIngest()
	}
}

// CEnvClusterAdvertiseUrl names the wake-up address a node advertises to its
// peers in cluster_nodes. When set it is stored verbatim; when unset the
// address is derived from BASE_URL and I2SIG_CLUSTER_INTERNAL_PORT (#348).
const CEnvClusterAdvertiseUrl = "I2SIG_CLUSTER_ADVERTISE_URL"

// registerNode registers the current node in the cluster with its ID, address, version, and timestamps.
func (sa *SignalsApplication) registerNode() {
	addr := sa.advertisedAddress()

	node := model.ClusterNode{
		Id:         sa.NodeID,
		Address:    addr,
		Version:    constants.GoSignalsVersion,
		StartedAt:  sa.StartedAt,
		LastSeenAt: time.Now().UTC(),
	}
	if sa.Coordinator == nil {
		serverLog.Warn("RegisterNode skipped: coordinator not initialized")
		return
	}
	err := sa.Coordinator.RegisterNode(node)
	if err != nil {
		serverLog.Error("Failed to register node", "error", err)
		return
	}
	sa.warnDuplicateAdvertisedAddress(addr)
}

// warnDuplicateAdvertisedAddress logs one WARN per live peer that advertises
// the same wake-up address as this node (#348). Wake-up calls addressed to
// either node reach only one of them, so cross-node delivery silently falls
// back to the backfill. Host case is ignored, as DNS ignores it.
func (sa *SignalsApplication) warnDuplicateAdvertisedAddress(addr string) {
	nodes, err := sa.Coordinator.GetActiveNodes()
	if err != nil {
		serverLog.Debug("Duplicate advertised-address check skipped: cannot read active cluster nodes", "error", err)
		return
	}
	for _, n := range nodes {
		if n.Id == sa.NodeID || !strings.EqualFold(n.Address, addr) || sa.dupAddrWarned[n.Id] {
			continue
		}
		if sa.dupAddrWarned == nil {
			sa.dupAddrWarned = make(map[string]bool)
		}
		sa.dupAddrWarned[n.Id] = true
		serverLog.Warn("CLUSTER: another live cluster node advertises the same wake-up address; wake-up calls meant for one node reach the other and cross-node delivery falls back to backfill. Give each node its own address with "+CEnvClusterAdvertiseUrl+" or a per-node BASE_URL (see docs/Cluster.md).",
			"address", addr, "nodeID", sa.NodeID, "peerNodeID", n.Id)
	}
}

// advertisedAddress is the wake-up address this node publishes in
// cluster_nodes: I2SIG_CLUSTER_ADVERTISE_URL verbatim when set, else
// http://<BASE_URL host>:<I2SIG_CLUSTER_INTERNAL_PORT or main port>.
func (sa *SignalsApplication) advertisedAddress() string {
	if v := strings.TrimSpace(os.Getenv(CEnvClusterAdvertiseUrl)); v != "" {
		return v
	}

	sa.mu.RLock()
	server := sa.Server
	baseUrl := sa.BaseUrl
	sa.mu.RUnlock()

	host := ""
	port := ""

	if baseUrl != nil {
		host = baseUrl.Hostname()
		port = baseUrl.Port()
	}

	if host == "" || host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "0.0.0.0" {
		host, _ = os.Hostname()
	}

	mainPort := port
	if mainPort == "" && server != nil {
		_, p, _ := net.SplitHostPort(server.Addr)
		mainPort = p
	}

	internalPort := os.Getenv("I2SIG_CLUSTER_INTERNAL_PORT")
	effectivePort := internalPort
	if effectivePort == "" {
		effectivePort = mainPort
	}

	addr := net.JoinHostPort(host, effectivePort)
	if !strings.HasPrefix(addr, "http") {
		addr = "http://" + addr
	}
	return addr
}

// StartServer creates a real net/http server wrapping the application handler.
// This is used for production binaries. Tests can instead use NewApplication + httptest.Server.
func StartServer(addr string, persistence *dbProviders.Persistence, baseUrlString string) *SignalsApplication {
	sa := NewApplication(persistence, baseUrlString)
	server := http.Server{
		Addr:     addr,
		Handler:  sa.Handler,
		ErrorLog: slog.NewLogLogger(serverLog.Handler(), slog.LevelError),
	}
	sa.mu.Lock()
	sa.Server = &server
	if sa.BaseUrl == nil {
		baseUrl, _ := url.Parse("http://" + server.Addr + "/")
		sa.BaseUrl = baseUrl
		if sa.Storage != nil {
			sa.Storage.SetBaseUrl(baseUrl)
		}
	}
	sa.mu.Unlock()
	dbName := ""
	if sa.Storage != nil {
		dbName = sa.Storage.Name()
	}
	serverLog.Info("Server listening", "db", dbName, "addr", addr)
	return sa
}

func (sa *SignalsApplication) Shutdown() {
	name := ""
	if sa.Storage != nil {
		name = sa.Storage.Name()
	}
	serverLog.Info("Shutdown initiated", "db", name)

	if sa.stopSync != nil {
		close(sa.stopSync)
	}

	// Turn off Polling Clients
	sa.shutdownReceivers()

	// Turn off the server (if present)
	if sa.Server != nil {
		_ = sa.Server.Shutdown(context.Background())
	}

	if sa.InternalServer != nil {
		_ = sa.InternalServer.Shutdown(context.Background())
	}

	if sa.PprofServer != nil {
		_ = sa.PprofServer.Shutdown(context.Background())
	}

	// Turn off client connections
	sa.mu.Lock()
	for _, client := range sa.pollClients {
		client.Close()
	}
	sa.mu.Unlock()

	// Graceful drain: let in-flight receiver/event work settle before tearing
	// down the router and storage. Duration is configurable (I2SIG_SHUTDOWN_DRAIN,
	// seconds) so tests can set it to 0; production keeps the historical ~1s per
	// phase.
	drain := ResolveShutdownDrain()
	if drain > 0 {
		time.Sleep(drain)
	}

	// Stop processing new events
	sa.EventRouter.Shutdown()
	// The router's shutdown cancels the SSTP pair loops; wait for them to
	// release their leases before storage closes.
	if sa.SstpDialer != nil {
		sa.SstpDialer.Shutdown()
	}

	// Give some time to ensure all ops are finished.
	if drain > 0 {
		time.Sleep(drain)
	}

	// Release pooled peer SPIFFE clients and their shared X509Source (#326)
	// only after the drain, so in-flight deliveries keep a live source.
	oauthClient.CloseSpiffeClients()

	// Shutdown the storage
	if sa.Storage != nil {
		_ = sa.Storage.Close()
	}

	serverLog.Info("Shutdown Complete", "db", name)
}

// ResolveShutdownDrain returns the per-phase graceful-drain delay used by
// Shutdown. It reads I2SIG_SHUTDOWN_DRAIN (legacy SHUTDOWN_DRAIN) as a float
// number of seconds. Unset/empty or unparseable falls back to 1s, preserving
// the historical two-phase ~2s drain; a value of 0 disables the drain (used by
// the test suite, which spins up and tears down dozens of servers). Shared with
// pkg/goSsfServer, which applies the same drain in its Shutdown.
func ResolveShutdownDrain() time.Duration {
	val := envcompat.Lookup("I2SIG_SHUTDOWN_DRAIN", "SHUTDOWN_DRAIN")
	if val == "" {
		return time.Second
	}
	secs, err := strconv.ParseFloat(val, 64)
	if err != nil || secs < 0 {
		serverLog.Warn("Invalid I2SIG_SHUTDOWN_DRAIN; falling back to 1s",
			"value", val)
		return time.Second
	}
	return time.Duration(secs * float64(time.Second))
}
