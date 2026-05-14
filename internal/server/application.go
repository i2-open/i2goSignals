package server

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/internal/eventRouter/delivery"
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/internal/providers/storage"
	"github.com/i2-open/i2goSignals/internal/services"
	"github.com/i2-open/i2goSignals/pkg/constants"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/nodeid"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
)

// var sa *SignalsApplication

var serverLog = logger.Sub("SERVER")

type SsfApplicationInterface interface {
	GetEventRouter() eventRouter.EventRouter
	GetAuth() *authUtil.AuthIssuer
	GetBaseUrl() *url.URL
	GetDefIssuer() string
	Name() string
	CloseReceiver(sid string)
	HandleReceiver(streamState *model.StreamStateRecord) *ClientPollStream

	// Service accessors. Handlers depend on these directly.
	GetStreamService() *services.StreamService
	GetKeyService() *services.KeyService
	GetEventService() *services.EventService
	GetClientService() *services.ClientService
	GetServerService() *services.ServerService
	GetTokenService() *services.TokenService
	GetCoordinator() cluster.ClusterCoordinator
	GetStorage() storage.Storage
}

type SignalsApplication struct {
	Coordinator    cluster.ClusterCoordinator
	Storage        storage.Storage
	StreamService  *services.StreamService
	KeyService     *services.KeyService
	EventService   *services.EventService
	ClientService  *services.ClientService
	ServerService  *services.ServerService
	TokenService   *services.TokenService
	Server         *http.Server
	Handler        http.Handler
	EventRouter    eventRouter.EventRouter
	BaseUrl        *url.URL
	HostName       string
	DefIssuer      string
	AdminRole      string
	Auth           *authUtil.AuthIssuer
	pollClients    map[string]*ClientPollStream
	pushClients    map[string]*ReceiverPushStream
	pushReceivers  map[string]model.StreamStateRecord
	mu             sync.RWMutex
	Stats          *PrometheusHandler
	NodeID         string
	StartedAt      time.Time
	stopSync       chan struct{}
	InternalServer *http.Server
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

func (sa *SignalsApplication) GetStreamService() *services.StreamService  { return sa.StreamService }
func (sa *SignalsApplication) GetKeyService() *services.KeyService        { return sa.KeyService }
func (sa *SignalsApplication) GetEventService() *services.EventService    { return sa.EventService }
func (sa *SignalsApplication) GetClientService() *services.ClientService  { return sa.ClientService }
func (sa *SignalsApplication) GetServerService() *services.ServerService  { return sa.ServerService }
func (sa *SignalsApplication) GetTokenService() *services.TokenService    { return sa.TokenService }
func (sa *SignalsApplication) GetCoordinator() cluster.ClusterCoordinator { return sa.Coordinator }
func (sa *SignalsApplication) GetStorage() storage.Storage                { return sa.Storage }

func (sa *SignalsApplication) GetAuth() *authUtil.AuthIssuer {
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

func NewApplication(persistence *dbProviders.Persistence, baseUrlString string) *SignalsApplication {
	// Ensure the default HTTP client trusts configured CAs for outbound OAuth/token discovery calls
	tlsSupport.CheckCaInstalled(http.DefaultClient)

	role := os.Getenv("SSEF_ADMIN_ROLE")
	if role == "" {
		role = "ADMIN"
	}

	nodeID := nodeid.Resolve()

	sa := &SignalsApplication{
		Coordinator:   persistence.Coordinator,
		Storage:       persistence.Storage,
		StreamService: persistence.StreamService,
		KeyService:    persistence.KeyService,
		EventService:  persistence.EventService,
		ClientService: persistence.ClientService,
		ServerService: persistence.ServerService,
		TokenService:  persistence.TokenService,
		AdminRole:     role,
		pollClients:   map[string]*ClientPollStream{},
		pushClients:   map[string]*ReceiverPushStream{},
		pushReceivers: map[string]model.StreamStateRecord{},
		NodeID:        nodeID,
		StartedAt:     time.Now().UTC(),
		stopSync:      make(chan struct{}),
	}

	// Initialize Auth if available
	if sa.KeyService != nil {
		sa.Auth = sa.KeyService.GetAuthIssuer()
	}

	serverLog.Info("Starting goSignalsApplication", "nodeID", nodeID)

	httpRouter := NewRouter(sa)
	// expose the handler for external server usage (e.g., httptest.Server)
	sa.Handler = httpRouter.router

	sa.EventRouter = eventRouter.NewRouter(eventRouter.RouterDeps{
		StreamService: persistence.StreamService,
		KeyService:    persistence.KeyService,
		EventService:  persistence.EventService,
		Coordinator:   persistence.Coordinator,
		// The HTTP push adapter is wired at the composition root. NewRouter
		// late-binds itself as the KeyReloader so the adapter can drive the
		// RFC8935 jws_signature_failed rotate-and-retry sub-policy.
		PushDelivery: delivery.NewHTTPAdapter(persistence.StreamService, nil),
	}, nodeID)

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
	defaultIssuer, issDefined := os.LookupEnv("I2SIG_ISSUER")
	if !issDefined {
		if sa.BaseUrl != nil {
			defaultIssuer = sa.BaseUrl.String()
		} else {
			defaultIssuer = "DEFAULT"
		}
	}
	sa.DefIssuer = defaultIssuer
	serverLog.Info("Selected issuer id", "issuer", sa.DefIssuer)

	sa.InitializeReceivers()

	// Start background sync for clustering
	go sa.backgroundSync()

	// Start internal cluster server if requested on a different port
	sa.startInternalServer()

	return sa
}

// backgroundSync handles periodic tasks such as cluster node registration and state synchronization for event streams.
func (sa *SignalsApplication) backgroundSync() {
	ticker := time.NewTicker(10 * time.Second) // Heartbeat every 10s
	defer ticker.Stop()

	// Initial registration
	sa.registerNode()

	syncCounter := 0
	for {
		select {
		case <-ticker.C:
			sa.registerNode()

			syncCounter++
			if syncCounter >= 4 { // Every 40s
				syncCounter = 0
				serverLog.Debug("Periodic background sync starting")
				sa.InitializeReceivers()

				// Sync router state
				states := sa.StreamService.GetStateMap(context.Background())
				for _, state := range states {
					sa.EventRouter.UpdateStreamState(&state)
				}
			}
		case <-sa.stopSync:
			return
		}
	}
}

// registerNode registers the current node in the cluster with its ID, address, version, and timestamps.
func (sa *SignalsApplication) registerNode() {
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
	}
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

	// Turn off client connections
	sa.mu.Lock()
	for _, client := range sa.pollClients {
		client.Close()
	}
	sa.mu.Unlock()
	time.Sleep(time.Second)

	// Stop processing new events
	sa.EventRouter.Shutdown()

	// Give some time to ensure all ops are finished.
	time.Sleep(time.Second)

	// Shutdown the storage
	if sa.Storage != nil {
		_ = sa.Storage.Close()
	}

	serverLog.Info("Shutdown Complete", "db", name)
}