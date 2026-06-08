package goSsfServer

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/internal/envcompat"
	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/internal/eventRouter/delivery"
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/internal/providers/storage"
	"github.com/i2-open/i2goSignals/internal/services"
	"github.com/i2-open/i2goSignals/internal/server"
	"github.com/i2-open/i2goSignals/pkg/constants"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/nodeid"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

var serverLog = logger.Sub("SERVER")

type SsfApplication struct {
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
	Handler       http.Handler
	EventRouter   eventRouter.EventRouter
	BaseUrl       *url.URL
	HostName      string
	DefIssuer     string
	AdminRole     string
	Auth          *authSupport.AuthIssuer
	mu            sync.RWMutex
	NodeID        string
	StartedAt     time.Time
}

func (sa *SsfApplication) GetStreamService() *services.StreamService  { return sa.StreamService }
func (sa *SsfApplication) GetKeyService() *services.KeyService        { return sa.KeyService }
func (sa *SsfApplication) GetEventService() *services.EventService    { return sa.EventService }
func (sa *SsfApplication) GetClientService() *services.ClientService  { return sa.ClientService }
func (sa *SsfApplication) GetServerService() *services.ServerService  { return sa.ServerService }
func (sa *SsfApplication) GetTokenService() *services.TokenService    { return sa.TokenService }
func (sa *SsfApplication) GetSubjectFilterService() *services.SubjectFilterService {
	return sa.SubjectFilterService
}
func (sa *SsfApplication) GetSubjectRelayService() *services.SubjectRelayService {
	return sa.SubjectRelayService
}
func (sa *SsfApplication) GetCoordinator() cluster.ClusterCoordinator { return sa.Coordinator }
func (sa *SsfApplication) GetStorage() storage.Storage                { return sa.Storage }

func (sa *SsfApplication) GetEventRouter() eventRouter.EventRouter {
	return sa.EventRouter
}

func (sa *SsfApplication) GetAuth() *authSupport.AuthIssuer {
	if sa.KeyService == nil {
		return sa.Auth
	}
	auth := sa.KeyService.GetAuthIssuer()
	if auth != nil {
		sa.mu.Lock()
		sa.Auth = auth
		sa.mu.Unlock()
	}
	return auth
}

func (sa *SsfApplication) GetDefIssuer() string {
	return sa.DefIssuer
}

func (sa *SsfApplication) CloseReceiver(_ string) {
	// SSF-only server does not implement receivers
}

func (sa *SsfApplication) HandleReceiver(_ *model.StreamStateRecord) *server.ClientPollStream {
	// SSF-only server does not implement receivers
	return nil
}

func (sa *SsfApplication) Name() string {
	if sa.Storage != nil {
		return sa.Storage.Name()
	}
	return "goSSF"
}

func (sa *SsfApplication) Index(w http.ResponseWriter, r *http.Request) {
	test := r.UserAgent()
	_, _ = fmt.Fprintf(w, "Hello %s", test)
}

func (sa *SsfApplication) IssuerProjectIat(w http.ResponseWriter, r *http.Request) {
	server.IssuerProjectIatHandler(sa, w, r)
}

func (sa *SsfApplication) RegisterClient(w http.ResponseWriter, r *http.Request) {
	server.RegisterClientHandler(sa, w, r)
}

func (sa *SsfApplication) TriggerEvent(w http.ResponseWriter, r *http.Request) {
	server.TriggerEventHandler(sa, w, r)
}

func (sa *SsfApplication) ReceivePushEvent(w http.ResponseWriter, r *http.Request) {
	server.ReceivePushEventHandler(sa, w, r)
}

func (sa *SsfApplication) AddSubject(w http.ResponseWriter, r *http.Request) {
	server.AddSubjectHandler(sa, w, r)
}

func (sa *SsfApplication) GetStatus(w http.ResponseWriter, r *http.Request) {
	server.GetStatusHandler(sa, w, r)
}

func (sa *SsfApplication) RemoveSubject(w http.ResponseWriter, r *http.Request) {
	server.RemoveSubjectHandler(sa, w, r)
}

func (sa *SsfApplication) StreamDelete(w http.ResponseWriter, r *http.Request) {
	server.StreamDeleteHandler(sa, w, r)
}

func (sa *SsfApplication) ListStreamStates(w http.ResponseWriter, r *http.Request) {
	server.ListStreamStatesHandler(sa, w, r)
}

func (sa *SsfApplication) GetStreamState(w http.ResponseWriter, r *http.Request) {
	server.GetStreamStateHandler(sa, w, r)
}

func (sa *SsfApplication) StreamGet(w http.ResponseWriter, r *http.Request) {
	server.StreamGetHandler(sa, w, r)
}

func (sa *SsfApplication) StreamCreate(w http.ResponseWriter, r *http.Request) {
	server.StreamCreateHandler(sa, w, r)
}

func (sa *SsfApplication) StreamUpdate(w http.ResponseWriter, r *http.Request) {
	server.StreamUpdateHandler(sa, w, r)
}

func (sa *SsfApplication) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	server.UpdateStatusHandler(sa, w, r)
}

func (sa *SsfApplication) VerificationRequest(w http.ResponseWriter, r *http.Request) {
	server.VerificationRequestHandler(sa, w, r)
}

func (sa *SsfApplication) WellKnownSsfConfigurationGet(w http.ResponseWriter, r *http.Request) {
	server.WellKnownSsfConfigurationGetHandler(sa, w, r)
}

func (sa *SsfApplication) WellKnownSsfConfigurationIssuerGet(w http.ResponseWriter, r *http.Request) {
	server.WellKnownSsfConfigurationIssuerGetHandler(sa, w, r)
}

func (sa *SsfApplication) CreateKey(w http.ResponseWriter, r *http.Request) {
	server.CreateKeyHandler(sa, w, r)
}

func (sa *SsfApplication) LoadKey(w http.ResponseWriter, r *http.Request) {
	server.LoadKeyHandler(sa, w, r)
}

func (sa *SsfApplication) CreateJwksIssuer(w http.ResponseWriter, r *http.Request) {
	server.CreateKeyNameHandler(sa, w, r)
}

func (sa *SsfApplication) JwksJson(w http.ResponseWriter, r *http.Request) {
	server.JwksJsonHandler(sa, w, r)
}

func (sa *SsfApplication) JwksIssuers(w http.ResponseWriter, r *http.Request) {
	server.JwksIssuersHandler(sa, w, r)
}

func (sa *SsfApplication) JwksJsonIssuer(w http.ResponseWriter, r *http.Request) {
	server.JwksJsonIssuerHandler(sa, w, r)
}

func (sa *SsfApplication) DeleteJwksIssuerKey(w http.ResponseWriter, r *http.Request) {
	server.DeleteJwksIssuerKeyHandler(sa, w, r)
}

func (sa *SsfApplication) PollEvents(w http.ResponseWriter, r *http.Request) {
	server.PollEventsHandler(sa, w, r)
}

func (sa *SsfApplication) ProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	server.ProtectedResourceMetadataHandler(sa, w, r)
}

func (sa *SsfApplication) GetBaseUrl() *url.URL {
	sa.mu.RLock()
	defer sa.mu.RUnlock()
	return sa.BaseUrl
}

func (sa *SsfApplication) SetBaseUrl(u *url.URL) {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	sa.BaseUrl = u
	if sa.Storage != nil {
		sa.Storage.SetBaseUrl(u)
	}
}

func (sa *SsfApplication) HealthCheck() bool {
	if sa.Storage == nil {
		return false // for memory provider should be true?
	}
	err := sa.Storage.Check()
	if err != nil {
		serverLog.Error("MongoProvider ping failed", "error", err)
		return false
	}
	auth := sa.GetAuth()
	if auth == nil || !auth.IsReady() {
		serverLog.Warn("Health check: token keys not yet initialized")
		return false
	}
	return true
}

func (sa *SsfApplication) Health(w http.ResponseWriter, r *http.Request) {
	if sa.HealthCheck() {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("Service Unavailable"))
	}
}
func NewApplication(persistence *dbProviders.Persistence, baseUrlString string) *SsfApplication {
	role := envcompat.Lookup("I2SIG_AUTH_ADMIN_ROLE", "SSEF_ADMIN_ROLE")
	if role == "" {
		role = "ADMIN"
	}

	nodeID := nodeid.Resolve()

	sa := &SsfApplication{
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
		NodeID:               nodeID,
		StartedAt:            time.Now().UTC(),
	}

	if sa.KeyService != nil {
		sa.Auth = sa.KeyService.GetAuthIssuer()
	}

	serverLog.Info("Starting goSsfApplication", "nodeID", nodeID)

	httpRouter := NewRouter(sa)
	// expose the handler for external server usage (e.g., httptest.Server)
	sa.Handler = httpRouter.router

	sa.EventRouter = eventRouter.NewRouter(eventRouter.RouterDeps{
		StreamService:        persistence.StreamService,
		KeyService:           persistence.KeyService,
		EventService:         persistence.EventService,
		Coordinator:          persistence.Coordinator,
		SubjectFilterService: persistence.SubjectFilterService,
		PushDelivery:         delivery.NewHTTPAdapter(persistence.StreamService, nil),
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

	// Start background sync for clustering
	go sa.backgroundSync()

	return sa
}

// backgroundSync handles periodic tasks such as cluster node registration and state synchronization for event streams.
func (sa *SsfApplication) backgroundSync() {
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

				// Sync router state
				states := sa.StreamService.GetStateMap(context.Background())
				for _, state := range states {
					sa.EventRouter.UpdateStreamState(&state)
				}
			}
		}
	}
}

// registerNode registers the current node in the cluster with its ID, address, version, and timestamps.
func (sa *SsfApplication) registerNode() {
	sa.mu.RLock()
	httpServer := sa.Server
	baseUrl := sa.BaseUrl
	sa.mu.RUnlock()

	addr := ""
	if httpServer != nil {
		addr = httpServer.Addr
	} else if baseUrl != nil {
		addr = baseUrl.Host
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
func StartServer(addr string, persistence *dbProviders.Persistence, baseUrlString string) *SsfApplication {
	sa := NewApplication(persistence, baseUrlString)
	httpServer := http.Server{
		Addr:     addr,
		Handler:  sa.Handler,
		ErrorLog: slog.NewLogLogger(serverLog.Handler(), slog.LevelError),
	}
	sa.mu.Lock()
	sa.Server = &httpServer
	if sa.BaseUrl == nil {
		baseUrl, _ := url.Parse("http://" + httpServer.Addr + "/")
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

func (sa *SsfApplication) Shutdown() {
	name := ""
	if sa.Storage != nil {
		name = sa.Storage.Name()
	}
	serverLog.Info("Shutdown initiated", "db", name)

	// Turn off the server (if present)
	if sa.Server != nil {
		_ = sa.Server.Shutdown(context.Background())
	}

	// Graceful drain, configurable via I2SIG_SHUTDOWN_DRAIN (see
	// server.ResolveShutdownDrain); 0 disables it for tests.
	drain := server.ResolveShutdownDrain()
	if drain > 0 {
		time.Sleep(drain)
	}

	// Stop processing new events
	sa.EventRouter.Shutdown()

	// Give some time to ensure all ops are finished.
	if drain > 0 {
		time.Sleep(drain)
	}

	// Shutdown the provider
	if sa.Storage != nil {
		_ = sa.Storage.Close()
	}

	serverLog.Info("Shutdown Complete", "db", name)
}
