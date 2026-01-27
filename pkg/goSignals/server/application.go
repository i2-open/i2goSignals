package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/internal/logger"
	"github.com/i2-open/i2goSignals/internal/model"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
)

// var sa *SignalsApplication

var serverLog = logger.Sub("SERVER")

type SignalsApplication struct {
	Provider      dbProviders.DbProviderInterface
	Server        *http.Server
	Handler       http.Handler
	EventRouter   eventRouter.EventRouter
	BaseUrl       *url.URL
	HostName      string
	DefIssuer     string
	AdminRole     string
	Auth          *authUtil.AuthIssuer
	pollClients   map[string]*ClientPollStream
	pushReceivers map[string]model.StreamStateRecord
	mu            sync.RWMutex
	Stats         *PrometheusHandler
	NodeID        string
	StartedAt     time.Time
}

func (sa *SignalsApplication) Name() string {
	if sa.Provider != nil {
		return sa.Provider.Name()
	}
	return "goSignals"
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
	if sa.Provider != nil {
		sa.Provider.SetBaseUrl(u)
	}
}

func (sa *SignalsApplication) HealthCheck() bool {
	err := sa.Provider.Check()
	if err != nil {
		serverLog.Error("MongoProvider ping failed", "error", err)
		return false
	}
	return true
}

func NewApplication(provider dbProviders.DbProviderInterface, baseUrlString string) *SignalsApplication {
	role := os.Getenv("SSEF_ADMIN_ROLE")
	if role == "" {
		role = "ADMIN"
	}

	nodeID := os.Getenv("NODE_ID")
	if nodeID == "" {
		nodeID = os.Getenv("POD_NAME")
	}
	if nodeID == "" {
		hostname, _ := os.Hostname()
		nodeID = fmt.Sprintf("%s-%d", hostname, time.Now().Unix())
	}

	sa := &SignalsApplication{
		Provider:      provider,
		AdminRole:     role,
		Auth:          provider.GetAuthIssuer(),
		pollClients:   map[string]*ClientPollStream{},
		pushReceivers: map[string]model.StreamStateRecord{},
		NodeID:        nodeID,
		StartedAt:     time.Now().UTC(),
	}

	serverLog.Info("Starting goSignalsApplication", "nodeID", nodeID)

	httpRouter := NewRouter(sa)
	// expose the handler for external server usage (e.g., httptest.Server)
	sa.Handler = httpRouter.router

	sa.EventRouter = eventRouter.NewRouter(provider, nodeID)

	var baseUrl *url.URL
	var err error
	if baseUrlString != "" {
		baseUrl, err = url.Parse(baseUrlString)
		if err != nil {
			serverLog.Error("FATAL: Invalid BaseUrl", "url", baseUrlString, "error", err)
		}
	}
	sa.BaseUrl = baseUrl
	if sa.Provider != nil {
		sa.Provider.SetBaseUrl(baseUrl)
	}

	sa.InitializePrometheus()

	// Set defaults
	defaultIssuer, issDefined := os.LookupEnv("I2SIG_ISSUER")
	if !issDefined {
		defaultIssuer = "DEFAULT"
	}
	sa.DefIssuer = defaultIssuer
	serverLog.Info("Selected issuer id", "issuer", sa.DefIssuer)

	sa.InitializeReceivers()

	// Start background sync for clustering
	go sa.backgroundSync()

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
				states := sa.Provider.GetStateMap()
				for _, state := range states {
					sa.EventRouter.UpdateStreamState(&state)
				}
			}
		}
	}
}

// registerNode registers the current node in the cluster with its ID, address, version, and timestamps.
func (sa *SignalsApplication) registerNode() {
	sa.mu.RLock()
	server := sa.Server
	baseUrl := sa.BaseUrl
	sa.mu.RUnlock()

	addr := ""
	if server != nil {
		addr = server.Addr
	} else if baseUrl != nil {
		addr = baseUrl.Host
	}

	node := model.ClusterNode{
		Id:         sa.NodeID,
		Address:    addr,
		Version:    "1.0.0", // TODO: use actual version
		StartedAt:  sa.StartedAt,
		LastSeenAt: time.Now().UTC(),
	}
	err := sa.Provider.RegisterNode(node)
	if err != nil {
		serverLog.Error("Failed to register node", "error", err)
	}
}

// StartServer creates a real net/http server wrapping the application handler.
// This is used for production binaries. Tests can instead use NewApplication + httptest.Server.
func StartServer(addr string, provider dbProviders.DbProviderInterface, baseUrlString string) *SignalsApplication {
	sa := NewApplication(provider, baseUrlString)
	server := http.Server{
		Addr:    addr,
		Handler: sa.Handler,
	}
	sa.mu.Lock()
	sa.Server = &server
	if sa.BaseUrl == nil {
		baseUrl, _ := url.Parse("http://" + server.Addr + "/")
		sa.BaseUrl = baseUrl
		if sa.Provider != nil {
			sa.Provider.SetBaseUrl(baseUrl)
		}
	}
	sa.mu.Unlock()
	serverLog.Info("Server listening", "db", provider.Name(), "addr", addr)
	return sa
}

func (sa *SignalsApplication) Shutdown() {
	name := sa.Provider.Name()
	serverLog.Info("Shutdown initiated", "db", name)

	// Turn off Polling Clients
	sa.shutdownReceivers()

	// Turn off the server (if present)
	if sa.Server != nil {
		_ = sa.Server.Shutdown(context.Background())
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

	// Shutdown the provider
	_ = sa.Provider.Close()

	serverLog.Info("Shutdown Complete", "db", name)
}
