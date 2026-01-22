package server

import (
	"context"
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
}

func (sa *SignalsApplication) Name() string {
	if sa.Provider != nil {
		return sa.Provider.Name()
	}
	return "goSignals"
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

	sa := &SignalsApplication{
		Provider:      provider,
		AdminRole:     role,
		Auth:          provider.GetAuthIssuer(),
		pollClients:   map[string]*ClientPollStream{},
		pushReceivers: map[string]model.StreamStateRecord{},
	}

	httpRouter := NewRouter(sa)
	// expose the handler for external server usage (e.g., httptest.Server)
	sa.Handler = httpRouter.router

	sa.EventRouter = eventRouter.NewRouter(provider)

	var baseUrl *url.URL
	var err error
	if baseUrlString != "" {
		baseUrl, err = url.Parse(baseUrlString)
		if err != nil {
			serverLog.Error("FATAL: Invalid BaseUrl", "url", baseUrlString, "error", err)
		}
	}
	sa.BaseUrl = baseUrl

	sa.InitializePrometheus()

	// Set defaults
	defaultIssuer, issDefined := os.LookupEnv("I2SIG_ISSUER")
	if !issDefined {
		defaultIssuer = "DEFAULT"
	}
	sa.DefIssuer = defaultIssuer
	serverLog.Info("Selected issuer id", "issuer", sa.DefIssuer)

	sa.InitializeReceivers()
	return sa
}

// StartServer creates a real net/http server wrapping the application handler.
// This is used for production binaries. Tests can instead use NewApplication + httptest.Server.
func StartServer(addr string, provider dbProviders.DbProviderInterface, baseUrlString string) *SignalsApplication {
	sa := NewApplication(provider, baseUrlString)
	server := http.Server{
		Addr:    addr,
		Handler: sa.Handler,
	}
	sa.Server = &server
	if sa.BaseUrl == nil {
		baseUrl, _ := url.Parse("http://" + server.Addr + "/")
		sa.BaseUrl = baseUrl
	}
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
