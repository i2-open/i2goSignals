package server

import (
	"context"
	"i2goSignals/internal/eventRouter"
	"i2goSignals/internal/model"
	"i2goSignals/internal/providers/dbProviders"
	"log"
	"net/http"
	"os"
	"time"
)

// var sa *SignalsApplication

var serverLog = log.New(os.Stdout, "goSigServ: ", log.Ldate|log.Ltime)

type SignalsApplication struct {
	Provider      dbProviders.DbProviderInterface
	Server        *http.Server
	EventRouter   eventRouter.EventRouter
	HostName      string
	DefIssuer     string
	AdminRole     string
	AdminUser     string
	AdminPwd      string
	pollClients   map[string]*ClientPollStream
	pushReceivers map[string]model.StreamStateRecord
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
		log.Println("MongoProvider ping failed: " + err.Error())
		return false
	}
	return true
}

func StartServer(addr string, provider dbProviders.DbProviderInterface) *SignalsApplication {
	role := os.Getenv("SSEF_ADMIN_ROLE")
	if role == "" {
		role = "ADMIN"
	}

	user := os.Getenv("SSEF_ADMIN_USER")

	pwd := os.Getenv("SSEF_ADMIN_SECRET")

	sa := &SignalsApplication{
		Provider:      provider,
		AdminRole:     role,
		AdminUser:     user,
		AdminPwd:      pwd,
		pollClients:   map[string]*ClientPollStream{},
		pushReceivers: map[string]model.StreamStateRecord{},
	}

	router := NewRouter(sa)

	server := http.Server{
		Addr:    addr,
		Handler: router.router,
	}
	serverLog.Printf("Server[%s] listening on %s", provider.Name(), addr)

	sa.Server = &server
	sa.EventRouter = eventRouter.NewRouter(provider)
	name := ""
	if server.TLSConfig != nil {
		name = server.TLSConfig.ServerName
	}

	sa.InitializePrometheus()

	log.Println("Server TLS hostname: \t[" + name + "]")
	if name == "" {
		serverLog.Println("TLS not configured.")

	}
	sa.HostName = name

	defaultIssuer, issDefined := os.LookupEnv("I2SIG_ISSUER")
	if !issDefined {
		defaultIssuer = "DEFAULT"
	}
	sa.DefIssuer = defaultIssuer
	serverLog.Printf("Default issuer id: %s", sa.DefIssuer)

	sa.InitializeReceivers()
	return sa
}

func (sa *SignalsApplication) Shutdown() {
	name := sa.Provider.Name()
	serverLog.Printf("[%s] Shutdown initiated...", name)

	// Turn off Polling Clients
	sa.shutdownReceivers()

	// Turn off the server
	_ = sa.Server.Shutdown(context.Background())

	// Turn off client connections
	for _, client := range sa.pollClients {
		client.Close()
	}
	time.Sleep(time.Second)

	// Stop processing new events
	sa.EventRouter.Shutdown()

	// Give some time to ensure all ops are finished.
	time.Sleep(time.Second)

	// Shutdown the provider
	_ = sa.Provider.Close()

	serverLog.Printf("[%s] Shutdown Complete.", name)
}
