package server

import (
	"context"
	"i2goSignals/internal/eventRouter"
	"i2goSignals/internal/model"
	"i2goSignals/internal/providers/dbProviders"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"
)

// var sa *SignalsApplication

var serverLog = log.New(os.Stdout, "SERVER: ", log.Ldate|log.Ltime)

type SignalsApplication struct {
	Provider      dbProviders.DbProviderInterface
	Server        *http.Server
	EventRouter   eventRouter.EventRouter
	BaseUrl       *url.URL
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

func StartServer(addr string, provider dbProviders.DbProviderInterface, baseUrlString string) *SignalsApplication {
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

	httpRouter := NewRouter(sa)

	server := http.Server{
		Addr:    addr,
		Handler: httpRouter.router,
	}
	serverLog.Printf("Server[%s] listening on %s", provider.Name(), addr)

	sa.Server = &server
	sa.EventRouter = eventRouter.NewRouter(provider)
	name := ""
	if server.TLSConfig != nil {
		name = server.TLSConfig.ServerName
	}

	var baseUrl *url.URL
	var err error
	if baseUrlString == "" {
		baseUrl, _ = url.Parse("http://" + server.Addr + "/")
	} else {
		baseUrl, err = url.Parse(baseUrlString)
		if err != nil {
			serverLog.Println("FATAL: Invalid Baseurl[%s]: %s", baseUrlString, err.Error())
		}
	}
	sa.BaseUrl = baseUrl

	sa.InitializePrometheus()

	if name != "" {
		serverLog.Println("TLS hostname: [" + name + "]")
	} else {
		serverLog.Println("TLS not configured.")
	}

	sa.HostName = name

	defaultIssuer, issDefined := os.LookupEnv("I2SIG_ISSUER")
	if !issDefined {
		defaultIssuer = "DEFAULT"
	}
	sa.DefIssuer = defaultIssuer
	serverLog.Printf("Selected issuer id: %s", sa.DefIssuer)

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
