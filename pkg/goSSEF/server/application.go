package server

import (
	"i2goSignals/internal/eventRouter"
	"i2goSignals/internal/providers/dbProviders"
	"log"
	"net/http"
	"os"
)

// var sa *SignalsApplication

type SignalsApplication struct {
	Provider    dbProviders.DbProviderInterface
	Server      *http.Server
	EventRouter eventRouter.EventRouter
	HostName    string
	DefIssuer   string
	AdminRole   string
	AdminUser   string
	AdminPwd    string
}

func (sa *SignalsApplication) Name() string {
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
		Provider:  provider,
		AdminRole: role,
		AdminUser: user,
		AdminPwd:  pwd,
	}

	router := NewRouter(sa)

	server := http.Server{
		Addr:    addr,
		Handler: router.router,
	}
	sa.Server = &server
	sa.EventRouter = eventRouter.NewRouter(sa)
	name := ""
	if server.TLSConfig != nil {
		name = server.TLSConfig.ServerName
	}
	log.Println("Server TLS hostname: \t[" + name + "]")
	if name == "" {
		name = "http://" + addr
		log.Println("Server default hostname:\t[" + name + "]")
	}
	sa.HostName = name

	defaultIssuer, issDefined := os.LookupEnv("I2SIG_ISSUER")
	if !issDefined {
		defaultIssuer = "DEFAULT"
	}
	sa.DefIssuer = defaultIssuer

	return sa
}
