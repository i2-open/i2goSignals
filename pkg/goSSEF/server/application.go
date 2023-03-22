package server

import (
	"i2goSignals/internal/providers/dbProviders"
	"log"
	"net/http"
	"os"
)

var sa *SignalsApplication

type SignalsApplication struct {
	Provider  dbProviders.DbProviderInterface
	Server    *http.Server
	HostName  string
	DefIssuer string
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
	router := NewRouter()

	server := http.Server{
		Addr:    addr,
		Handler: router,
	}
	name := ""
	if server.TLSConfig != nil {
		name = server.TLSConfig.ServerName
	}
	log.Println("Server TLS hostname: \t[" + name + "]")
	if name == "" {
		name = "http://" + addr
		log.Println("Server default hostname:\t[" + name + "]")
	}

	defaultIssuer, issDefined := os.LookupEnv("I2SIG_ISSUER")
	if !issDefined {
		defaultIssuer = "DEFAULT"
	}
	sa = &SignalsApplication{
		Provider:  provider,
		Server:    &server,
		HostName:  name,
		DefIssuer: defaultIssuer,
	}

	return sa

}
