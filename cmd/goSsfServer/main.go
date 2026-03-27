/*
 * SSF Test Server
 *
 * [OpenID Spec](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.txt)
 *
 */
package main

import (
	"fmt"
	"os"

	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/pkg/constants"
	ssf "github.com/i2-open/i2goSignals/pkg/goSsfServer"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
)

var mLog = logger.Sub("MAIN")

// stripQuotes removes surrounding double or single quotes from a string
func stripQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func StartProvider(dbUrl string) (dbProviders.DbProviderInterface, error) {

	name := "ssf"
	if found := stripQuotes(os.Getenv("DBNAME")); found != "" {
		mLog.Info("Using dbname", "name", found)
		name = found
	}

	return dbProviders.OpenProvider(dbUrl, name)
}

func main() {
	logger.Init(os.Getenv("LOG_LEVEL"))
	tlsSupport.CheckCaInstalled(nil)

	mLog.Info("i2goSSF server starting...", "version", constants.GoSignalsVersion)
	port := "8889"
	if found := stripQuotes(os.Getenv("PORT")); found != "" {
		port = found
	}

	dbUrl := ""
	if found := stripQuotes(os.Getenv("MONGO_URL")); found != "" {
		dbUrl = fmt.Sprintf("%v", found)
		mLog.Info("Connecting to MONGO_URL service", "url", dbUrl)
	} else {
		mLog.Info("MONGO_URL not set, using memory provider")
	}

	provider, err := StartProvider(dbUrl)
	if err != nil {
		mLog.Error("Fatal: Unable to start database provider", "error", err)
		os.Exit(-1)
	}
	defer func(provider dbProviders.DbProviderInterface) {
		err := provider.Close()
		if err != nil {
			mLog.Error("Fatal: Unable to close database provider", "error", err)
		}
	}(provider)

	baseUrl := "127.0.0.1:" + port + "/"
	if found := stripQuotes(os.Getenv("BASE_URL")); found != "" {
		baseUrl = found
	}
	mLog.Info("Base URL", "url", baseUrl)

	ssfApplication := ssf.StartServer(":"+port, provider, baseUrl)
	tlsMode, err := tlsSupport.InitTransportLayerSecurity(ssfApplication.Server)
	if err != nil {
		mLog.Error("Fatal: Unable to initialize TLS mode", "error", err)
		panic(err)
	}
	mLog.Info("HTTP Listening", "tls", tlsMode, "port", port)
	if tlsMode {
		err = ssfApplication.Server.ListenAndServeTLS("", "")
	} else {
		mLog.Warn("TLS not enabled, using HTTP")
		err = ssfApplication.Server.ListenAndServe()
	}

	if err != nil {
		mLog.Error("Server error", "error", err)
		os.Exit(-1)
	}
}
