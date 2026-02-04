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

	"github.com/i2-open/i2goSignals/internal/logger"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/mongo_provider"
	"github.com/i2-open/i2goSignals/pkg/constants"
	ssf "github.com/i2-open/i2goSignals/pkg/goSsfServer"
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

	var provider dbProviders.DbProviderInterface
	mongo, err := mongo_provider.Open(dbUrl, name)
	provider = mongo
	return provider, err
}

func main() {
	logger.Init(os.Getenv("LOG_LEVEL"))

	mLog.Info("i2goSSF server starting...", "version", constants.GoSignalsVersion)
	port := "8889"
	if found := stripQuotes(os.Getenv("PORT")); found != "" {
		port = found
	}

	mLog.Info("Listening on port", "port", port)

	dbUrl := "mongodb://root:dockTest@0.0.0.0:8880"
	if found := stripQuotes(os.Getenv("MONGO_URL")); found != "" {
		dbUrl = fmt.Sprintf("%v", found)
		mLog.Info("Connecting to MONGO_URL service", "url", dbUrl)
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
	err = ssfApplication.Server.ListenAndServe()
	if err != nil {
		mLog.Error("Server error", "error", err)
		os.Exit(-1)
	}
}
