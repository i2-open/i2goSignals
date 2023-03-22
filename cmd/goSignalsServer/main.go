/*
 * Stream Management API for OpenID Shared Security Events
 *
 * [OpenID Spec](https://openid.net/specs/openid-sse-framework-1_0.html#management)  HTTP API to be implemented by Event Transmitters. This API can be used by Event Receivers to query and update the Event Stream configuration and status, to add and remove subjects, and to trigger verification.
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package main

import (
	"fmt"
	"i2goSignals/internal/providers/dbProviders"
	"i2goSignals/internal/providers/dbProviders/mongo_provider"
	ssef "i2goSignals/pkg/goSSEF/server"
	"log"
	"net"
	"os"
)

func StartProvider(dbUrl string) (dbProviders.DbProviderInterface, error) {

	var provider dbProviders.DbProviderInterface
	mongo, err := mongo_provider.Open(dbUrl)
	provider = mongo
	return provider, err
}

func main() {
	log.Printf("i2goSignals Server starting...")
	addr := "0.0.0.0:8888"

	if found := os.Getenv("PORT"); found != "" {
		host, _, _ := net.SplitHostPort(addr)
		addr = fmt.Sprintf("%v:%v", host, found)
	}
	log.Printf("Found server address %v", addr)

	if found := os.Getenv("HOST"); found != "" {
		_, port, _ := net.SplitHostPort(addr)
		addr = fmt.Sprintf("%v:%v", found, port)
	}
	log.Printf("Found server host %v", addr)

	dbUrl := "mongodb://root:dockTest@0.0.0.0:8880"
	if found := os.Getenv("MONGO_URL"); found != "" {
		dbUrl = fmt.Sprintf("%v", found)
	}

	provider, err := StartProvider(dbUrl)
	if err != nil {
		log.Println("Fatal: Unable to start database provider: " + err.Error())
		os.Exit(-1)
	}

	listener, _ := net.Listen("tcp", addr)

	signalsApplication := ssef.StartServer(addr, provider)
	log.Fatal(signalsApplication.Server.Serve(listener))
}
