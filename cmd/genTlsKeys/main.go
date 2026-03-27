/*
genTlsKeys is a command line tool that can be used to generate a set of self-signed keys for use by
the goSignals development environment.

USAGE:

	genTlsKeys -type=tls
	genTlsKeys -type=jwt -action=init -dir=./certs

This will generate a CA cert/key pair and use that to sign Server cert/key pair
and Client cert/key pair.

Use these certs for tests such as websupport_test and orchestrator_test.
*/
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/i2-open/i2goSignals/pkg/constants"
)

func doTlsKeys() {
	config := GetKeyConfig()
	err := config.InitializeKeys()
	if err != nil {
		panic(err)
	}
}

var (
	typeFlag *string

	dirFlag *string

	helpFlag *bool
	keyPath  string
)

func init() {
	keyPath = os.Getenv(EnvCertDirectory)
	if keyPath == "" {
		keyPath = "config/certs"
	}

	dirFlag = flag.String("dir", keyPath, "filepath for storing keys")

	helpFlag = flag.Bool("help", false, "To return help")
}

func start() {
	fmt.Println(fmt.Sprintf("Key Tool (Version: %s)", constants.GoSignalsVersion))

	flag.Parse()

	arg := flag.Arg(0)
	if (helpFlag != nil && *helpFlag) || strings.EqualFold("help", arg) {
		fmt.Println(`
Generates certificates for use with GoSignals docker environment

To generate self-signed CA for use with TLS (ca-cert.pem):
genTlsKeys`)
		return
	}

	if dirFlag != nil {
		_ = os.Setenv(EnvCertDirectory, *dirFlag)
	} else {
		_ = os.Setenv(EnvCertDirectory, keyPath)
	}

	existDir := os.Getenv(EnvCertDirectory)
	certDir := existDir
	if dirFlag != nil && *dirFlag != "" {
		_ = os.Setenv(EnvCertDirectory, *dirFlag)
		certDir = *dirFlag
	}
	fmt.Println(fmt.Sprintf("\nInitializing self-signed CA keys for TLS in: %s", certDir))
	doTlsKeys()
	if existDir != "" {
		_ = os.Setenv(EnvCertDirectory, existDir)
	}
	return
}

func main() {
	start()
}
