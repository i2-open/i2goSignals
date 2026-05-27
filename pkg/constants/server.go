package constants

import (
    _ "embed"
    "strings"
)

//go:embed version.txt
var versionFile string

// GoSignalsVersion is the project version. CI or release builds can override it with
//
//   go build -ldflags "-X github.com/i2-open/i2goSignals/pkg/constants.GoSignalsVersion=<tag>"
//
// When the linker has not set it, init() falls back to the embedded version.txt
// (the single source of truth, also read by the Makefile). The override must be a
// link-time constant — that's why this is a bare `var` rather than one with an
// initializer expression, which -X cannot replace.
var GoSignalsVersion string

func init() {
    if GoSignalsVersion == "" {
        GoSignalsVersion = strings.TrimSpace(versionFile)
    }
}

const BearerAuth = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
const RFC6749 = "urn:ietf:rfc:6749"

const SSF_VERSION = "1_0"