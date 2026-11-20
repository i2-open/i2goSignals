package services

import (
	"os"
	"strings"
)

// strictSsfEnvVar is the opt-in switch that makes the standalone goSsfServer
// simulator present itself as a strict-spec, administrator-provisioned SSF
// transmitter. See ADR 0025.
const strictSsfEnvVar = "I2SIG_STRICT_SSF"

// StrictSsfEnabled reports whether strict SSF mode is requested. True only when
// I2SIG_STRICT_SSF is a truthy value (true/1/enabled/yes, case-insensitive);
// unset or any other value means false.
//
// Strict mode is consumed only by cmd/goSsfServer (the SSF-server simulator),
// where it requires the transmitter to be backed by an administrator-declared
// issuer (I2SIG_ISSUER_DEFAULT) whose SET-signing key is provisioned up front,
// binding iss == discovery issuer == JWKS key name (ADR 0023). The base-URL /
// "DEFAULT" fallback that the default mode allows is refused (see
// goSsfServer.SsfApplication.ProvisionStrictMode). It does not change the
// /stream registration contract, and cmd/goSignalsServer does not consult it.
func StrictSsfEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(strictSsfEnvVar))) {
	case "true", "1", "enabled", "yes":
		return true
	default:
		return false
	}
}
