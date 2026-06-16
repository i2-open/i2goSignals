package services

import (
	"os"
	"strings"
)

// txTLSSkipVerifyEnvVar is a server-wide default for new transmitter streams'
// tx_tls_skip_verify flag. It exists for deployments where the receiver presents
// a self-signed or otherwise unverifiable TLS cert — dev stacks, and the OpenID
// conformance suite (whose nginx serves a SAN-less self-signed cert, so Go's push
// client rejects it). A per-stream value set explicitly on the create request
// still applies; this only supplies the default when the request leaves it false.
const txTLSSkipVerifyEnvVar = "I2SIG_TX_TLS_SKIP_VERIFY"

// TxTLSSkipVerifyDefault reports whether new transmitter streams should default
// to skipping receiver TLS certificate verification. True only when
// I2SIG_TX_TLS_SKIP_VERIFY is a truthy value (true/1/enabled/yes,
// case-insensitive); unset or any other value means false (verify, the default).
func TxTLSSkipVerifyDefault() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(txTLSSkipVerifyEnvVar))) {
	case "true", "1", "enabled", "yes":
		return true
	default:
		return false
	}
}
