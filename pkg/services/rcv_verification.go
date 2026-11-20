package services

import (
	"os"
	"strings"
)

// rcvVerifyOnEstablishEnvVar opts a polling receiver into requesting a stream
// verification event from the transmitter once a stream is established (SSF 1.0
// §8.1.4.2). A receiver-initiated verification is legitimate behaviour, but it
// adds an outbound request (and retries when the transmitter rejects it), so it
// stays off by default and is enabled explicitly — e.g. by the OpenID SSF
// receiver conformance plan, which waits to observe the verification request.
const rcvVerifyOnEstablishEnvVar = "I2SIG_RCV_VERIFY_ON_ESTABLISH"

// RcvVerifyOnEstablishEnabled reports whether a polling receiver should request a
// verification event from the transmitter on stream establishment. True only when
// I2SIG_RCV_VERIFY_ON_ESTABLISH is a truthy value (true/1/enabled/yes,
// case-insensitive); unset or anything else means false.
func RcvVerifyOnEstablishEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(rcvVerifyOnEstablishEnvVar))) {
	case "true", "1", "enabled", "yes":
		return true
	default:
		return false
	}
}
