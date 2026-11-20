package eventRouter

import (
	"os"
	"strings"
)

// pushReceiverStatusDisabledEnvVar opts goSignals out of polling a PUSH
// receiver's /status endpoint. SSF (§7.1.3) and RFC 8935 place the stream
// status endpoint on the TRANSMITTER: a receiver controls status by POSTing to
// the transmitter's status endpoint, never the reverse. goSignals' T2 pre-flight
// and recovery loop nonetheless GET <push-endpoint>/status on the receiver, which
// is meaningful only for goSignals↔goSignals (SSTP) peers. A standard SSF
// receiver exposes no such endpoint (and the OpenID conformance suite fails the
// test on the unexpected request). Setting this skips the receiver status-poll
// and logs a warning instead; push delivery still works (a receiver pause is
// observed via the push response, not a status poll).
const pushReceiverStatusDisabledEnvVar = "I2SIG_PUSH_DISABLE_RECEIVER_STATUS"

// PushReceiverStatusDisabled reports whether goSignals must NOT poll a PUSH
// receiver's /status endpoint. True only when I2SIG_PUSH_DISABLE_RECEIVER_STATUS
// is a truthy value (true/1/enabled/yes, case-insensitive).
func PushReceiverStatusDisabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(pushReceiverStatusDisabledEnvVar))) {
	case "true", "1", "enabled", "yes":
		return true
	default:
		return false
	}
}
