package tlsSupport

import (
	"errors"
	"net/url"
	"strings"
)

// ErrPlaintextNotAllowed is the single business-stream TLS-floor sentinel
// (ADR-0066 §2 as amended by ADR 0076, i2goSignals#322). The dialers
// (goSetSstp.Exchange, goSetPush.PushSET, goSetPoll.PollRaw) and the
// eventRouter status probe each wrap it with %w and the offending endpoint,
// so errors.Is(err, tlsSupport.ErrPlaintextNotAllowed) holds regardless of
// which package refused the dial. The per-package ErrPlaintextNotAllowed
// names are aliases of this value.
var ErrPlaintextNotAllowed = errors.New("plaintext endpoint not allowed (tx_allow_plaintext is false)")

// IsPlaintextEndpoint reports whether raw's scheme is anything other than
// https. It fails closed: an empty or scheme-less URL counts as plaintext.
// An unparseable URL is not reported here — http.NewRequest (or the
// delivery-method validator) reports it on the existing path; this check is
// only the TLS floor.
func IsPlaintextEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return !strings.EqualFold(u.Scheme, "https")
}
