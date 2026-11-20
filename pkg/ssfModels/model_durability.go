package model

import (
	"fmt"
	"strings"
)

// DurabilityMode is the per-stream ingest durability knob (spec #111 Stage 3,
// issue #343, ADR 0045). Like RetentionWindowDays and EventValidation it is a
// goSignals operator knob kept OFF the SSF wire-format StreamConfiguration.
//
// DurabilityMajority (the default, also what an unset value means) keeps the
// ADR 0038 contract: a SET is acknowledged after a majority-committed store
// write. DurabilityLocal opts the stream into the node-local WAL, but only on
// a deployment running I2SIG_STORE_WAL=local; elsewhere the value is stored and
// reported yet the stream runs at majority.
type DurabilityMode string

const (
	// DurabilityUnset means no per-stream value: the stream runs at majority.
	DurabilityUnset DurabilityMode = ""
	// DurabilityMajority acknowledges after a majority-committed store write.
	DurabilityMajority DurabilityMode = "majority"
	// DurabilityLocal acknowledges after a node-local WAL fsync, when the
	// deployment allows it.
	DurabilityLocal DurabilityMode = "local"
)

// ParseDurabilityMode parses an operator-supplied durability value. Matching
// is case-insensitive and surrounding whitespace is ignored. An empty string
// parses to DurabilityUnset with a nil error; anything else unrecognized is an
// error naming the accepted values.
func ParseDurabilityMode(s string) (DurabilityMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return DurabilityUnset, nil
	case string(DurabilityMajority):
		return DurabilityMajority, nil
	case string(DurabilityLocal):
		return DurabilityLocal, nil
	default:
		return DurabilityUnset, fmt.Errorf("invalid durability %q: must be one of %s, %s", s, DurabilityMajority, DurabilityLocal)
	}
}

// IsLocal reports whether the stored value asks for local durability.
func (m DurabilityMode) IsLocal() bool {
	parsed, err := ParseDurabilityMode(string(m))
	return err == nil && parsed == DurabilityLocal
}
