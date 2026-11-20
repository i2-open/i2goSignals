package goSetValidate

import "fmt"

// Disposition is the outcome of validating one event payload.
//
// The constants are declared in ASCENDING SEVERITY so the whole-SET
// "worst-disposition-wins" reduction is a plain max over the per-URI results.
// Valid is the zero value, which is what lets a zero SetResult read as "nothing
// to report" rather than as a rejection.
type Disposition int

const (
	// Valid means the event URI was recognized by an engaged validator and the
	// payload was well-formed.
	Valid Disposition = iota

	// Unsupported means no validator was engaged for the event URI. This covers
	// both "nothing in the registry validates this URI" and "the URI is
	// out-of-contract for this stream" — ADR 0029 makes the two identical,
	// because in both cases nothing vouched for the payload.
	Unsupported

	// Malformed means the event URI was recognized by an engaged validator and
	// the payload failed one of its checks.
	Malformed
)

func (d Disposition) String() string {
	switch d {
	case Valid:
		return "valid"
	case Unsupported:
		return "unsupported"
	case Malformed:
		return "malformed"
	default:
		return fmt.Sprintf("Disposition(%d)", int(d))
	}
}

// Result is the disposition of a single event URI inside a SET.
type Result struct {
	EventURI    string
	Disposition Disposition
	Claim       string // failing claim name; empty unless Disposition == Malformed
	Detail      string // human-readable reason; empty unless Disposition == Malformed
}

// SetResult is the whole-SET decision plus the per-URI detail behind it.
//
// Rejection granularity is deliberately the whole SET: the router forwards raw
// signed tokens and never strips a payload, so a single bad payload colours the
// entire token.
type SetResult struct {
	Disposition Disposition // worst of Results; Valid for a SET with no events
	Results     []Result    // one entry per event URI in the SET
}

// valid builds the success Result for an event URI.
func valid(eventURI string) Result {
	return Result{EventURI: eventURI, Disposition: Valid}
}

// unsupported builds the "nothing vouched for this URI" Result.
func unsupported(eventURI string) Result {
	return Result{EventURI: eventURI, Disposition: Unsupported}
}

// malformed builds a failure Result naming the offending claim and why.
func malformed(eventURI, claim, detail string) Result {
	return Result{EventURI: eventURI, Disposition: Malformed, Claim: claim, Detail: detail}
}
