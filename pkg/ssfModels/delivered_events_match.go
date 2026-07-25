package model

import (
	"regexp"
	"strings"
)

// MatchDeliveredEvents resolves a stream's requested event patterns against the
// transmitter's supported event URIs, returning the concrete events_delivered
// set (SSF 1.0 §7.1.1). It is the single implementation of the registration-time
// pattern -> URI semantics, living in the package that already owns
// events_delivered and carries no DAO dependency, so both the stream service and
// any consumer that needs to reason about a stream's negotiated event set share
// one matcher rather than a second profile-selection surface.
//
// Semantics (unchanged from the original StreamService implementation):
//   - an empty requested set yields an empty slice — nothing was asked for;
//   - a requested set whose first entry is "*" yields supported as-is, the
//     "give me everything you have" shorthand;
//   - otherwise every pattern is matched against every supported URI via
//     MatchesEventPattern, accumulating in pattern-major order.
//
// A pattern that matches nothing simply contributes nothing; a malformed pattern
// is skipped rather than being fatal, because events_requested is receiver-supplied
// and a bad glob must not fail an otherwise valid stream registration.
//
// This is deliberately NOT the routing-time check: by the time a SET is routed,
// events_delivered is already concrete, so matching an event's types against a
// stream uses an exact case-insensitive compare (see EventService), not globbing.
func MatchDeliveredEvents(requested []string, supported []string) []string {
	var delivered []string
	if len(requested) == 0 {
		return []string{}
	}
	if requested[0] == "*" {
		return supported
	}

	for _, reqUri := range requested {
		for _, eventUri := range supported {
			if MatchesEventPattern(reqUri, eventUri) {
				delivered = append(delivered, eventUri)
			}
		}
	}
	return delivered
}

// MatchesEventPattern reports whether a single events_requested pattern matches
// an event URI. Matching is case-insensitive and "*" is a wildcard run; a pattern
// that cannot be compiled returns false rather than panicking, so a malformed
// receiver-supplied glob is skipped instead of failing the caller.
//
// The comparison is an unanchored search, preserving the original behaviour: a
// pattern is satisfied when it occurs anywhere within the event URI.
func MatchesEventPattern(pattern string, eventUri string) bool {
	expr := "(?i)" + strings.ReplaceAll(pattern, "*", ".*")
	match, err := regexp.MatchString(expr, eventUri)
	if err != nil {
		return false
	}
	return match
}
