package model

import (
	"fmt"
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
// A pattern that matches nothing simply contributes nothing. A pattern that does
// not compile contributes nothing either, but that case is not supposed to reach
// here: ValidateEventPatterns rejects it at registration so the receiver learns
// its pattern was bad instead of silently getting a narrower events_delivered.
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
// an event URI. Matching is case-insensitive, unanchored, and the pattern is a
// REGULAR EXPRESSION in which "*" is additionally rewritten to ".*" so the
// familiar glob shorthand ("urn:ietf:params:scim:event:prov:*") keeps working.
//
// Regex is the deliberate pattern language, not an accident of the
// implementation: a receiver selecting a subset of a 30-URI catalog wants
// alternation ("*:event:(feed|sig):*"), character classes and anchors, and the
// CLI and its tests have relied on that since the matcher was introduced. The
// price is that regex metacharacters in a URI-shaped pattern are live — "." is
// any-character rather than a literal dot — which is a widening a receiver opts
// into by writing one, not something the server does behind its back.
//
// A pattern that does not compile returns false. Callers must not rely on that
// as an error channel: ValidateEventPatterns rejects an uncompilable pattern at
// registration time, which is where a receiver can still act on it.
func MatchesEventPattern(pattern string, eventUri string) bool {
	match, err := regexp.MatchString(eventPatternExpr(pattern), eventUri)
	if err != nil {
		return false
	}
	return match
}

// ValidateEventPatterns reports the first events_requested pattern that is not a
// usable expression, naming it and the compile failure. Registration calls this
// before anything is persisted (spec #247): a pattern that cannot compile
// otherwise contributes no matches and the receiver is handed a silently
// narrower events_delivered — the stream looks registered but never carries the
// events that were asked for. Rejecting the registration surfaces the typo while
// the caller can still fix it.
//
// An empty or nil set is valid: it means "no explicit request", which the stream
// service resolves to the full supported catalog.
func ValidateEventPatterns(requested []string) error {
	for _, pattern := range requested {
		if _, err := regexp.Compile(eventPatternExpr(pattern)); err != nil {
			return fmt.Errorf("invalid events_requested pattern %q: %v", pattern, err)
		}
	}
	return nil
}

// eventPatternExpr is the single pattern -> expression transform shared by the
// matcher and the validator, so what is validated at registration is exactly
// what is compiled at match time.
func eventPatternExpr(pattern string) string {
	return "(?i)" + strings.ReplaceAll(pattern, "*", ".*")
}
