package model

import (
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/i2-open/i2goSignals/pkg/logger"
)

var eventCatalogLog = logger.Sub("EVENT_CATALOG")

// EnvEventTypesExtra names the server-level environment variable that extends
// the supported-event catalog with event type URIs this build has no compiled-in
// knowledge of.
//
// The catalog is what events_requested is negotiated against (SSF 1.0 §7.1.1),
// and the router matches a SET's types against the resulting events_delivered.
// A URI outside the catalog therefore intersects to nothing at registration and
// every SET carrying it is accepted, stored — and never routed. This variable is
// the supported way to carry a private or not-yet-published event vocabulary
// through goSignals without recompiling (issue #261).
const EnvEventTypesExtra = "I2SIG_EVENT_TYPES_EXTRA"

// extraEventTypesCache memoizes the parse keyed on the RAW environment value.
//
// Keying on the raw string rather than parsing once per process is what lets a
// test set the variable with t.Setenv and see it take effect, while still
// parsing — and WARN-ing about a bad entry — exactly once per distinct value
// instead of on every GetSupportedEvents call. GetSupportedEvents is on the
// stream-registration path and the validator-engagement fallback, so a WARN per
// call would be a per-SET log flood.
var extraEventTypesCache sync.Map // raw env value -> []string

// extraEventTypes returns the configured catalog extension, in the order the
// operator wrote it.
func extraEventTypes() []string {
	raw := os.Getenv(EnvEventTypesExtra)
	if raw == "" {
		return nil
	}
	if cached, ok := extraEventTypesCache.Load(raw); ok {
		return cached.([]string)
	}
	parsed := parseExtraEventTypes(raw)
	extraEventTypesCache.Store(raw, parsed)
	return parsed
}

// parseExtraEventTypes splits the raw environment value on commas and/or
// whitespace and keeps the entries that are usable event type URIs.
//
// An entry must be an ABSOLUTE URI: an event type is an identifier a peer sends
// on the wire, and a relative reference ("account-disabled") could never appear
// in a SET's events map, so admitting one would only advertise a value in
// events_supported that nothing can ever match. A rejected entry is named in a
// WARN because the failure is otherwise invisible — the stream registers, the
// SETs arrive, and they are silently never routed, which is the exact symptom
// this variable exists to cure.
// An entry already carried by the compiled-in packs — or repeated within the
// variable — is dropped: events_supported is a SET, and "*" resolves
// events_delivered straight out of it, so a duplicate would be advertised twice
// and negotiated twice onto every wildcard stream. The comparison is
// case-insensitive to match how the router compares a SET's types against
// events_delivered (pkg/services.matchesEventType).
func parseExtraEventTypes(raw string) []string {
	seen := make(map[string]struct{})
	for _, uri := range builtinEventTypes() {
		seen[strings.ToLower(uri)] = struct{}{}
	}

	var extra []string
	for _, entry := range strings.FieldsFunc(raw, isExtraEventSeparator) {
		parsed, err := url.Parse(entry)
		if err != nil || !parsed.IsAbs() {
			eventCatalogLog.Warn("Ignoring invalid entry in "+EnvEventTypesExtra+" - an event type must be an absolute URI",
				"entry", entry)
			continue
		}
		key := strings.ToLower(entry)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		extra = append(extra, entry)
	}
	return extra
}

func isExtraEventSeparator(r rune) bool {
	return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
}
