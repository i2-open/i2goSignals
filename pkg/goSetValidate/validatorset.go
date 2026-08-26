package goSetValidate

import (
	jsonv2 "encoding/json/v2"
	"errors"
	"sort"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSet/events"
)

// The two SSF stream-management event types. Aliased from pkg/goSet/events so
// there is exactly one definition of each URI in the repo.
const (
	SsfVerificationEventUri  = events.VerificationEventUri  // pkg/goSet/events
	SsfStreamUpdatedEventUri = events.StatusUpdatedEventUri // pkg/goSet/events
)

// ValidatorSet is a Registry narrowed to the event URIs one stream has engaged.
// Build it per receiver stream; the engaged-URI set is computed by the caller
// (normally from the stream's negotiated events_delivered) and passed in, so this
// package never reads stream state.
type ValidatorSet struct {
	registry *Registry
	engaged  map[string]struct{}
}

// NewValidatorSet narrows r to engagedURIs.
//
// engagedURIs are exact event-type URIs: any events_delivered glob expansion is
// the caller's job, since the matcher lives in pkg/ssfModels which this package
// may not import.
//
// The two SSF stream-management URIs are added unconditionally, so a narrowly
// scoped STRICT stream never rejects its own verification handshake or a status
// change it did not subscribe to. SSF §8.1.5 makes this normative for the Stream
// Updated event: a Transmitter MAY send it even when it appears in none of
// events_supported / events_requested / events_delivered.
//
// A nil registry falls back to BuiltinRegistry so the always-in-contract rule
// still holds for a caller that supplies no registry.
func NewValidatorSet(r *Registry, engagedURIs []string) *ValidatorSet {
	if r == nil {
		r = BuiltinRegistry()
	}

	// Engagement keys are case-folded for the same reason registry keys are: the
	// router matches event types case-insensitively, so engagement must too, or a
	// case-variant URI is routed but reported out-of-contract.
	engaged := make(map[string]struct{}, len(engagedURIs)+2)
	for _, uri := range engagedURIs {
		if uri != "" {
			engaged[registryKey(uri)] = struct{}{}
		}
	}
	engaged[registryKey(SsfVerificationEventUri)] = struct{}{}
	engaged[registryKey(SsfStreamUpdatedEventUri)] = struct{}{}

	return &ValidatorSet{registry: r, engaged: engaged}
}

// Validate reports a disposition for every event URI in set, plus the whole-SET
// worst-disposition-wins reduction.
//
// A nil *ValidatorSet is valid and reports the zero SetResult — that is the
// "validation not configured" case, and it must never look like a rejection.
//
// Results are emitted in stable lexicographic URI order. SecurityEventToken
// carries events in a Go map, which neither preserves JSON payload order nor
// iterates deterministically, so a sorted order is the only order callers, logs,
// and tests can actually rely on. The reduction is order-independent either way.
func (vs *ValidatorSet) Validate(set *goSet.SecurityEventToken) SetResult {
	if vs == nil || set == nil || len(set.Events) == 0 {
		return SetResult{Disposition: Valid}
	}

	uris := make([]string, 0, len(set.Events))
	for uri := range set.Events {
		uris = append(uris, uri)
	}
	sort.Strings(uris)

	results := make([]Result, 0, len(uris))
	worst := Valid

	for _, uri := range uris {
		result := vs.validateOne(uri, set.Events[uri], set)
		if result.EventURI == "" {
			// Defensive: a third-party validator that forgot to set EventURI must
			// not produce an unattributable Result.
			result.EventURI = uri
		}
		if result.Disposition > worst {
			worst = result.Disposition
		}
		results = append(results, result)
	}

	return SetResult{Disposition: worst, Results: results}
}

// validateOne resolves engagement, normalises the payload, and delegates.
func (vs *ValidatorSet) validateOne(uri string, rawPayload any, set *goSet.SecurityEventToken) Result {
	if _, engaged := vs.engaged[registryKey(uri)]; !engaged {
		// Out-of-contract for this stream — identical to unsupported (ADR 0029).
		return unsupported(uri)
	}

	validator, ok := vs.registry.Lookup(uri)
	if !ok {
		return unsupported(uri)
	}

	payload, err := normalizePayload(rawPayload)
	if err != nil {
		return malformed(uri, "", "event payload is not a JSON object (RFC 8417 §2.2): "+err.Error())
	}

	return validator.Validate(uri, payload, set)
}

// normalizePayload coerces whatever the SET carries for an event into a claim
// map: already a map from a wire parse, or a typed struct attached in-process via
// AddEventPayload (round-tripped through JSON so validators only ever see wire
// shapes).
//
// The round-trip runs on encoding/json/v2. It is the only JSON work this package
// does and the only allocation on its hot path, which made it the spec #101
// json/v2 pilot; v2 came in ~35% faster with ten fewer allocations per call and
// was adopted on that evidence. See docs/perf/go127-baseline.md and the A/B in
// normalize_pilot_test.go, which also pins that v2 decodes into an `any` with
// exactly the six wire types v1 used — the property isWireShape and every
// validator type assertion below rest on.
//
// One behaviour moves with the encoder: v2 REJECTS invalid UTF-8 in a string
// where v1 silently substituted U+FFFD. Such a payload can only arrive from an
// in-process Go string (RFC 8259 requires JSON text to be valid UTF-8, so it
// cannot come off the wire), and it now reports Malformed instead of validating
// a payload whose bytes had already been rewritten. That is the better of the
// two answers, and it is still a report rather than a rejection.
func normalizePayload(rawPayload any) (map[string]any, error) {
	if rawPayload == nil {
		return nil, errors.New("payload is null")
	}
	// A map is returned as-is ONLY when it already holds wire shapes all the way
	// down. Short-circuiting on the map type alone would skip the round-trip for
	// a map assembled in-process — AddEventPayload(uri, map[string]any{"data":
	// someStruct}) is a shape this repo's own event builders produce — and the
	// validators would then see a Go struct where they assert map[string]any and
	// report a perfectly conformant SET as Malformed.
	//
	// The check is a non-allocating type walk, so the common case (a payload that
	// came off the wire, which is wire-shaped by construction) still costs no
	// marshal/unmarshal on the receive hot path.
	if m, ok := rawPayload.(map[string]any); ok && isWireShape(m) {
		return m, nil
	}

	encoded, err := jsonv2.Marshal(rawPayload)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := jsonv2.Unmarshal(encoded, &m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("payload is null")
	}
	return m, nil
}

// isWireShape reports whether v is built exclusively from the types the JSON
// decoder produces when unmarshalling into an any: nil, bool, float64, string,
// []any and map[string]any. v1 and v2 agree on this set; normalize_pilot_test.go
// holds that agreement to a test.
//
// Anything else — a typed struct, a pointer, an int, a time.Time, a
// json.Number — means the value was assembled in-process rather than parsed off
// the wire, so normalizePayload must round-trip it before a validator sees it.
// Reporting false is always safe: the cost is one marshal/unmarshal.
func isWireShape(v any) bool {
	switch t := v.(type) {
	case nil, bool, float64, string:
		return true
	case []any:
		for _, e := range t {
			if !isWireShape(e) {
				return false
			}
		}
		return true
	case map[string]any:
		for _, e := range t {
			if !isWireShape(e) {
				return false
			}
		}
		return true
	default:
		return false
	}
}
