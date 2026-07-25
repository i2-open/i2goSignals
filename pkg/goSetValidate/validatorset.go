package goSetValidate

import (
	"encoding/json"
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

	engaged := make(map[string]struct{}, len(engagedURIs)+2)
	for _, uri := range engagedURIs {
		if uri != "" {
			engaged[uri] = struct{}{}
		}
	}
	engaged[SsfVerificationEventUri] = struct{}{}
	engaged[SsfStreamUpdatedEventUri] = struct{}{}

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
	if _, engaged := vs.engaged[uri]; !engaged {
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
func normalizePayload(rawPayload any) (map[string]any, error) {
	if rawPayload == nil {
		return nil, errors.New("payload is null")
	}
	if m, ok := rawPayload.(map[string]any); ok {
		return m, nil
	}

	encoded, err := json.Marshal(rawPayload)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(encoded, &m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("payload is null")
	}
	return m, nil
}
