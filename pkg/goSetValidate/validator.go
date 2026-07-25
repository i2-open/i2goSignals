package goSetValidate

import (
	"github.com/i2-open/i2goSignals/pkg/goSet"
)

// Validator validates one event type's payload.
//
// payload is the event's claim map, already normalised from whatever the SET
// carried (a JSON object from the wire, or a typed struct attached in-process via
// SecurityEventToken.AddEventPayload). set is the surrounding envelope, needed by
// event types whose spec puts required claims at the top level — both SSF
// stream-management events require a top-level sub_id.
//
// A Validator MUST NOT reject: it returns a Result and lets the caller apply
// policy. It MUST tolerate unknown extra claims (forward compatibility) and MUST
// NOT fail on an absent OPTIONAL or RECOMMENDED claim.
type Validator interface {
	Validate(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result
}

// ValidatorFunc adapts a plain function to Validator.
type ValidatorFunc func(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result

func (f ValidatorFunc) Validate(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
	return f(eventURI, payload, set)
}

// Registry maps event-type URIs to validators. It is built once and then read
// concurrently; Register is not safe against concurrent readers, so finish
// building before handing a Registry to a ValidatorSet.
type Registry struct {
	validators map[string]Validator
}

// NewRegistry returns an empty registry. Use BuiltinRegistry to start from the
// validators this repo ships.
func NewRegistry() *Registry {
	return &Registry{validators: make(map[string]Validator)}
}

// BuiltinRegistry returns a FRESH registry pre-loaded with the validators this
// repo ships. A new instance per call is deliberate: an embedder that chains
// Register onto the result must not mutate process-wide state that another
// embedder depends on.
func BuiltinRegistry() *Registry {
	r := NewRegistry().
		Register(SsfVerificationEventUri, ValidatorFunc(validateVerificationEvent)).
		Register(SsfStreamUpdatedEventUri, ValidatorFunc(validateStreamUpdatedEvent))

	r = registerCaepValidators(r)
	r = registerRiscValidators(r)
	r = registerScimValidators(r)

	// EXPERIMENTAL, and last on purpose: WISE is an unadopted proposal, so the
	// adopted packs above are what a receiver is actually promised. See wise.go.
	return registerWiseValidators(r)
}

// Register adds or replaces the validator for eventURI and returns the receiver
// so built-in packs and embedder registrations chain. An empty URI or a nil
// validator is ignored.
func (r *Registry) Register(eventURI string, v Validator) *Registry {
	if r == nil || eventURI == "" || v == nil {
		return r
	}
	if r.validators == nil {
		r.validators = make(map[string]Validator)
	}
	r.validators[eventURI] = v
	return r
}

// Lookup returns the validator registered for eventURI. A nil receiver reports a
// miss rather than panicking.
func (r *Registry) Lookup(eventURI string) (Validator, bool) {
	if r == nil {
		return nil, false
	}
	v, ok := r.validators[eventURI]
	return v, ok
}
