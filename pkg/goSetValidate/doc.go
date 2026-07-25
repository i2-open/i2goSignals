// Package goSetValidate validates the *semantics* of SET event payloads once the
// SET itself has passed signature / iss / aud verification.
//
// It is deliberately a reporting library, not a policy engine: it computes a
// per-event-URI Disposition and a whole-SET reduction, and it never rejects
// anything. The mode policy (NONE / WARN / ENFORCE / STRICT), the mapping from a
// disposition to a wire error, and any metrics live in the server wiring — see
// the "Event validation mode" glossary entry in CONTEXT.md and ADR 0029.
//
// # Shape
//
//	registry := goSetValidate.BuiltinRegistry()          // built-in validators
//	registry.Register(myUri, myValidator)                // embedder extension
//	vs := goSetValidate.NewValidatorSet(registry, engagedURIs)
//	set, result, err := goSetValidate.ParseAndValidate(wire, jwks, vs)
//
// engagedURIs is computed by the *caller* — normally from the stream's negotiated
// events_delivered set — and passed in. The package never looks at stream state,
// which is what keeps it standalone-consumable by a third-party SSF receiver and
// keeps the server's stream state inside internal/ (ADR 0049 r5).
//
// # Import boundary
//
// Per the standing pkg/goSet* rule and the #247 Slice Contract, this package
// imports only pkg/goSet, pkg/goSet/events, pkg/subjectid, the standard library,
// and github.com/MicahParks/keyfunc. TestPackageImportBoundary enforces it.
package goSetValidate
