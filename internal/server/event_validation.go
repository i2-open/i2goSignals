package server

import (
	"fmt"

	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	"github.com/i2-open/i2goSignals/pkg/goSetValidate"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// Receive-transport labels for the event-validation counter. Deliberately a
// closed pair of constants: the label is low-cardinality by contract.
const (
	validationTransportPush = "push"
	validationTransportPoll = "poll"
)

// validationRejectionErrCode is the wire error both transports report for a SET
// rejected by event validation. RFC8935 §2.4 makes invalid_request the code for a
// non-conformant event payload, and RFC8936 §7.1.2 shares that registry, so poll's
// setErrs entry and push's 400 body carry the same code.
const validationRejectionErrCode = goSetPush.ErrInvalidRequest

// eventValidationDecision is the wire decision for one inbound SET, derived from
// the dispositions the receiver library computed and the stream's resolved
// event_validation mode.
//
// The libraries never reject; this type is where a disposition first becomes a
// wire outcome (spec #247 #251). Reject == false is the forward path, and the
// zero value is therefore "forward", which is what makes NONE free.
type eventValidationDecision struct {
	// Reject is true when the mode says this SET must not reach the event router.
	Reject bool

	// ErrCode is the RFC8935 §2.4 / RFC8936 §7.1.2 error code to report. Always
	// goSetPush.ErrInvalidRequest ("invalid_request") when Reject is true: the
	// registry's non-conformant-payload code is shared by both transports.
	ErrCode string

	// Description names the offending event URI and, for a malformed payload, the
	// failing claim.
	Description string
}

// resolveReceiveValidationMode returns the effective inbound event_validation
// mode for rec, resolving an unset per-stream value against the server default
// the StreamService was constructed with (I2SIG_STREAM_EVENT_VALIDATION).
//
// A nil StreamService resolves against no server default rather than panicking,
// so the receive paths stay drivable from the narrow unit-test harnesses that
// build a SignalsApplication by hand.
func resolveReceiveValidationMode(ss *services.StreamService, rec *model.StreamStateRecord) model.EventValidationMode {
	if ss == nil {
		return services.ResolveEventValidationMode(rec, model.EventValidationUnset)
	}
	return ss.ResolveEventValidation(rec)
}

// engagedEventUris derives the validator-engagement set for a receiver stream
// from its negotiated events_delivered, expanding it through the exported
// pkg/ssfModels matcher so exactly one pattern→URI surface exists in the repo
// (spec #247 story 20).
//
// events_delivered is already concrete by the time a SET is received — it was
// resolved to events_requested ∩ events_supported at registration — so the
// expansion is normally the identity. It still earns its keep for a stream whose
// stored events_delivered carries a pattern (notably "*"), which then engages
// every matching URI instead of none.
//
// A URI this server does not know is deliberately left OUT of the engaged set:
// no validator could vouch for it either way, so it reports Unsupported whether
// it is engaged or not. The two SSF stream-management URIs are added
// unconditionally by goSetValidate.NewValidatorSet and are not this function's
// concern.
func engagedEventUris(rec *model.StreamStateRecord) []string {
	if rec == nil {
		return nil
	}
	delivered := rec.StreamConfiguration.EventsDelivered
	if len(delivered) == 0 {
		return nil
	}
	supported := rec.StreamConfiguration.EventsSupported
	if len(supported) == 0 {
		supported = model.GetSupportedEvents()
	}
	return model.MatchDeliveredEvents(delivered, supported)
}

// buildReceiveValidatorSet returns the validator set a receiver stream should
// hand to its transport adapter, or nil when mode is NONE.
//
// Returning nil under NONE is the point: a nil *ValidatorSet makes the receiver
// libraries skip validation entirely, so NONE is byte-for-byte the pre-#247
// receive path rather than "validate and then ignore the answer".
func buildReceiveValidatorSet(rec *model.StreamStateRecord, mode model.EventValidationMode) *goSetValidate.ValidatorSet {
	if mode == model.EventValidationNone || mode == model.EventValidationUnset {
		return nil
	}
	return goSetValidate.NewValidatorSet(goSetValidate.BuiltinRegistry(), engagedEventUris(rec))
}

// rejectsDisposition reports whether mode rejects a whole-SET disposition.
//
// This is the mode × disposition matrix from spec #247, and the only place it is
// written down in code:
//
//	                       NONE   WARN   ENFORCE  STRICT
//	Valid                  fwd    fwd    fwd      fwd
//	Unsupported            fwd    fwd    fwd      reject
//	Malformed              fwd    fwd*   reject   reject
//
//	(*) WARN forwards but logs — see applyEventValidation. There is no
//	    silent-drop mode; a WARN-first rollout is the poison-pill mitigation.
func rejectsDisposition(mode model.EventValidationMode, d goSetValidate.Disposition) bool {
	switch mode {
	case model.EventValidationEnforce:
		return d == goSetValidate.Malformed
	case model.EventValidationStrict:
		// STRICT is the firewall posture: every event must be vouched for, so
		// Unsupported (== out-of-contract) rejects alongside Malformed. This is
		// why the constants ascend in severity.
		return d >= goSetValidate.Unsupported
	default:
		// NONE and WARN never reject. An unrecognized mode is treated as NONE,
		// matching StreamService's unset/unrecognized defaulting.
		return false
	}
}

// describeValidationRejection builds the claim-level error description that goes
// on the wire, naming the event URI and — for a malformed payload — the failing
// claim (RFC8935 §2.4 covers non-conformant event payloads; RFC8936 §7.1.2
// shares the registry).
//
// The whole-SET disposition is the worst of the per-URI results, so the
// description is attributed to the first result carrying that disposition.
func describeValidationRejection(result goSetValidate.SetResult) string {
	for _, r := range result.Results {
		if r.Disposition != result.Disposition {
			continue
		}
		switch r.Disposition {
		case goSetValidate.Malformed:
			if r.Claim != "" {
				return fmt.Sprintf("The event payload for %q is not conformant: claim %q: %s",
					r.EventURI, r.Claim, r.Detail)
			}
			return fmt.Sprintf("The event payload for %q is not conformant: %s", r.EventURI, r.Detail)
		case goSetValidate.Unsupported:
			return fmt.Sprintf("The event type %q is not vouched for by any validator engaged on this stream "+
				"(event_validation=STRICT)", r.EventURI)
		}
	}
	// Unreachable for a rejecting disposition, since the worst disposition is by
	// construction one of the results. Kept so a future disposition cannot ship a
	// rejection with an empty description.
	return "The SET carries an event payload that failed event validation."
}

// applyEventValidation is the whole of the server-side event_validation policy:
// it counts the disposition, logs it, and returns the wire decision.
//
// Called once per inbound SET on each receive transport, AFTER the receiver
// library has settled signature/iss/aud and computed dispositions, and BEFORE
// the SET reaches the event router. result is whatever the library reported —
// the zero SetResult when validation was not engaged, which decides "forward"
// through every branch below.
//
// stats may be nil (test harnesses without a metrics registry); the counter
// helper is nil-safe.
func applyEventValidation(
	mode model.EventValidationMode,
	transport string,
	sid string,
	jti string,
	result goSetValidate.SetResult,
	stats *PrometheusHandler,
) eventValidationDecision {
	// NONE is the pre-#247 path: no validator set was built, so there is nothing
	// to count and nothing to log. Returning early keeps the default posture free
	// rather than merely cheap.
	if mode == model.EventValidationNone || mode == model.EventValidationUnset {
		return eventValidationDecision{}
	}

	stats.RecordEventValidation(result.Disposition.String(), string(mode), transport)

	reject := rejectsDisposition(mode, result.Disposition)

	// Log every per-URI finding, not just the one that decided the SET: an
	// operator staging a rollout on WARN needs the full list to know what
	// ENFORCE would start rejecting.
	for _, r := range result.Results {
		switch r.Disposition {
		case goSetValidate.Malformed:
			// A malformed payload is an operator-actionable peer defect, so WARN
			// even when the mode forwards it — that IS the WARN mode's product.
			serverLog.Warn("EVENT-VALIDATION: malformed event payload",
				"transport", transport, "sid", sid, "jti", jti,
				"mode", string(mode), "event_uri", r.EventURI,
				"claim", r.Claim, "detail", r.Detail, "rejected", reject)
		case goSetValidate.Unsupported:
			// Unsupported is the normal state of any event type no validator pack
			// covers yet, so it is DEBUG — it would otherwise be pure noise on a
			// WARN or ENFORCE stream.
			serverLog.Debug("EVENT-VALIDATION: unsupported event type",
				"transport", transport, "sid", sid, "jti", jti,
				"mode", string(mode), "event_uri", r.EventURI, "rejected", reject)
		}
	}

	if !reject {
		return eventValidationDecision{}
	}
	return eventValidationDecision{
		Reject:      true,
		ErrCode:     validationRejectionErrCode,
		Description: describeValidationRejection(result),
	}
}

// statsFor returns the Prometheus handler behind an application interface, or
// nil when the value is not the concrete application (handler unit tests and
// split-router harnesses run without metrics). Mirrors the existing
// sa.(*SignalsApplication) narrowing in receivePushForStream.
func statsFor(sa SsfApplicationInterface) *PrometheusHandler {
	if app, ok := sa.(*SignalsApplication); ok {
		return app.Stats
	}
	return nil
}
