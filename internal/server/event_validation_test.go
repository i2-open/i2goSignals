package server

import (
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSetValidate"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testMalformedUri   = goSetValidate.SsfStreamUpdatedEventUri
	testUnsupportedUri = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
	testValidUri       = goSetValidate.SsfVerificationEventUri
)

// newValidationStats builds a PrometheusHandler carrying only the
// event-validation counter, so the mode-matrix assertions below can read the
// counter without standing up the whole application.
func newValidationStats() *PrometheusHandler {
	return &PrometheusHandler{
		EventValidations: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "goSignals",
				Subsystem: "router",
				Name:      "event_validation_total",
			},
			[]string{"disposition", "mode", "transport"},
		),
	}
}

func validResult() goSetValidate.SetResult {
	return goSetValidate.SetResult{
		Disposition: goSetValidate.Valid,
		Results: []goSetValidate.Result{
			{EventURI: testValidUri, Disposition: goSetValidate.Valid},
		},
	}
}

func unsupportedResult() goSetValidate.SetResult {
	return goSetValidate.SetResult{
		Disposition: goSetValidate.Unsupported,
		Results: []goSetValidate.Result{
			{EventURI: testUnsupportedUri, Disposition: goSetValidate.Unsupported},
		},
	}
}

func malformedResult() goSetValidate.SetResult {
	return goSetValidate.SetResult{
		Disposition: goSetValidate.Malformed,
		Results: []goSetValidate.Result{
			{
				EventURI:    testMalformedUri,
				Disposition: goSetValidate.Malformed,
				Claim:       "status",
				Detail:      "status \"bogus\" is outside the allowable values",
			},
		},
	}
}

// TestEventValidationModeMatrix is the combinatorial seam the spec asks for: the
// full mode × disposition matrix from #247 asserted once, transport-independent,
// so the integration suites only need one thin per-transport smoke test each.
func TestEventValidationModeMatrix(t *testing.T) {
	cases := []struct {
		name       string
		mode       model.EventValidationMode
		result     goSetValidate.SetResult
		wantReject bool
	}{
		// NONE — behaviorally identical to today's forwarding.
		{"none/valid", model.EventValidationNone, validResult(), false},
		{"none/unsupported", model.EventValidationNone, unsupportedResult(), false},
		{"none/malformed", model.EventValidationNone, malformedResult(), false},

		// WARN — wire-invisible; malformed is logged and still forwarded.
		{"warn/valid", model.EventValidationWarn, validResult(), false},
		{"warn/unsupported", model.EventValidationWarn, unsupportedResult(), false},
		{"warn/malformed", model.EventValidationWarn, malformedResult(), false},

		// ENFORCE — "what I recognize must be well-formed".
		{"enforce/valid", model.EventValidationEnforce, validResult(), false},
		{"enforce/unsupported", model.EventValidationEnforce, unsupportedResult(), false},
		{"enforce/malformed", model.EventValidationEnforce, malformedResult(), true},

		// STRICT — firewall: everything must be vouched for.
		{"strict/valid", model.EventValidationStrict, validResult(), false},
		{"strict/unsupported", model.EventValidationStrict, unsupportedResult(), true},
		{"strict/malformed", model.EventValidationStrict, malformedResult(), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, transport := range []string{validationTransportPush, validationTransportPoll} {
				stats := newValidationStats()
				decision := applyEventValidation(tc.mode, transport, "sid-1", "jti-1", tc.result, stats)

				assert.Equal(t, tc.wantReject, decision.Reject,
					"reject decision for mode=%s transport=%s", tc.mode, transport)
				if tc.wantReject {
					assert.Equal(t, "invalid_request", decision.ErrCode,
						"both transports report the shared invalid_request code")
					assert.NotEmpty(t, decision.Description)
				} else {
					assert.Empty(t, decision.ErrCode)
					assert.Empty(t, decision.Description)
				}
			}
		})
	}
}

// TestEventValidationCounter covers the observability AC: the counter is labeled
// disposition × mode × transport and increments under WARN too, where the wire
// response is unchanged and the counter is the ONLY machine-readable signal.
func TestEventValidationCounter(t *testing.T) {
	stats := newValidationStats()

	applyEventValidation(model.EventValidationWarn, validationTransportPush, "sid", "jti-1", malformedResult(), stats)
	applyEventValidation(model.EventValidationWarn, validationTransportPush, "sid", "jti-2", malformedResult(), stats)
	applyEventValidation(model.EventValidationWarn, validationTransportPoll, "sid", "jti-3", validResult(), stats)
	applyEventValidation(model.EventValidationStrict, validationTransportPoll, "sid", "jti-4", unsupportedResult(), stats)

	assert.Equal(t, 2.0, testutil.ToFloat64(
		stats.EventValidations.WithLabelValues("malformed", "WARN", "push")),
		"WARN forwards on the wire but must still be counted")
	assert.Equal(t, 1.0, testutil.ToFloat64(
		stats.EventValidations.WithLabelValues("valid", "WARN", "poll")))
	assert.Equal(t, 1.0, testutil.ToFloat64(
		stats.EventValidations.WithLabelValues("unsupported", "STRICT", "poll")))

	// NONE builds no validator set, so it computes no disposition and must not
	// pollute the counter with a meaningless always-"valid" series.
	applyEventValidation(model.EventValidationNone, validationTransportPush, "sid", "jti-5", validResult(), stats)
	assert.Equal(t, 0.0, testutil.ToFloat64(
		stats.EventValidations.WithLabelValues("valid", "NONE", "push")))
}

// TestEventValidationNilStats pins the harness contract: the receive paths hand
// through whatever statsFor returns, which is nil before InitializePrometheus.
func TestEventValidationNilStats(t *testing.T) {
	decision := applyEventValidation(model.EventValidationEnforce, validationTransportPush,
		"sid", "jti", malformedResult(), nil)
	assert.True(t, decision.Reject, "policy must not depend on metrics being wired")
}

// TestEventValidationRejectionDescription covers the AC that the wire body names
// the offending event URI and the failing claim.
func TestEventValidationRejectionDescription(t *testing.T) {
	malformed := applyEventValidation(model.EventValidationEnforce, validationTransportPush,
		"sid", "jti", malformedResult(), nil)
	assert.Contains(t, malformed.Description, testMalformedUri, "description names the event URI")
	assert.Contains(t, malformed.Description, "status", "description names the failing claim")

	unsupported := applyEventValidation(model.EventValidationStrict, validationTransportPoll,
		"sid", "jti", unsupportedResult(), nil)
	assert.Contains(t, unsupported.Description, testUnsupportedUri)
	assert.Contains(t, unsupported.Description, "STRICT")
}

// TestEventValidationWorstDispositionWins covers the multi-URI AC: a SET whose
// companion payload is unrecognized forwards under ENFORCE and is rejected whole
// under STRICT, and the attribution follows the deciding disposition.
func TestEventValidationWorstDispositionWins(t *testing.T) {
	mixed := goSetValidate.SetResult{
		Disposition: goSetValidate.Unsupported, // max(Valid, Unsupported)
		Results: []goSetValidate.Result{
			{EventURI: testValidUri, Disposition: goSetValidate.Valid},
			{EventURI: testUnsupportedUri, Disposition: goSetValidate.Unsupported},
		},
	}

	forwarded := applyEventValidation(model.EventValidationEnforce, validationTransportPush,
		"sid", "jti", mixed, nil)
	assert.False(t, forwarded.Reject, "ENFORCE forwards an unrecognized companion payload")

	rejected := applyEventValidation(model.EventValidationStrict, validationTransportPush,
		"sid", "jti", mixed, nil)
	assert.True(t, rejected.Reject, "STRICT rejects the whole SET")
	assert.Contains(t, rejected.Description, testUnsupportedUri,
		"the description is attributed to the URI that decided the rejection")
	assert.NotContains(t, rejected.Description, testValidUri)

	// A malformed payload outranks an unsupported companion, so it decides both
	// the reject and the attribution.
	worse := goSetValidate.SetResult{
		Disposition: goSetValidate.Malformed,
		Results: []goSetValidate.Result{
			{EventURI: testUnsupportedUri, Disposition: goSetValidate.Unsupported},
			{EventURI: testMalformedUri, Disposition: goSetValidate.Malformed, Claim: "status", Detail: "bad"},
		},
	}
	decision := applyEventValidation(model.EventValidationEnforce, validationTransportPoll,
		"sid", "jti", worse, nil)
	assert.True(t, decision.Reject)
	assert.Contains(t, decision.Description, testMalformedUri)
}

// TestEventValidationZeroResultForwards pins the "validation not configured"
// path: a nil validator set leaves a zero SetResult, which must read as forward
// on every mode rather than as a rejection.
func TestEventValidationZeroResultForwards(t *testing.T) {
	for _, mode := range []model.EventValidationMode{
		model.EventValidationNone, model.EventValidationWarn,
		model.EventValidationEnforce, model.EventValidationStrict,
	} {
		decision := applyEventValidation(mode, validationTransportPush, "sid", "jti",
			goSetValidate.SetResult{}, nil)
		assert.False(t, decision.Reject, "zero SetResult must forward under %s", mode)
	}
}

// TestBuildReceiveValidatorSet pins the NONE short-circuit: under the default
// posture no validator set is built at all, so the receiver libraries take
// exactly their pre-#247 path rather than validating and discarding the answer.
func TestBuildReceiveValidatorSet(t *testing.T) {
	rec := &model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			EventsDelivered: []string{testUnsupportedUri},
		},
	}

	assert.Nil(t, buildReceiveValidatorSet(rec, model.EventValidationNone))
	assert.Nil(t, buildReceiveValidatorSet(rec, model.EventValidationUnset))
	assert.NotNil(t, buildReceiveValidatorSet(rec, model.EventValidationWarn))
	assert.NotNil(t, buildReceiveValidatorSet(rec, model.EventValidationEnforce))
	assert.NotNil(t, buildReceiveValidatorSet(rec, model.EventValidationStrict))
}

// TestEngagedEventUris covers the AC that engagement derives from the negotiated
// delivered-event set through the exported pkg/ssfModels matcher.
func TestEngagedEventUris(t *testing.T) {
	assert.Nil(t, engagedEventUris(nil))

	// A concrete delivered set passes through unchanged.
	concrete := engagedEventUris(&model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			EventsDelivered: []string{model.EventScimCreateFull},
			EventsSupported: model.GetSupportedEvents(),
		},
	})
	assert.Equal(t, []string{model.EventScimCreateFull}, concrete)

	// A stream still carrying a pattern engages every matching URI rather than
	// none — that is what routing engagement through the matcher buys.
	wildcard := engagedEventUris(&model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			EventsDelivered: []string{"*"},
		},
	})
	require.NotEmpty(t, wildcard)
	assert.Equal(t, model.GetSupportedEvents(), wildcard,
		"\"*\" falls back to the server's supported set when the peer advertised none")

	scoped := engagedEventUris(&model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			EventsDelivered: []string{"urn:ietf:params:scim:event:prov:*"},
			EventsSupported: model.GetSupportedEvents(),
		},
	})
	require.NotEmpty(t, scoped)
	assert.Contains(t, scoped, model.EventScimActivate)
	assert.NotContains(t, scoped, testUnsupportedUri, "a RISC URI is outside the SCIM prov pattern")
}

// A stream persisted with an empty events_delivered never negotiated one — the
// pre-#247 CreateStream only populated it when the registration supplied
// events_requested, so every stream registered without it has [] in Mongo.
// Engaging nothing for those makes STRICT reject 100% of their traffic while an
// identically-configured new stream (which gets the full-catalog default) works.
func TestEngagedEventUris_EmptyDeliveredEngagesSupportedSet(t *testing.T) {
	legacy := engagedEventUris(&model.StreamStateRecord{})
	assert.Equal(t, model.GetSupportedEvents(), legacy,
		"a stream that never negotiated events_delivered must engage what this server supports")

	// The consequence that matters: a supported event type on such a stream is no
	// longer reported out-of-contract, so STRICT stops rejecting everything. The
	// same URI is the Unsupported fixture elsewhere in this file precisely because
	// those streams scope events_delivered narrowly.
	vs := buildReceiveValidatorSet(&model.StreamStateRecord{}, model.EventValidationStrict)
	require.NotNil(t, vs)
	result := vs.Validate(unsupportedEventSetForTest("stream-legacy"))
	assert.NotEqual(t, goSetValidate.Unsupported, result.Disposition,
		"a legacy stream must not report every supported event type as out-of-contract")

	// An explicitly advertised events_supported still narrows the fallback.
	narrow := engagedEventUris(&model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			EventsSupported: []string{model.EventScimCreateFull},
		},
	})
	assert.Equal(t, []string{model.EventScimCreateFull}, narrow)
}

// TestEngagedEventUrisAlwaysInContractStreamManagement pins story 11: a narrowly
// scoped STRICT stream never rejects its own verification handshake, because
// NewValidatorSet engages the two SSF stream-management URIs unconditionally even
// though engagedEventUris never returns them.
func TestEngagedEventUrisAlwaysInContractStreamManagement(t *testing.T) {
	rec := &model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			EventsDelivered: []string{model.EventScimCreateFull},
			EventsSupported: model.GetSupportedEvents(),
		},
	}
	engaged := engagedEventUris(rec)
	assert.NotContains(t, engaged, goSetValidate.SsfVerificationEventUri,
		"the SSF URIs are not part of the negotiated delivered set")

	// Build the set the receive path would build and confirm a well-formed
	// verification event still validates clean under STRICT.
	vs := buildReceiveValidatorSet(rec, model.EventValidationStrict)
	require.NotNil(t, vs)
	set := verificationSetForTest("stream-1", "opaque-state")
	result := vs.Validate(set)
	assert.Equal(t, goSetValidate.Valid, result.Disposition,
		"a STRICT stream must not reject its own verification handshake")
	assert.False(t, rejectsDisposition(model.EventValidationStrict, result.Disposition))
}

// TestResolveReceiveValidationMode pins the nil-StreamService guard the narrow
// unit harnesses depend on, plus the per-stream-over-default precedence.
func TestResolveReceiveValidationMode(t *testing.T) {
	inbound := &model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Delivery: &model.OneOfStreamConfigurationDelivery{
				PushReceiveMethod: &model.PushReceiveMethod{Method: model.ReceivePush},
			},
		},
		EventValidation: model.EventValidationStrict,
	}
	assert.Equal(t, model.EventValidationStrict, resolveReceiveValidationMode(nil, inbound))

	unset := &model.StreamStateRecord{
		StreamConfiguration: inbound.StreamConfiguration,
	}
	assert.Equal(t, model.EventValidationNone, resolveReceiveValidationMode(nil, unset),
		"no per-stream value and no server default resolves to NONE")
}
