package server

import (
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetValidate"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testWiseCredentialRevokedUri = "https://schemas.openid.net/secevent/wise/event-type/credential-revoked"

// wiseSet builds a SET carrying one WISE credential-revoked event with the
// draft's REQUIRED subject (uri format) and credential_type claims.
func wiseSet(payload map[string]any) *goSet.SecurityEventToken {
	return &goSet.SecurityEventToken{
		SubjectId: &goSet.SubjectIdentifier{
			Format:                    "uri",
			UniformResourceIdentifier: goSet.UniformResourceIdentifier{Uri: "spiffe://example.org/workload/api"},
		},
		Events: map[string]interface{}{testWiseCredentialRevokedUri: payload},
	}
}

// The WISE validator pack must be reachable from a real receiver stream.
//
// Engagement intersects a stream's events_delivered with the supported-events
// catalog, so a validator whose URI the catalog omits can never be engaged: the
// event reports Unsupported instead, which ENFORCE forwards unvalidated and
// STRICT rejects. The four WISE types shipped in pkg/goSetValidate were exactly
// that — registered but absent from model.GetSupportedEvents(), and therefore
// dead code in the server (code-review finding on spec #247).
func TestEngagedEventUris_IncludesWise(t *testing.T) {
	engaged := engagedEventUris(&model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			EventsDelivered: []string{testWiseCredentialRevokedUri},
			EventsSupported: model.GetSupportedEvents(),
		},
	})

	assert.Equal(t, []string{testWiseCredentialRevokedUri}, engaged,
		"a WISE event a receiver negotiated must engage its validator")
}

// The "*" shorthand and the catalog default must both reach WISE too, so a
// stream that subscribed to everything gets WISE payloads checked.
func TestEngagedEventUris_WildcardReachesWise(t *testing.T) {
	engaged := engagedEventUris(&model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			EventsDelivered: []string{"*"},
		},
	})

	assert.Contains(t, engaged, testWiseCredentialRevokedUri,
		`"*" must engage the WISE pack along with everything else`)
}

// End-to-end through the set the receive path actually builds: a conformant WISE
// event validates clean, and a malformed one is caught rather than waved through
// as Unsupported.
func TestWiseValidationThroughReceiveValidatorSet(t *testing.T) {
	rec := &model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			EventsDelivered: []string{testWiseCredentialRevokedUri},
			EventsSupported: model.GetSupportedEvents(),
		},
	}

	vs := buildReceiveValidatorSet(rec, model.EventValidationEnforce)
	require.NotNil(t, vs)

	valid := vs.Validate(wiseSet(map[string]any{"credential_type": "x509"}))
	assert.Equal(t, goSetValidate.Valid, valid.Disposition,
		"a conformant WISE credential-revoked event must validate clean")

	// credential_type is REQUIRED by the WISE draft.
	missing := vs.Validate(wiseSet(map[string]any{"reason": "compromise"}))
	assert.Equal(t, goSetValidate.Malformed, missing.Disposition,
		"a WISE event missing a REQUIRED claim must be Malformed, not Unsupported")
	assert.True(t, rejectsDisposition(model.EventValidationEnforce, missing.Disposition),
		"ENFORCE must reject the malformed WISE payload it can now see")
}

// A WISE type the pack deliberately does not cover stays Unsupported: the
// catalog advertises only the validated subset, so an uncovered draft type is
// not engaged and is never vouched for by a validator nobody wrote.
func TestUncoveredWiseTypeStaysUnsupported(t *testing.T) {
	const uncovered = "https://schemas.openid.net/secevent/wise/event-type/credential-issued"

	assert.NotContains(t, model.GetSupportedEvents(), uncovered,
		"only the validated WISE subset may be advertised")

	engaged := engagedEventUris(&model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			EventsDelivered: []string{uncovered},
			EventsSupported: model.GetSupportedEvents(),
		},
	})
	assert.Empty(t, engaged, "an uncovered WISE type must not engage")
}
