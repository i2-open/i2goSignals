package services

import (
	"context"
	"strings"
	"testing"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A registration that omits events_requested means "everything you support".
// Previously both events_requested and events_delivered were left empty, so the
// stream registered successfully and then delivered nothing at all.
func TestCreateStream_EmptyEventsRequestedDefaultsToAll(t *testing.T) {
	svc := newEventValidationTestService(model.EventValidationUnset)
	ctx := context.Background()

	req := pollReceiverRequest()
	require.Empty(t, req.EventsRequested, "fixture must omit events_requested")

	created, err := svc.CreateStream(ctx, req, "test-project", nil)
	require.NoError(t, err)

	supported := model.GetSupportedEvents()
	require.NotEmpty(t, supported, "the supported catalog must be non-empty for this test to mean anything")

	assert.ElementsMatch(t, supported, created.EventsRequested,
		"an omitted events_requested must default to the full supported catalog")
	assert.ElementsMatch(t, supported, created.EventsDelivered,
		"an omitted events_requested must deliver the full supported catalog")

	state, err := svc.GetStreamState(ctx, created.Id)
	require.NoError(t, err)
	assert.ElementsMatch(t, supported, state.StreamConfiguration.EventsRequested,
		"the default must be persisted, not just returned")
	assert.ElementsMatch(t, supported, state.StreamConfiguration.EventsDelivered)
}

// "*" is a non-standard goSignals shorthand accepted on the request only. SSF
// 1.0 §7.1.1 defines events_requested/events_delivered as sets of event type
// URIs, so a returned configuration must enumerate and never echo the pattern.
func TestCreateStream_StarShorthandIsEnumeratedNotEchoed(t *testing.T) {
	svc := newEventValidationTestService(model.EventValidationUnset)
	ctx := context.Background()

	req := pollReceiverRequest()
	req.EventsRequested = []string{"*"}

	created, err := svc.CreateStream(ctx, req, "test-project", nil)
	require.NoError(t, err)

	assert.NotContains(t, created.EventsRequested, "*",
		"the returned events_requested must not echo the shorthand")
	assert.NotContains(t, created.EventsDelivered, "*")
	assert.ElementsMatch(t, model.GetSupportedEvents(), created.EventsRequested,
		`"*" must expand to every supported event URI`)

	state, err := svc.GetStreamState(ctx, created.Id)
	require.NoError(t, err)
	assert.NotContains(t, state.StreamConfiguration.EventsRequested, "*",
		"the shorthand must not be persisted either")
}

// A partial glob is a pattern too and gets the same treatment: what is returned
// is the concrete set of URIs it selected.
func TestCreateStream_PartialGlobIsEnumerated(t *testing.T) {
	svc := newEventValidationTestService(model.EventValidationUnset)
	ctx := context.Background()

	supported := model.GetSupportedEvents()
	// Derive a prefix glob from a real catalog entry so the test does not encode
	// a particular event-type vocabulary.
	sample := supported[0]
	cut := strings.LastIndex(sample, ":")
	require.Positive(t, cut, "catalog URIs are expected to be colon-delimited")
	glob := sample[:cut+1] + "*"

	req := pollReceiverRequest()
	req.EventsRequested = []string{glob}

	created, err := svc.CreateStream(ctx, req, "test-project", nil)
	require.NoError(t, err)

	assert.NotContains(t, created.EventsRequested, glob,
		"a glob must be expanded, not stored verbatim")
	assert.Contains(t, created.EventsRequested, sample)
	assert.ElementsMatch(t, created.EventsDelivered, created.EventsRequested,
		"every URI a glob expands to is by construction deliverable")
}

// An explicitly requested URI is preserved verbatim, including one this
// transmitter does not support: events_requested records what the receiver asked
// for and events_delivered is the subset that was granted.
func TestCreateStream_ExplicitUrisArePreserved(t *testing.T) {
	svc := newEventValidationTestService(model.EventValidationUnset)
	ctx := context.Background()

	supported := model.GetSupportedEvents()
	unsupported := "urn:example:events:not-supported-by-this-transmitter"

	req := pollReceiverRequest()
	req.EventsRequested = []string{supported[0], unsupported}

	created, err := svc.CreateStream(ctx, req, "test-project", nil)
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{supported[0], unsupported}, created.EventsRequested,
		"an unsupported explicit request must still be recorded")
	assert.Equal(t, []string{supported[0]}, created.EventsDelivered,
		"only the supported subset may be delivered")
}

// events_requested, events_delivered and events_supported must not share a
// backing array — MatchDeliveredEvents returns supported as-is for "*", so
// without a copy a later mutation of one field would corrupt the others.
func TestCreateStream_EventSetsDoNotAlias(t *testing.T) {
	svc := newEventValidationTestService(model.EventValidationUnset)
	ctx := context.Background()

	req := pollReceiverRequest()
	req.EventsRequested = []string{"*"}

	created, err := svc.CreateStream(ctx, req, "test-project", nil)
	require.NoError(t, err)
	require.NotEmpty(t, created.EventsDelivered)

	original := created.EventsSupported[0]
	created.EventsDelivered[0] = "urn:example:mutated"

	assert.Equal(t, original, created.EventsSupported[0],
		"mutating events_delivered must not disturb events_supported")
	assert.NotEqual(t, "urn:example:mutated", created.EventsRequested[0],
		"mutating events_delivered must not disturb events_requested")
}

// UpdateStream re-negotiates against the stream's own catalog: a PATCH body
// carries no events_supported (it is Read-Only per SSF 1.0 §7.1.1), and the
// shorthand must be enumerated on this path too.
func TestUpdateStream_StarShorthandIsEnumerated(t *testing.T) {
	svc := newEventValidationTestService(model.EventValidationUnset)
	ctx := context.Background()

	created, err := svc.CreateStream(ctx, pollReceiverRequest(), "test-project", nil)
	require.NoError(t, err)

	patched, err := svc.UpdateStream(ctx, created.Id, "test-project", model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{EventsRequested: []string{"*"}},
	})
	require.NoError(t, err)

	assert.NotContains(t, patched.EventsRequested, "*",
		"a patched events_requested must not echo the shorthand")
	assert.ElementsMatch(t, model.GetSupportedEvents(), patched.EventsRequested)
	assert.ElementsMatch(t, model.GetSupportedEvents(), patched.EventsDelivered,
		"a patch with no events_supported must re-negotiate against the stream's catalog")
}

// An empty events_requested on UPDATE means "not patched" — the create-time
// full-catalog default must not be re-applied and the existing negotiated set
// must survive.
func TestUpdateStream_EmptyEventsRequestedIsNotPatched(t *testing.T) {
	svc := newEventValidationTestService(model.EventValidationUnset)
	ctx := context.Background()

	supported := model.GetSupportedEvents()
	req := pollReceiverRequest()
	req.EventsRequested = []string{supported[0]}
	created, err := svc.CreateStream(ctx, req, "test-project", nil)
	require.NoError(t, err)

	patched, err := svc.UpdateStream(ctx, created.Id, "test-project", model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{Description: "renamed"},
	})
	require.NoError(t, err)

	assert.Equal(t, []string{supported[0]}, patched.EventsRequested,
		"an omitted events_requested on PATCH must leave the negotiated set alone")
	assert.Equal(t, []string{supported[0]}, patched.EventsDelivered)
}

// expandRequestedEvents is order-preserving and drops duplicates
// case-insensitively, so overlapping globs cannot inflate events_requested.
func TestExpandRequestedEvents_DeduplicatesOverlappingPatterns(t *testing.T) {
	supported := []string{"urn:a:one", "urn:a:two", "urn:b:one"}

	expanded := expandRequestedEvents([]string{"urn:a:*", "*", "URN:A:ONE"}, supported)

	assert.Equal(t, supported, expanded,
		"overlapping patterns must yield each supported URI exactly once, in match order")
}

// A pattern that matches nothing contributes nothing rather than failing the
// registration; the explicit entries alongside it survive.
func TestExpandRequestedEvents_UnmatchedPatternContributesNothing(t *testing.T) {
	supported := []string{"urn:a:one"}

	expanded := expandRequestedEvents([]string{"urn:zzz:*", "urn:a:one"}, supported)

	assert.Equal(t, []string{"urn:a:one"}, expanded)
}

// A request with no wildcard is passed through untouched — the pre-existing
// behaviour this change must not disturb.
func TestExpandRequestedEvents_NoWildcardIsIdentity(t *testing.T) {
	requested := []string{"urn:a:one", "urn:b:two"}

	assert.Equal(t, requested, expandRequestedEvents(requested, []string{"urn:a:one"}))
}

// events_requested is a regular expression (with "*" as ".*" shorthand), so a
// typo like an unclosed group compiles to nothing and used to register a stream
// that quietly delivered a narrower set than was asked for. It must be a
// rejected registration the caller can act on instead — flagged ErrInvalidRequest
// so the handler answers 400 rather than the catch-all 500.
func TestCreateStream_UncompilablePatternIsRejected(t *testing.T) {
	svc := newEventValidationTestService(model.EventValidationUnset)
	ctx := context.Background()

	req := pollReceiverRequest()
	req.EventsRequested = []string{"urn:ietf:params:scim:event:prov:[typo"}

	_, err := svc.CreateStream(ctx, req, "test-project", nil)

	require.Error(t, err, "an uncompilable events_requested pattern must fail the registration")
	assert.ErrorIs(t, err, ErrInvalidRequest, "it is the caller's request that is bad, not the server")
	assert.Contains(t, err.Error(), "[typo", "the error must name the offending pattern")
}

// The same gate on the patch path: a bad pattern must not silently narrow an
// already-working stream's events_delivered.
func TestUpdateStream_UncompilablePatternIsRejected(t *testing.T) {
	svc := newEventValidationTestService(model.EventValidationUnset)
	ctx := context.Background()

	created, err := svc.CreateStream(ctx, pollReceiverRequest(), "test-project", nil)
	require.NoError(t, err)
	require.NotEmpty(t, created.EventsDelivered)

	_, err = svc.UpdateStream(ctx, created.Id, "test-project", model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{EventsRequested: []string{"*:event:(feed|sig:*"}},
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidRequest)

	// The stream must be untouched — a rejected patch mutates nothing.
	state, err := svc.GetStreamState(ctx, created.Id)
	require.NoError(t, err)
	assert.ElementsMatch(t, created.EventsDelivered, state.StreamConfiguration.EventsDelivered,
		"a rejected patch must leave events_delivered as it was")
}

// A valid regex is the point of keeping regex: one pattern selects a subset of
// the catalog by alternation, which no glob could express.
func TestCreateStream_AlternationPatternSelectsSubset(t *testing.T) {
	svc := newEventValidationTestService(model.EventValidationUnset)
	ctx := context.Background()

	req := pollReceiverRequest()
	req.EventsRequested = []string{"*:event:(feed|sig):*"}

	created, err := svc.CreateStream(ctx, req, "test-project", nil)
	require.NoError(t, err)

	require.NotEmpty(t, created.EventsDelivered, "alternation must select real events")
	for _, uri := range created.EventsDelivered {
		assert.True(t,
			strings.Contains(uri, ":event:feed:") || strings.Contains(uri, ":event:sig:"),
			"only the alternation's branches may be delivered, got %q", uri)
	}
	assert.Less(t, len(created.EventsDelivered), len(model.GetSupportedEvents()),
		"an alternation over two branches must be a strict subset of the catalog")
}
