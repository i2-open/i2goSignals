package services

import (
	"context"
	"testing"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// aiEventType stands in for a private event vocabulary an operator carries over
// goSignals that no compiled-in pack knows (issue #261).
const aiEventType = "urn:i2:gosignals-ai:v1:analysis:tier0-deny"

// TestCreateStream_ExtendedEventTypeIsNegotiated is the registration half of the
// extensible catalog: a receiver naming an extended URI literally must get it
// back in events_delivered, because events_delivered is what the router matches
// a SET's types against. Before the extension existed the URI intersected to
// nothing, the stream registered with an empty events_delivered, and every SET
// carrying that type was accepted, stored, and never routed.
func TestCreateStream_ExtendedEventTypeIsNegotiated(t *testing.T) {
	t.Setenv(model.EnvEventTypesExtra, aiEventType)
	svc := newEventValidationTestService(model.EventValidationUnset)
	ctx := context.Background()

	req := pollReceiverRequest()
	req.EventsRequested = []string{aiEventType}

	created, err := svc.CreateStream(ctx, req, "test-project", nil)
	require.NoError(t, err)

	assert.Contains(t, created.EventsSupported, aiEventType,
		"a configured extension must be advertised in events_supported")
	assert.Contains(t, created.EventsDelivered, aiEventType,
		"a literally requested extension URI must be granted in events_delivered")

	state, err := svc.GetStreamState(ctx, created.Id)
	require.NoError(t, err)
	assert.Contains(t, state.StreamConfiguration.EventsDelivered, aiEventType,
		"the negotiated extension must be persisted, not just returned")
}

// TestCreateStream_ExtendedEventTypeMatchedByWildcard: "*" resolves
// events_delivered straight out of the supported catalog, so the extension has
// to be visible there too — an operator who configured a vocabulary and
// registered a catch-all stream expects it carried.
func TestCreateStream_ExtendedEventTypeMatchedByWildcard(t *testing.T) {
	t.Setenv(model.EnvEventTypesExtra, aiEventType)
	svc := newEventValidationTestService(model.EventValidationUnset)
	ctx := context.Background()

	req := pollReceiverRequest()
	req.EventsRequested = []string{"*"}

	created, err := svc.CreateStream(ctx, req, "test-project", nil)
	require.NoError(t, err)

	assert.Contains(t, created.EventsDelivered, aiEventType,
		`"*" must resolve to the extended catalog, not just the compiled-in packs`)
}

// TestUpdateStream_RenegotiatesAgainstLiveCatalog: a stream registered before
// the operator configured the extension carries the OLD catalog in its stored
// events_supported. Re-negotiating a PATCH against that snapshot would make the
// extension unreachable for every pre-existing stream — the operator would have
// to delete and recreate. A PATCH re-negotiates against what this transmitter
// supports NOW.
func TestUpdateStream_RenegotiatesAgainstLiveCatalog(t *testing.T) {
	svc := newEventValidationTestService(model.EventValidationUnset)
	ctx := context.Background()

	req := pollReceiverRequest()
	req.EventsRequested = []string{model.EventScimFeedAdd}
	created, err := svc.CreateStream(ctx, req, "test-project", nil)
	require.NoError(t, err)
	require.NotContains(t, created.EventsSupported, aiEventType,
		"fixture must create the stream before the extension is configured")

	t.Setenv(model.EnvEventTypesExtra, aiEventType)

	patched, err := svc.UpdateStream(ctx, created.Id, "test-project", model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			EventsRequested: []string{model.EventScimFeedAdd, aiEventType},
		},
	})
	require.NoError(t, err)
	assert.Contains(t, patched.EventsDelivered, aiEventType,
		"a PATCH must re-negotiate against the live catalog so an extension reaches existing streams")
	assert.Subset(t, patched.EventsSupported, patched.EventsDelivered,
		"events_delivered must stay a subset of events_supported (SSF 1.0 §7.1.1)")
}

// TestCreateSstpPair_ExtendedEventTypeIsNegotiated: an SSTP direction names its
// events explicitly (silence forwards nothing, see resolveSstpDirectionEvents),
// so a pair carrying a private vocabulary depends entirely on that vocabulary
// being in the catalog the direction is negotiated against. This is the
// registration half of the two-hop topology issue #261 was filed for.
func TestCreateSstpPair_ExtendedEventTypeIsNegotiated(t *testing.T) {
	t.Setenv(model.EnvEventTypesExtra, aiEventType)
	svc, _ := sstpFixture(t)

	b := responderBootstrap()
	b.Inbound.Mode = model.SstpModeForward
	b.Inbound.Events = []string{aiEventType}
	b.Primary.Events = []string{aiEventType}

	rec, err := svc.CreateSstpPair(context.Background(), b, "proj-1", nil)
	require.NoError(t, err)

	require.NotNil(t, rec.SstpInbound)
	assert.Contains(t, rec.SstpInbound.EventsDelivered, aiEventType,
		"an SSTP inbound direction naming an extended URI must negotiate it into events_delivered")
	assert.Contains(t, rec.StreamConfiguration.EventsDelivered, aiEventType,
		"the tx direction must negotiate it too")
	assert.Contains(t, rec.SstpInbound.EventsSupported, aiEventType,
		"the pair must advertise the extended catalog it negotiated against")
}

// TestCreateStream_ExtendedEventTypeMatchedByPattern: events_requested is a
// REGULAR EXPRESSION language (MatchesEventPattern), not a literal list, and a
// receiver carrying a private vocabulary is the caller most likely to write a
// prefix pattern rather than enumerate. The extension has to be visible to the
// matcher, not only to the literal-equality path the other tests take.
func TestCreateStream_ExtendedEventTypeMatchedByPattern(t *testing.T) {
	t.Setenv(model.EnvEventTypesExtra, aiEventType)
	svc := newEventValidationTestService(model.EventValidationUnset)
	ctx := context.Background()

	req := pollReceiverRequest()
	req.EventsRequested = []string{"urn:i2:gosignals-ai:v1:analysis:.*"}

	created, err := svc.CreateStream(ctx, req, "test-project", nil)
	require.NoError(t, err)

	assert.Contains(t, created.EventsDelivered, aiEventType,
		"a pattern selecting an extended URI must expand to it in events_delivered")
	assert.NotContains(t, created.EventsDelivered, model.EventScimFeedAdd,
		"the pattern must not widen delivery to the compiled-in packs it does not select")
	assert.Contains(t, created.EventsRequested, aiEventType,
		"a returned configuration enumerates URIs rather than echoing the pattern")
}
