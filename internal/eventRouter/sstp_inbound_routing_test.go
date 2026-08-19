package eventRouter

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// sstpRouteEventType is deliberately OUTSIDE the compiled-in catalog: it is the
// exact reproducer from GH #261, where every test in this file passed with a
// builtin URI and failed the moment the event type was one goSignals had no
// compiled-in knowledge of. Routing a builtin type is covered by the rest of the
// package (event_source_routing_test.go, pb_resign_test.go, push_state_test.go,
// subject_filter_*_test.go); what these tests uniquely pin is that the RouteMode
// gate and the catalog gate both pass for a vocabulary supplied by configuration.
// mustCreateOutboundPollStream configures it via EnvEventTypesExtra (ADR 0032).
const sstpRouteEventType = "urn:i2:gosignals-ai:v1:analysis:tier0-deny"

// persistSstpPairWithInboundMode builds a bidirectional SSTP pair whose inbound
// (rx) direction carries the given RouteMode, honouring the aliasing invariant
// (tx Id == PairId == document _id hex).
func persistSstpPairWithInboundMode(t *testing.T, h *testHarness, inboundMode string) *model.StreamStateRecord {
	t.Helper()
	mid := bson.NewObjectID()
	pairId := mid.Hex()
	rec := &model.StreamStateRecord{
		Id: mid,
		StreamConfiguration: model.StreamConfiguration{
			Id:              pairId,
			Iss:             "https://tx.issuer.example",
			Aud:             []string{"https://tx.audience.example"},
			RouteMode:       model.RouteModePublish,
			EventsDelivered: []string{sstpRouteEventType},
			Delivery: &model.OneOfStreamConfigurationDelivery{
				SstpTransmitMarker: &model.SstpTransmitMarker{Method: model.DeliverySstp},
			},
		},
		SstpInbound: &model.StreamConfiguration{
			Id:              bson.NewObjectID().Hex(),
			Iss:             "https://rx.issuer.example",
			Aud:             []string{"https://rx.audience.example"},
			RouteMode:       inboundMode,
			EventsRequested: []string{sstpRouteEventType},
			Delivery: &model.OneOfStreamConfigurationDelivery{
				SstpReceiveMarker: &model.SstpReceiveMarker{Method: model.ReceiveSstp},
			},
		},
		PairId:        pairId,
		Status:        model.StreamStateEnabled,
		InboundStatus: model.StreamStateEnabled,
	}
	require.NoError(t, h.streamService.PersistStreamStateRecord(context.Background(), rec))
	return rec
}

// mustCreateOutboundPollStream registers an AUDIENCE-sourced poll-transmit
// stream. Poll buffers do not auto-drain the way push buffers do, so the buffer
// count is a stable observation point proving the event was routed here.
func mustCreateOutboundPollStream(t *testing.T, h *testHarness, projectId string) *model.StreamStateRecord {
	t.Helper()
	// sstpRouteEventType is outside the compiled-in catalog, so without the
	// extension the CreateStream below negotiates events_delivered to nothing and
	// every routing assertion in this file fails on the catalog gate rather than
	// on the RouteMode gate it means to test (GH #261).
	t.Setenv(model.EnvEventTypesExtra, sstpRouteEventType)
	return mustCreateOutboundPollStreamForType(t, h, projectId, sstpRouteEventType)
}

// mustCreateOutboundPollStreamForType is mustCreateOutboundPollStream over an
// arbitrary event type, so a test can exercise a vocabulary outside the
// compiled-in catalog.
func mustCreateOutboundPollStreamForType(t *testing.T, h *testHarness, projectId, eventType string) *model.StreamStateRecord {
	t.Helper()
	cfg := model.StreamConfiguration{
		Aud:             []string{"https://downstream.example.com"},
		RouteMode:       model.RouteModePublish,
		EventsRequested: []string{eventType},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollTransmitMethod: &model.PollTransmitMethod{
				Method:      model.DeliveryPoll,
				EndpointUrl: "https://transmitter.example.com/events",
			},
		},
	}
	ctx := context.WithValue(context.Background(), authSupport.AuthContextKey, authSupport.ConvertProject(projectId))
	created, err := h.streamService.CreateStream(ctx, model.StreamStateRecord{
		StreamConfiguration: cfg,
		EventSource:         &model.EventSource{Type: model.EventSourceAudience},
	}, projectId, nil)
	require.NoError(t, err)
	state, err := h.streamService.GetStreamState(context.Background(), created.Id)
	require.NoError(t, err)
	h.router.UpdateStreamState(state)
	return state
}

func sstpInboundTestToken(jti string) *goSet.SecurityEventToken {
	token := &goSet.SecurityEventToken{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   "https://upstream.issuer.example",
			Audience: jwt.ClaimStrings{"https://rx.audience.example"},
		},
		Events: map[string]interface{}{sstpRouteEventType: map[string]interface{}{}},
	}
	token.ID = jti
	return token
}

func pollBufferCount(h *testHarness, sid string) int {
	h.router.mu.RLock()
	defer h.router.mu.RUnlock()
	buf, ok := h.router.pollBuffers[sid]
	if !ok {
		return -1
	}
	return buf.Cnt()
}

// TestHandleEvent_SstpInboundForward_RoutesToOutboundStream is the core AC for
// issue #261: an SSTP-ingested SET on a pair whose inbound mode is FORWARD must
// reach a matching outbound stream. Before the fix HandleEvent returned at the
// unconditional `if sstpInbound` guard, so hop 2 of an
// A --sstp--> goSignals --sstp/push--> B topology was silently dropped.
func TestHandleEvent_SstpInboundForward_RoutesToOutboundStream(t *testing.T) {
	h := newTestRouter(t)
	projectId := projectIdFromHarness(t, h)
	out := mustCreateOutboundPollStream(t, h, projectId)
	pair := persistSstpPairWithInboundMode(t, h, model.RouteModeForward)

	require.NoError(t, h.router.HandleEvent(sstpInboundTestToken("sstp-fw-jti"), `{"raw":true}`, pair.SstpInbound.Id))

	require.Eventually(t, func() bool { return pollBufferCount(h, out.StreamConfiguration.Id) == 1 },
		2*time.Second, 5*time.Millisecond,
		"an SSTP inbound in FORWARD mode must fan out to matching outbound streams")
}

// TestHandleEvent_SstpInboundPublish_RoutesToOutboundStream: PUBLISH routes the
// same way. The re-sign itself happens at delivery time, keyed off the OUTBOUND
// stream's route mode, exactly as for an RFC 8935 push receiver.
func TestHandleEvent_SstpInboundPublish_RoutesToOutboundStream(t *testing.T) {
	h := newTestRouter(t)
	projectId := projectIdFromHarness(t, h)
	out := mustCreateOutboundPollStream(t, h, projectId)
	pair := persistSstpPairWithInboundMode(t, h, model.RouteModePublish)

	require.NoError(t, h.router.HandleEvent(sstpInboundTestToken("sstp-pb-jti"), `{"raw":true}`, pair.SstpInbound.Id))

	require.Eventually(t, func() bool { return pollBufferCount(h, out.StreamConfiguration.Id) == 1 },
		2*time.Second, 5*time.Millisecond,
		"an SSTP inbound in PUBLISH mode must fan out to matching outbound streams")
}

// TestHandleEvent_SstpInboundImport_NotRouted pins the unchanged half of the
// contract: IMPORT consumes the SET locally and must NOT fan out.
func TestHandleEvent_SstpInboundImport_NotRouted(t *testing.T) {
	h := newTestRouter(t)
	projectId := projectIdFromHarness(t, h)
	out := mustCreateOutboundPollStream(t, h, projectId)
	pair := persistSstpPairWithInboundMode(t, h, model.RouteModeImport)

	require.NoError(t, h.router.HandleEvent(sstpInboundTestToken("sstp-im-jti"), `{"raw":true}`, pair.SstpInbound.Id))

	assert.Never(t, func() bool { return pollBufferCount(h, out.StreamConfiguration.Id) > 0 },
		250*time.Millisecond, 10*time.Millisecond,
		"IMPORT is terminal: the SET is consumed locally and must not be routed")
}

// TestHandleEvent_SstpInboundForward_DoesNotEchoToOriginatingPair: fanning an
// SSTP-ingested SET back out the tx side of the SAME pair would return it to
// the peer that just sent it. The pair's tx side matches the event on aud, so
// without an explicit exclusion the fan-out loop would do exactly that.
func TestHandleEvent_SstpInboundForward_DoesNotEchoToOriginatingPair(t *testing.T) {
	h := newTestRouter(t)
	pair := persistSstpPairWithInboundMode(t, h, model.RouteModeForward)

	// Register the pair's tx side as a server-side outbound the fan-out scans.
	txSid := pair.StreamConfiguration.Id
	h.router.mu.Lock()
	h.router.sstpServerStreams[txSid] = *pair
	h.router.mu.Unlock()

	token := sstpInboundTestToken("sstp-echo-jti")
	// Make the event match the pair's own tx side on aud.
	token.Audience = jwt.ClaimStrings{"https://tx.audience.example"}
	require.NoError(t, h.router.HandleEvent(token, `{"raw":true}`, pair.SstpInbound.Id))

	jtis, _ := h.router.eventService.GetEventIds(context.Background(), txSid, model.PollParameters{MaxEvents: 100, ReturnImmediately: true})
	assert.NotContains(t, jtis, "sstp-echo-jti",
		"a SET must not be routed back out the pair it arrived on")
}

// TestHandleEvent_SstpInboundBlankMode_NotRouted pins ADR-0031 D4. A blank
// inbound RouteMode means a record written before the field existed; those were
// import-only under the old unconditional guard, so they must stay that way.
// Following SstpModeToRouteMode's PUBLISH default would silently start fanning
// out their events on upgrade.
func TestHandleEvent_SstpInboundBlankMode_NotRouted(t *testing.T) {
	h := newTestRouter(t)
	projectId := projectIdFromHarness(t, h)
	out := mustCreateOutboundPollStream(t, h, projectId)
	pair := persistSstpPairWithInboundMode(t, h, "")

	require.NoError(t, h.router.HandleEvent(sstpInboundTestToken("sstp-blank-jti"), `{"raw":true}`, pair.SstpInbound.Id))

	assert.Never(t, func() bool { return pollBufferCount(h, out.StreamConfiguration.Id) > 0 },
		250*time.Millisecond, 10*time.Millisecond,
		"a blank inbound RouteMode is a pre-#261 record and must not route")
}

// TestSstpInboundRouteMode_NilInboundIsImport: sstpInboundCounterRecord leaves
// the TX StreamConfiguration in place when a pair has no inbound half, so
// reading the mode straight off that view would return the TX direction's mode
// and route on it. A pair with no inbound direction has no inbound mode.
func TestSstpInboundRouteMode_NilInboundIsImport(t *testing.T) {
	pair := &model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:        "tx-sid",
			RouteMode: model.RouteModePublish, // the TX mode must not leak through
		},
	}
	assert.Equal(t, model.RouteModeImport, sstpInboundRouteMode(pair),
		"a pair with no inbound direction must not route on its tx mode")
	assert.Equal(t, model.RouteModeImport, sstpInboundRouteMode(nil))
}

// TestHandleEvent_SstpInboundForward_RoutesToOtherSstpPair is the positive
// SSTP-tx case: the echo guard must skip only the ORIGINATING pair, not the
// whole SSTP fan-out. A second, unrelated pair matching on aud must still
// receive the SET.
func TestHandleEvent_SstpInboundForward_RoutesToOtherSstpPair(t *testing.T) {
	h := newTestRouter(t)
	origin := persistSstpPairWithInboundMode(t, h, model.RouteModeForward)
	other := persistSstpPairWithInboundMode(t, h, model.RouteModeImport)

	originTx := origin.StreamConfiguration.Id
	otherTx := other.StreamConfiguration.Id
	require.NotEqual(t, originTx, otherTx, "test premise: two distinct pairs")

	h.router.mu.Lock()
	h.router.sstpServerStreams[originTx] = *origin
	h.router.sstpServerStreams[otherTx] = *other
	h.router.mu.Unlock()

	token := sstpInboundTestToken("sstp-fanout-jti")
	token.Audience = jwt.ClaimStrings{"https://tx.audience.example"}
	require.NoError(t, h.router.HandleEvent(token, `{"raw":true}`, origin.SstpInbound.Id))

	params := model.PollParameters{MaxEvents: 100, ReturnImmediately: true}
	otherJtis, _ := h.router.eventService.GetEventIds(context.Background(), otherTx, params)
	assert.Contains(t, otherJtis, "sstp-fanout-jti",
		"a non-originating SSTP pair must still receive the forwarded SET")

	originJtis, _ := h.router.eventService.GetEventIds(context.Background(), originTx, params)
	assert.NotContains(t, originJtis, "sstp-fanout-jti",
		"the originating pair must still be excluded")
}

// TestHandleEvent_SstpInboundForward_DoesNotEchoToInitiatorPair: the exclusion
// must hold on the initiator (client) fan-out loop too, which is keyed by
// PairId rather than by tx SID.
func TestHandleEvent_SstpInboundForward_DoesNotEchoToInitiatorPair(t *testing.T) {
	h := newTestRouter(t)
	pair := persistSstpPairWithInboundMode(t, h, model.RouteModeForward)
	txSid := pair.StreamConfiguration.Id

	h.router.mu.Lock()
	h.router.sstpClientStreams[pair.PairId] = *pair
	h.router.mu.Unlock()

	token := sstpInboundTestToken("sstp-echo-client-jti")
	token.Audience = jwt.ClaimStrings{"https://tx.audience.example"}
	require.NoError(t, h.router.HandleEvent(token, `{"raw":true}`, pair.SstpInbound.Id))

	jtis, _ := h.router.eventService.GetEventIds(context.Background(), txSid,
		model.PollParameters{MaxEvents: 100, ReturnImmediately: true})
	assert.NotContains(t, jtis, "sstp-echo-client-jti",
		"an initiator pair must not be echoed either")
}
