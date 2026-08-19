package eventRouter

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// aiRouteEventType is a private vocabulary no compiled-in pack knows — the case
// issue #261 was reopened for: an agent proxy and an analysis engine exchanging
// their own verdict types through goSignals over SSTP.
const aiRouteEventType = "urn:i2:gosignals-ai:v1:analysis:tier0-deny"

// mustCreateForwardingSstpPair provisions an SSTP pair through the REAL
// StreamService bootstrap path, so events_delivered on both directions is
// whatever buildSstpRecord's negotiation against the live catalog produces.
//
// That is the whole point of this fixture. The sibling fixture in
// sstp_inbound_routing_test.go hand-writes EventsDelivered, which cannot fail
// when the catalog is the thing that is broken: it pre-supplies the field whose
// computation is under test.
func mustCreateForwardingSstpPair(t *testing.T, h *testHarness, projectId, eventType string) *model.StreamStateRecord {
	t.Helper()
	return mustCreateSstpPairForRouting(t, h, projectId, eventType,
		"https://tx.audience.example", "https://rx.audience.example", model.SstpModeForward)
}

// mustCreateSstpPairForRouting is mustCreateForwardingSstpPair over an arbitrary
// audience pair and inbound mode, so a test can stand up two distinct pairs and
// route between them.
func mustCreateSstpPairForRouting(t *testing.T, h *testHarness, projectId, eventType, txAud, rxAud, inboundMode string) *model.StreamStateRecord {
	t.Helper()
	// A responder derives its own endpoint_url from the server's base URL; the
	// router harness has none, and CreateSstpPair rejects the empty scheme.
	baseUrl, err := url.Parse("https://local.example")
	require.NoError(t, err)
	h.streamService.SetBaseUrl(baseUrl)

	rec, err := h.streamService.CreateSstpPair(context.Background(), model.SstpPairBootstrap{
		Role:        model.SstpRoleResponder,
		Description: "extended-vocabulary pair",
		Primary: model.SstpDirection{
			Iss:    "https://tx.issuer.example",
			Aud:    []string{txAud},
			Mode:   model.SstpModePublish,
			Events: []string{eventType},
		},
		Inbound: model.SstpDirection{
			Iss:    "https://rx.issuer.example",
			Aud:    []string{rxAud},
			Mode:   inboundMode,
			Events: []string{eventType},
		},
	}, projectId, nil)
	require.NoError(t, err)
	require.NotNil(t, rec.SstpInbound)
	return &rec
}

// TestHandleEvent_SstpInboundForward_RoutesExtendedEventType is the end-to-end
// AC for the extensible catalog: with a vocabulary configured, hop 2 of an
// A --sstp--> goSignals --poll--> B topology carries a custom event type.
//
// Everything the router consults here — the pair's inbound events_delivered and
// the outbound stream's — is produced by real negotiation against
// model.GetSupportedEvents(). Without the extension the custom URI intersects to
// nothing, both sides negotiate an empty events_delivered, and matchesEventType
// rejects every SET: the stream registers, the SETs are accepted and stored, and
// nothing is ever routed.
func TestHandleEvent_SstpInboundForward_RoutesExtendedEventType(t *testing.T) {
	t.Setenv(model.EnvEventTypesExtra, aiRouteEventType)
	h := newTestRouter(t)
	projectId := projectIdFromHarness(t, h)
	out := mustCreateOutboundPollStreamForType(t, h, projectId, aiRouteEventType)
	pair := mustCreateForwardingSstpPair(t, h, projectId, aiRouteEventType)

	require.Contains(t, pair.SstpInbound.EventsDelivered, aiRouteEventType,
		"the inbound direction must have negotiated the extended type before routing can be asserted")

	token := &goSet.SecurityEventToken{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   "https://upstream.issuer.example",
			Audience: jwt.ClaimStrings{"https://rx.audience.example"},
		},
		Events: map[string]interface{}{aiRouteEventType: map[string]interface{}{}},
	}
	token.ID = "sstp-extended-jti"

	require.NoError(t, h.router.HandleEvent(token, `{"raw":true}`, pair.SstpInbound.Id))

	require.Eventually(t, func() bool { return pollBufferCount(h, out.StreamConfiguration.Id) == 1 },
		2*time.Second, 5*time.Millisecond,
		"an extended event type must fan out to a matching outbound stream")
}

// TestHandleEvent_ExtendedEventType_NotRoutedWithoutConfig is the other half of
// the contract, and the reason the extension is opt-in: with nothing configured
// the custom URI is not in the catalog, negotiates to nothing, and is not
// routed. Behaviour without the env var is exactly what it was.
func TestHandleEvent_ExtendedEventType_NotRoutedWithoutConfig(t *testing.T) {
	h := newTestRouter(t)
	projectId := projectIdFromHarness(t, h)
	out := mustCreateOutboundPollStreamForType(t, h, projectId, aiRouteEventType)
	pair := mustCreateForwardingSstpPair(t, h, projectId, aiRouteEventType)

	require.NotContains(t, out.StreamConfiguration.EventsDelivered, aiRouteEventType,
		"an unconfigured custom URI must not be negotiated into events_delivered")

	token := &goSet.SecurityEventToken{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   "https://upstream.issuer.example",
			Audience: jwt.ClaimStrings{"https://rx.audience.example"},
		},
		Events: map[string]interface{}{aiRouteEventType: map[string]interface{}{}},
	}
	token.ID = "sstp-unconfigured-jti"

	require.NoError(t, h.router.HandleEvent(token, `{"raw":true}`, pair.SstpInbound.Id))

	assert.Never(t, func() bool { return pollBufferCount(h, out.StreamConfiguration.Id) > 0 },
		250*time.Millisecond, 10*time.Millisecond,
		"an event type outside the catalog must not be routed")
}

// TestHandleEvent_TwoHopSstp_ExtendedEventType is the topology issue #261 was
// filed for, end to end and with nothing hand-written:
// A --sstp--> goSignals --sstp--> B, aud-routed, carrying a vocabulary no pack
// knows.
//
// Both pairs are provisioned through the real CreateSstpPair bootstrap, so every
// events_delivered the router consults on either hop is the product of
// negotiation against the live catalog. The pre-existing sibling test
// (TestHandleEvent_SstpInboundForward_RoutesToOtherSstpPair) proves the same
// fan-out but pre-supplies EventsDelivered, so it cannot fail when the catalog
// is what is broken — which is exactly how the defect survived PR #262.
func TestHandleEvent_TwoHopSstp_ExtendedEventType(t *testing.T) {
	t.Setenv(model.EnvEventTypesExtra, aiRouteEventType)
	h := newTestRouter(t)
	projectId := projectIdFromHarness(t, h)

	const hopBAud = "https://hopB.tx.example"
	hopA := mustCreateSstpPairForRouting(t, h, projectId, aiRouteEventType,
		"https://hopA.tx.example", "https://hopA.rx.example", model.SstpModeForward)
	hopB := mustCreateSstpPairForRouting(t, h, projectId, aiRouteEventType,
		hopBAud, "https://hopB.rx.example", model.SstpModeImport)

	require.Contains(t, hopA.SstpInbound.EventsDelivered, aiRouteEventType,
		"hop A's inbound must have negotiated the extended type")
	require.Contains(t, hopB.EventsDelivered, aiRouteEventType,
		"hop B's tx must have negotiated the extended type — this is the field that was empty in #261")

	hopATx := hopA.StreamConfiguration.Id
	hopBTx := hopB.StreamConfiguration.Id
	require.NotEqual(t, hopATx, hopBTx, "test premise: two distinct pairs")

	h.router.mu.Lock()
	h.router.sstpServerStreams[hopATx] = *hopA
	h.router.sstpServerStreams[hopBTx] = *hopB
	h.router.mu.Unlock()

	token := &goSet.SecurityEventToken{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   "https://upstream.issuer.example",
			Audience: jwt.ClaimStrings{hopBAud},
		},
		Events: map[string]interface{}{aiRouteEventType: map[string]interface{}{}},
	}
	token.ID = "sstp-two-hop-jti"

	require.NoError(t, h.router.HandleEvent(token, `{"raw":true}`, hopA.SstpInbound.Id))

	params := model.PollParameters{MaxEvents: 100, ReturnImmediately: true}
	hopBJtis, _ := h.router.eventService.GetEventIds(context.Background(), hopBTx, params)
	assert.Contains(t, hopBJtis, "sstp-two-hop-jti",
		"hop 2 must carry the SET to the second pair's tx side")

	hopAJtis, _ := h.router.eventService.GetEventIds(context.Background(), hopATx, params)
	assert.NotContains(t, hopAJtis, "sstp-two-hop-jti",
		"the ingesting pair must not be echoed back to its own peer")
}
