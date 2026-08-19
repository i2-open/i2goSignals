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
			Aud:    []string{"https://tx.audience.example"},
			Mode:   model.SstpModePublish,
			Events: []string{eventType},
		},
		Inbound: model.SstpDirection{
			Iss:    "https://rx.issuer.example",
			Aud:    []string{"https://rx.audience.example"},
			Mode:   model.SstpModeForward,
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
