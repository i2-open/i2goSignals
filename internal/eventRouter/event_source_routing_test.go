package eventRouter

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/require"
)

// TestHandleEvent_AudienceStream_RoutesDespiteDifferentInboundAud is the
// production-wiring AC for issue #199: it drives the real router path
// (HandleEvent -> the r.eventService.MatchesStream match loop in
// event_router.go) and proves that an AUDIENCE-sourced stream whose
// transmitter-assigned aud differs from the inbound event's aud still routes
// the event. Without the EventSource-aware branch in MatchesStream, the
// disjoint aud would reject the match and the event would be black-holed.
func TestHandleEvent_AudienceStream_RoutesDespiteDifferentInboundAud(t *testing.T) {
	h := newTestRouter(t)
	projectId := projectIdFromHarness(t, h)

	const (
		downstreamAud = "https://downstream.example.com"
		inboundAud    = "https://inbound.example.com"
		typeDisabled  = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
	)

	// A poll-transmit stream tagged EventSource=AUDIENCE. Poll buffers do not
	// auto-drain (unlike push), so the buffer count is a stable observation
	// point that proves the event was routed to this stream. RouteMode PB so
	// the iss filter is ignored (default for transmitters).
	cfg := model.StreamConfiguration{
		Aud:             []string{downstreamAud},
		RouteMode:       model.RouteModePublish,
		EventsRequested: []string{typeDisabled},
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
	require.NotNil(t, state.EventSource, "EventSource must survive the create path")
	require.Equal(t, model.EventSourceAudience, state.EventSource.Type)
	require.Equal(t, []string{downstreamAud}, []string(state.Aud),
		"stream's transmitter-assigned aud handle must be the downstream value")
	h.router.UpdateStreamState(state)

	pollBufferCnt := func() int {
		h.router.mu.RLock()
		buf, ok := h.router.pollBuffers[created.Id]
		h.router.mu.RUnlock()
		if !ok {
			return -1
		}
		return buf.Cnt()
	}

	// Inbound event whose aud is a DIFFERENT handle from the stream's aud.
	token := &goSet.SecurityEventToken{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   "https://some-issuer.example.com",
			Audience: jwt.ClaimStrings{inboundAud},
		},
		Events: map[string]interface{}{typeDisabled: map[string]interface{}{}},
	}
	token.ID = "audience-route-jti"

	require.NotEqual(t, inboundAud, downstreamAud, "test premise: inbound aud must differ from the stream aud")

	// HandleEvent requires a resolvable inbound sid to persist the event; using
	// the created stream's own id mirrors the existing dedup router test. What
	// is under test is the aud-mismatch routing decision in the match loop, not
	// the inbound sid.
	err = h.router.HandleEvent(token, `{"raw":true}`, created.Id)
	require.NoError(t, err, "HandleEvent")

	require.Eventually(t, func() bool { return pollBufferCnt() == 1 },
		2*time.Second, 5*time.Millisecond,
		"AUDIENCE stream must route the event even though the inbound aud (%s) differs from the stream aud (%s)",
		inboundAud, downstreamAud)
}
