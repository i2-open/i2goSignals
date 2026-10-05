package eventRouter

import (
	"context"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/eventRouter/buffer"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/require"
)

// #363: the SSTP dialer's outbound record travels with its reference, so the
// acknowledgement JTI written with the row is the one the dialer signs and
// the one AckOutbound matches the peer's acknowledgement against.
func TestOutboundSet_CarriesRowAckJtiThroughClaimResolveAck(t *testing.T) {
	h := newSstpRunnerHarness(t)
	r := h.router
	txSid, pairId := "sstp-tx-outset-363", "pair-outset-363"
	pair := sstpClientPairForMatch(txSid, pairId)
	pair.StreamConfiguration.RouteMode = model.RouteModePublish
	r.mu.Lock()
	r.sstpClientStreams[pairId] = *pair
	r.sstpBuffers[pairId] = buffer.CreateEventPollBuffer(nil, 1, 1)
	r.rebuildRoutingLocked()
	r.mu.Unlock()
	r.NoteLease(pairId, time.Now(), true, time.Now().Add(time.Minute), time.Minute)

	jti := "sstp-outset-363"
	token := newRiscToken(jti, dupTestIssuer, "https://peer.example.com")
	_, err := r.eventService.AddEvent(context.Background(), token, txSid, `{"raw":true}`)
	require.NoError(t, err)
	ackJti := pair.AckJti(jti)
	require.NotEqual(t, jti, ackJti, "a publish pair re-signs under a derived JTI")
	require.NoError(t, r.eventService.AddEventToStream(context.Background(), interfaces.PendingRef{Jti: jti, AckJti: ackJti}, txSid))

	claimed := r.ClaimOutbound(pairId, 1)
	require.Len(t, claimed, 1)
	require.Equal(t, jti, claimed[0].Jti)
	require.Equal(t, ackJti, claimed[0].AckJti)

	sets := r.ResolveEvents(pairId, claimed)
	require.Len(t, sets, 1)
	require.Equal(t, claimed[0], sets[0].Ref)
	require.Equal(t, jti, sets[0].Record.Jti)

	require.Equal(t, 1, r.AckOutbound(pair, []string{ackJti}, sets))
	if ack := r.sstpAcker(pairId); ack != nil {
		_ = ack.flush()
	}
	page, err := r.eventService.PendingPage(context.Background(), txSid, 10)
	require.NoError(t, err)
	require.Zero(t, page.Total, "the row is acknowledged by its ackJti")
}
