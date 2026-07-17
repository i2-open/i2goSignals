package eventRouter

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// sstpRunnerHarness wires a router with the standard memory persistence for
// events/streams and prometheus counters. Used by the SSTP-server-side runner
// tests (client-side dialer tests moved to internal/server after PRD #49
// slice 2a relocated the dialer loop out of internal/eventRouter).
type sstpRunnerHarness struct {
	router     *router
	inCounter  *prometheus.CounterVec
	outCounter *prometheus.CounterVec
}

func newSstpRunnerHarness(t *testing.T) *sstpRunnerHarness {
	t.Helper()
	base := newTestRouter(t)

	inCounter := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "sstp_test_in", Help: "t"},
		[]string{"type", "iss", "tfr", "stream_id"})
	outCounter := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "sstp_test_out", Help: "t"},
		[]string{"type", "iss", "tfr", "stream_id"})
	base.router.SetEventCounter(inCounter, outCounter)

	return &sstpRunnerHarness{
		router:     base.router,
		inCounter:  inCounter,
		outCounter: outCounter,
	}
}

// persistOutboundEvent persists a SET for txSid and marks it pending for that
// stream so the server-side runner's outbound drain picks it up.
func (h *sstpRunnerHarness) persistOutboundEvent(t *testing.T, txSid, jti string) {
	t.Helper()
	token := newRiscToken(jti, dupTestIssuer, "https://peer.example.com")
	_, err := h.router.eventService.AddEvent(context.Background(), token, txSid, `{"raw":true}`)
	require.NoError(t, err)
	require.NoError(t, h.router.eventService.AddEventToStream(context.Background(), jti, txSid))
}
