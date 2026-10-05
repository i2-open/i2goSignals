package eventRouter

import (
	"context"
	"fmt"
	"testing"

	"github.com/i2-open/i2goSignals/internal/eventRouter/buffer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #347: a SET written by another node reaches this node's SSTP-client pair only
// through the store, not its outbound buffer. ClaimOutbound's store fallback
// read just the first max pending JTIs, so once those were all claimed by a
// push still in flight it came back empty and the second push stopped, leaving
// the later pending SETs for the primary long-poll. A claim must reach past the
// JTIs already in flight.
func TestClaimOutbound_StoreFallbackSkipsJtisAlreadyClaimed(t *testing.T) {
	h := newTestRouter(t)
	r := h.router

	pairId := "pair-claim-backfill"
	txSid := "sstp-tx-claim-backfill"
	pair := sstpClientPairForMatch(txSid, pairId)
	r.mu.Lock()
	r.sstpClientStreams[pairId] = *pair
	r.sstpBuffers[pairId] = buffer.CreateEventPollBuffer(nil, 1, 1)
	r.mu.Unlock()

	for i := 1; i <= 3; i++ {
		require.NoError(t, r.eventService.AddEventToStream(context.Background(), refOf(fmt.Sprintf("jti-claim-%d", i)), txSid))
	}

	first := r.ClaimOutbound(pairId, 2)
	require.Len(t, first, 2)

	second := r.ClaimOutbound(pairId, 2)
	require.Len(t, second, 1, "the pending JTI past the claimed ones is claimed")
	assert.NotContains(t, first, second[0])

	assert.Empty(t, r.ClaimOutbound(pairId, 2), "nothing is left once every pending JTI is claimed")
}
