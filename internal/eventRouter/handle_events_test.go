package eventRouter

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// TestHandleEvents_BatchIngestsAndFansOut proves the batch path: every SET of
// the batch is persisted, counted once, and queued on the matching poll stream
// in batch order; a duplicate JTI inside the batch is swallowed (nil, so it is
// acked) without a second count or a second pending entry; and a SET for a
// stream nobody wants is accepted but not queued.
func TestHandleEvents_BatchIngestsAndFansOut(t *testing.T) {
	s := setupDedupRouterPollStream(t)

	// Seed one JTI so the batch carries a duplicate of an already-stored SET.
	require.NoError(t, s.h.router.HandleEvent(newRiscToken("batch-seed", dupTestIssuer, s.audience), `{"seed":true}`, s.streamID))
	require.Eventually(t, func() bool { return s.pollBufferCh() == 1 }, time.Second, 5*time.Millisecond)

	tokens := []*goSet.SecurityEventToken{
		newRiscToken("batch-1", dupTestIssuer, s.audience),
		newRiscToken("batch-seed", dupTestIssuer, s.audience), // duplicate
		newRiscToken("batch-2", dupTestIssuer, s.audience),
		newRiscToken("batch-other", dupTestIssuer, "https://nobody.example.com"), // no matching stream
		newRiscToken("batch-3", dupTestIssuer, s.audience),
	}
	raws := make([]string, len(tokens))
	for i := range raws {
		raws[i] = fmt.Sprintf(`{"raw":%d}`, i)
	}

	errs := s.h.router.HandleEvents(tokens, raws, s.streamID)
	require.Len(t, errs, len(tokens))
	for i, err := range errs {
		assert.NoError(t, err, "entry %d", i)
	}

	// 4 new SETs counted on top of the seed; the duplicate is not.
	assert.InDelta(t, 5.0, inCounterValue(t, s.inCounter, s.streamID), 0.0001)

	// 3 matching SETs queued on top of the seed, read back in jti order.
	require.Eventually(t, func() bool { return s.pollBufferCh() == 4 }, time.Second, 5*time.Millisecond,
		"the three matching SETs of the batch must be queued once each")
	pending, _ := s.h.router.eventService.GetEventIds(context.Background(), s.streamID, model.PollParameters{MaxEvents: 10, ReturnImmediately: true})
	// GetPendingForStream publishes ascending jti order on BOTH providers (ADR
	// 0040), not insertion order. These are literal test jtis rather than the
	// UUIDv7s a real ingest mints, so "batch-seed" sorts last here where a real
	// seed — minted before the batch — would sort first.
	assert.Equal(t, []string{"batch-1", "batch-2", "batch-3", "batch-seed"}, pending,
		"pending list must hold the seed and the batch's matching SETs, in jti order")

	// Every non-duplicate SET was persisted, including the unmatched one.
	for _, jti := range []string{"batch-1", "batch-2", "batch-3", "batch-other"} {
		assert.NotNil(t, s.h.router.eventService.GetEventRecord(context.Background(), jti), "%s must be stored", jti)
	}

	// An empty batch is a no-op.
	assert.Empty(t, s.h.router.HandleEvents(nil, nil, s.streamID))

	// An unknown stream fails every entry.
	bad := s.h.router.HandleEvents(tokens[:2], raws[:2], "no-such-stream")
	require.Len(t, bad, 2)
	assert.Error(t, bad[0])
	assert.Error(t, bad[1])
}
