package eventRouter

import (
	"context"
	"sync"
	"testing"
	"time"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// longPoll is one RFC 8936 long poll (returnImmediately=false) for up to max
// SETs, acking acks.
func (h *filterPushHarness) longPoll(sid string, max int32, acks ...string) map[string]string {
	sets, _, _ := h.router.PollStreamHandler(context.Background(), sid, model.PollParameters{
		MaxEvents:         max,
		ReturnImmediately: false,
		TimeoutSecs:       2,
		Acks:              wireAcks(h.router, sid, acks...),
	})
	return inboundSets(h.router, sid, sets)
}

func keysOf(sets map[string]string) []string {
	out := make([]string, 0, len(sets))
	for jti := range sets {
		out = append(out, jti)
	}
	return out
}

// Two overlapping long polls on one stream get disjoint SETs; a poll after the
// claim TTL gets the unacked SETs again; acks carried by a poll free them (#337).
func TestPollClaims_OverlappingPollsAreDisjointAndExpiredClaimsRedeliver(t *testing.T) {
	t.Setenv("I2SIG_POLL_CLAIM_TTL", "400ms")
	h, _ := newPollKeyHarness(t, "50ms")
	sid := h.createSigningPollStream(t, pollKeyIssuer, model.RouteModePublish).StreamConfiguration.Id
	all := h.queuePollEvents(t, sid, 10)

	var wg sync.WaitGroup
	results := make([]map[string]string, 2)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = h.longPoll(sid, 5)
		}(i)
	}
	wg.Wait()

	require.Len(t, results[0], 5)
	require.Len(t, results[1], 5)
	for jti := range results[0] {
		assert.NotContains(t, results[1], jti, "overlapping polls must not share a SET")
	}
	assert.ElementsMatch(t, all, append(keysOf(results[0]), keysOf(results[1])...))

	// Ack the first poll's SETs; leave the second's unacked until its claim expires.
	time.Sleep(600 * time.Millisecond)
	again := h.longPoll(sid, 100, keysOf(results[0])...)
	assert.ElementsMatch(t, keysOf(results[1]), keysOf(again), "only the unacked SETs are redelivered after expiry")

	sets, status := h.poll(sid, keysOf(again)...)
	assert.Equal(t, 200, status)
	assert.Empty(t, sets, "acked SETs are never served again")
}

// Claims live only in the node's memory: a fresh router over the same store
// (a restart) serves the whole pending set, claimed or not (#337).
func TestPollClaims_RestartedNodeServesClaimedEventsAgain(t *testing.T) {
	t.Setenv("I2SIG_POLL_CLAIM_TTL", "30s")
	h, persistence := newPollKeyHarness(t, "50ms")
	sid := h.createSigningPollStream(t, pollKeyIssuer, model.RouteModePublish).StreamConfiguration.Id
	all := h.queuePollEvents(t, sid, 4)

	first, _ := h.poll(sid)
	require.Len(t, first, 4)
	none, _ := h.poll(sid)
	require.Empty(t, none, "claimed SETs are not served again on the same node")

	// The first node stops (giving back its poll-transmitter lease, #365)
	// and a fresh one takes the stream over.
	h.router.Shutdown()
	restarted := routerOn(t, persistence, "node-poll-key-restarted")
	var sets map[string]string
	require.Eventually(t, func() bool {
		sets, _ = restarted.poll(sid)
		return len(sets) == len(all)
	}, 5*time.Second, 50*time.Millisecond, "a restarted node must serve every pending SET")
	assert.ElementsMatch(t, all, keysOf(sets))
}
