package buffer

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// Poll claims (#337): a poll claims the JTIs it returns, so an overlapping
// poll gets the next disjoint slice; an ack or a release frees them, and an
// expired claim makes an unacked JTI servable again (ADR 0038).

func claimBuffer(t *testing.T, jtis ...string) *EventPollBuffer {
	t.Helper()
	b := CreateEventPollBuffer(jtis, 0, 0)
	t.Cleanup(b.Close)
	return b
}

func jtiList(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = string(rune('a' + i))
	}
	return out
}

func TestPollClaim_OverlappingClaimsAreDisjointAndInOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		all := jtiList(10)
		b := claimBuffer(t, all...)
		params := model.PollParameters{MaxEvents: 5, ReturnImmediately: true}

		tok1, first, more1 := b.ClaimEvents(params, 30*time.Second)
		tok2, second, more2 := b.ClaimEvents(params, 30*time.Second)
		require.NotEmpty(t, tok1)
		require.NotEqual(t, tok1, tok2)
		require.Equal(t, all[:5], *first)
		require.True(t, more1)
		require.Equal(t, all[5:], *second)
		require.False(t, more2)
		require.Equal(t, 10, b.ClaimedCnt())

		_, third, _ := b.ClaimEvents(params, 30*time.Second)
		require.Nil(t, third, "everything is claimed")
		got, _ := b.GetEvents(params)
		require.Nil(t, got, "GetEvents skips claimed JTIs")
		synctest.Wait()
	})
}

func TestPollClaim_ExpiredClaimIsServedAgain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := claimBuffer(t, jtiList(4)...)
		params := model.PollParameters{MaxEvents: 2, ReturnImmediately: true}
		_, first, _ := b.ClaimEvents(params, 10*time.Second)
		_, _, _ = b.ClaimEvents(params, 20*time.Second)

		time.Sleep(10 * time.Second)
		require.Equal(t, 2, b.ClaimedCnt())
		_, again, _ := b.ClaimEvents(model.PollParameters{ReturnImmediately: true}, 10*time.Second)
		require.Equal(t, *first, *again, "the expired claim's JTIs come back, the live one's do not")
		synctest.Wait()
	})
}

func TestPollClaim_AckAndReleaseFreeClaims(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := claimBuffer(t, jtiList(4)...)
		params := model.PollParameters{MaxEvents: 2, ReturnImmediately: true}
		_, first, _ := b.ClaimEvents(params, time.Minute)
		tok2, second, _ := b.ClaimEvents(params, time.Minute)

		b.AckEvents(*first)
		require.Equal(t, 2, b.ClaimedCnt())
		require.Equal(t, 2, b.Cnt(), "acked JTIs leave the buffer")

		b.ReleaseClaim(tok2)
		require.Zero(t, b.ClaimedCnt())
		_, again, _ := b.ClaimEvents(params, time.Minute)
		require.Equal(t, *second, *again, "released JTIs are served by the next poll")
		synctest.Wait()
	})
}

// A JTI submitted twice (a wake and a poll's prefetch) is queued once, so
// its ack takes it out of the buffer rather than leaving a copy to serve.
func TestPollClaim_DuplicateSubmitIsQueuedOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := claimBuffer(t, "a")
		b.SubmitEvents([]string{"a", "b"})
		b.SubmitEvent("a")
		synctest.Wait()
		require.Equal(t, 2, b.Cnt())

		params := model.PollParameters{ReturnImmediately: true}
		_, first, _ := b.ClaimEvents(params, time.Minute)
		require.Equal(t, []string{"a", "b"}, *first)
		b.AckEvents(*first)
		_, again, _ := b.ClaimEvents(params, time.Minute)
		require.Nil(t, again, "an acked JTI is not served again")

		b.SubmitEvent("a")
		synctest.Wait()
		require.Equal(t, 1, b.Cnt(), "a JTI submitted after its ack is queued again")
	})
}

// AddEvents queues before it returns, so the next claim serves the JTIs.
func TestPollClaim_AddEventsIsServedAtOnce(t *testing.T) {
	b := claimBuffer(t)
	b.AddEvents([]string{"a", "b", "a"})
	_, got, _ := b.ClaimEvents(model.PollParameters{ReturnImmediately: true}, time.Minute)
	require.NotNil(t, got)
	require.Equal(t, []string{"a", "b"}, *got)
}

func TestPollClaim_ZeroTTLTakesNoClaim(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := claimBuffer(t, jtiList(3)...)
		params := model.PollParameters{ReturnImmediately: true}
		tok, first, _ := b.ClaimEvents(params, 0)
		_, second, _ := b.ClaimEvents(params, 0)
		require.Empty(t, tok)
		require.Equal(t, *first, *second)
		synctest.Wait()
	})
}

// A long poll with everything claimed returns immediately under
// returnImmediately, and otherwise waits until a claim expires.
func TestPollClaim_LongPollWakesOnClaimExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := claimBuffer(t, jtiList(2)...)
		_, _, _ = b.ClaimEvents(model.PollParameters{ReturnImmediately: true}, 5*time.Second)

		start := time.Now()
		_, none, _ := b.ClaimEvents(model.PollParameters{ReturnImmediately: true}, 5*time.Second)
		require.Nil(t, none)
		require.Zero(t, time.Since(start), "returnImmediately does not wait")

		_, got, _ := b.ClaimEvents(model.PollParameters{TimeoutSecs: 30}, 5*time.Second)
		require.Len(t, *got, 2)
		require.Equal(t, 5*time.Second, time.Since(start), "the long poll ends when the claim expires")
		synctest.Wait()
	})
}

func TestPollClaim_LongPollWithNothingToExpireWaitsTheTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := claimBuffer(t)
		start := time.Now()
		_, got, _ := b.ClaimEvents(model.PollParameters{TimeoutSecs: 7}, 5*time.Second)
		require.Nil(t, got)
		require.Equal(t, 7*time.Second, time.Since(start))
		synctest.Wait()
	})
}
