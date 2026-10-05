package eventRouter

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/i2-open/i2goSignals/internal/eventRouter/buffer"
	"github.com/stretchr/testify/require"
)

// Poll claims (#337) belong to the stream's delivery queue (#363): a claim
// taken from the queue's buffer hides its JTIs from an overlapping claim, an
// ack or a release frees them, and an expired claim makes an unacked JTI
// servable again (ADR 0038). The buffer only orders the JTIs and wakes a
// long poll.

func claimQueue(t *testing.T, jtis ...string) (*deliveryQueue, *buffer.EventPollBuffer) {
	t.Helper()
	b := buffer.CreateEventPollBuffer(jtis, 0, 0)
	t.Cleanup(b.Close)
	return newDeliveryQueue(nil, "sid", 10), b
}

func claimJtiList(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = string(rune('a' + i))
	}
	return out
}

func TestQueueClaim_OverlappingClaimsAreDisjointAndInOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		all := claimJtiList(10)
		q, b := claimQueue(t, all...)
		ctx := context.Background()

		tok1, first, more1 := q.ClaimEvents(ctx, b, 5, 0, 30*time.Second)
		tok2, second, more2 := q.ClaimEvents(ctx, b, 5, 0, 30*time.Second)
		require.NotEmpty(t, tok1)
		require.NotEqual(t, tok1, tok2)
		require.Equal(t, all[:5], first)
		require.True(t, more1)
		require.Equal(t, all[5:], second)
		require.False(t, more2)
		require.Equal(t, 10, q.ClaimedCnt())

		_, third, _ := q.ClaimEvents(ctx, b, 5, 0, 30*time.Second)
		require.Empty(t, third, "everything is claimed")
		require.Equal(t, 10, b.Cnt(), "the buffer still holds every claimed JTI")
		synctest.Wait()
	})
}

func TestQueueClaim_ExpiredClaimIsServedAgain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q, b := claimQueue(t, claimJtiList(4)...)
		ctx := context.Background()
		_, first, _ := q.ClaimEvents(ctx, b, 2, 0, 10*time.Second)
		_, _, _ = q.ClaimEvents(ctx, b, 2, 0, 20*time.Second)

		time.Sleep(10 * time.Second)
		require.Equal(t, 2, q.ClaimedCnt())
		_, again, _ := q.ClaimEvents(ctx, b, 0, 0, 10*time.Second)
		require.Equal(t, first, again, "the expired claim's JTIs come back, the live one's do not")
		synctest.Wait()
	})
}

func TestQueueClaim_AckAndReleaseFreeClaims(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q, b := claimQueue(t, claimJtiList(4)...)
		ctx := context.Background()
		_, first, _ := q.ClaimEvents(ctx, b, 2, 0, time.Minute)
		tok2, second, _ := q.ClaimEvents(ctx, b, 2, 0, time.Minute)

		q.ackBuffered(b, first)
		require.Equal(t, 2, q.ClaimedCnt())
		require.Equal(t, 2, b.Cnt(), "acked JTIs leave the buffer")

		q.ReleaseClaim(tok2)
		require.Zero(t, q.ClaimedCnt())
		_, again, _ := q.ClaimEvents(ctx, b, 2, 0, time.Minute)
		require.Equal(t, second, again, "released JTIs are served by the next claim")
		synctest.Wait()
	})
}

// A JTI submitted twice (a wake and a poll's prefetch) is served once per
// batch, and its ack removes every copy rather than leaving one to serve.
func TestQueueClaim_DuplicateSubmitIsServedOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q, b := claimQueue(t, "a")
		b.SubmitEvents([]string{"a", "b"})
		b.SubmitEvent("a")
		synctest.Wait()

		ctx := context.Background()
		_, first, more := q.ClaimEvents(ctx, b, 0, 0, time.Minute)
		require.Equal(t, []string{"a", "b"}, first)
		require.False(t, more, "the hidden copies are not counted as more")
		q.ackBuffered(b, first)
		require.Zero(t, b.Cnt(), "an ack removes every copy")
		_, again, _ := q.ClaimEvents(ctx, b, 0, 0, time.Minute)
		require.Empty(t, again, "an acked JTI is not served again")
	})
}

// AddEvents queues before it returns, so the next claim serves the JTIs.
func TestQueueClaim_AddEventsIsServedAtOnce(t *testing.T) {
	q, b := claimQueue(t)
	b.AddEvents([]string{"a", "b", "a"})
	_, got, _ := q.ClaimEvents(context.Background(), b, 0, 0, time.Minute)
	require.Equal(t, []string{"a", "b"}, got)
}

func TestQueueClaim_ZeroTTLTakesNoClaim(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q, b := claimQueue(t, claimJtiList(3)...)
		ctx := context.Background()
		tok, first, _ := q.ClaimEvents(ctx, b, 0, 0, 0)
		_, second, _ := q.ClaimEvents(ctx, b, 0, 0, 0)
		require.Empty(t, tok)
		require.Equal(t, first, second)
		require.Zero(t, q.ClaimedCnt())
		synctest.Wait()
	})
}

// A claim with everything claimed returns at once without a wait, and with
// one waits until a claim expires.
func TestQueueClaim_LongPollWakesOnClaimExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q, b := claimQueue(t, claimJtiList(2)...)
		ctx := context.Background()
		_, _, _ = q.ClaimEvents(ctx, b, 0, 0, 5*time.Second)

		start := time.Now()
		_, none, _ := q.ClaimEvents(ctx, b, 0, 0, 5*time.Second)
		require.Empty(t, none)
		require.Zero(t, time.Since(start), "no wait means no wait")

		_, got, _ := q.ClaimEvents(ctx, b, 0, 30*time.Second, 5*time.Second)
		require.Len(t, got, 2)
		require.Equal(t, 5*time.Second, time.Since(start), "the long poll ends when the claim expires")
		synctest.Wait()
	})
}

func TestQueueClaim_LongPollWithNothingToExpireWaitsTheTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q, b := claimQueue(t)
		start := time.Now()
		_, got, _ := q.ClaimEvents(context.Background(), b, 0, 7*time.Second, 5*time.Second)
		require.Empty(t, got)
		require.Equal(t, 7*time.Second, time.Since(start))
		synctest.Wait()
	})
}

// A cancelled context ends the wait at once and claims nothing.
func TestQueueClaim_CancelledContextClaimsNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q, b := claimQueue(t)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan []string, 1)
		go func() {
			_, got, _ := q.ClaimEvents(ctx, b, 0, time.Minute, time.Minute)
			done <- got
		}()
		synctest.Wait()
		start := time.Now()
		cancel()
		b.AddEvents([]string{"a"})
		got := <-done
		require.Empty(t, got)
		require.Zero(t, time.Since(start))
		require.Zero(t, q.ClaimedCnt(), "nothing is claimed after the cancel")
	})
}

// Claims live in the queue, not the buffer: a fresh buffer for the same
// queue still sees them, and dropping the queue's claims frees them.
func TestQueueClaim_ClaimsBelongToTheQueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q, b := claimQueue(t, "a", "b")
		ctx := context.Background()
		_, first, _ := q.ClaimEvents(ctx, b, 1, 0, time.Minute)
		require.Equal(t, []string{"a"}, first)

		rebuilt := buffer.CreateEventPollBuffer([]string{"a", "b"}, 0, 0)
		t.Cleanup(rebuilt.Close)
		_, next, _ := q.ClaimEvents(ctx, rebuilt, 0, 0, time.Minute)
		require.Equal(t, []string{"b"}, next, "the queue's claim on a hides it in any buffer")

		q.clearClaims()
		require.Zero(t, q.ClaimedCnt())
		synctest.Wait()
	})
}
