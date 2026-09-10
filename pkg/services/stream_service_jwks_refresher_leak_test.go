package services

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keyfuncRefresherFrame is the stack frame of the goroutine keyfunc.Get starts
// for every JWKS it loads from a URL with a RefreshInterval set. Counting it is
// the same measurement the GH #290 report made from goroutine profiles of the
// dev cluster, taken here in-process instead.
const keyfuncRefresherFrame = "github.com/MicahParks/keyfunc/v2.(*JWKS).backgroundRefresh"

// keyfuncRefresherCount reports how many keyfunc background refreshers are live
// in this process. Only DELTAS across one test are meaningful: other tests in
// this package load JWKS too, so the absolute number carries their residue.
func keyfuncRefresherCount() int {
	buf := make([]byte, 1<<18)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return bytes.Count(buf[:n], []byte(keyfuncRefresherFrame))
		}
		buf = make([]byte, 2*len(buf))
	}
}

// requireRefresherCount waits for the refresher population to settle on want.
// It polls rather than sampling once because both edges are asynchronous: a
// rebuild starts the new refreshers before it ends the displaced ones, and an
// ended refresher exits on its own schedule once its context is cancelled.
func requireRefresherCount(t *testing.T, want int, what string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	got := keyfuncRefresherCount()
	for got != want && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		got = keyfuncRefresherCount()
	}
	require.Equalf(t, want, got,
		"%s: the live keyfunc refresher count never settled on the expected value", what)
}

// endAllRefreshers drops whatever this harness still holds so the count this
// test moved does not leak into the next test's baseline.
func endAllRefreshers(t *testing.T, svc *StreamService) {
	t.Helper()
	t.Cleanup(func() {
		svc.mu.Lock()
		defer svc.mu.Unlock()
		for _, entry := range svc.receiverStreams {
			entry.endBackground()
		}
	})
}

// TestLoadReceiverStreams_RebuildDoesNotLeakJwksRefreshers is the GH #290
// reproduction. LoadReceiverStreams rebuilds the entire receiverStreams map and
// newReceiverEntry loads a JWKS per entry, so before the fix every rebuild
// started a fresh keyfunc refresher per receiver stream and abandoned the
// previous one still running: one goroutine and one hourly outbound JWKS fetch
// per stream per rebuild, for the life of the process. The provider calls
// LoadReceiverStreams on every (re)connect, so a reconnecting node accumulated
// them indefinitely.
//
// The bar: the refresher population after N rebuilds equals the population
// after the first one. This is not load-dependent, so the count is the proof.
func TestLoadReceiverStreams_RebuildDoesNotLeakJwksRefreshers(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwksSrv := newFlakyJwksServer(t, "rebuild-leak", &key.PublicKey)
	jwksSrv.healthy.Store(true)

	h := newRetryHarness(t)
	endAllRefreshers(t, h.svc)
	ctx := context.Background()

	const streams = 3
	for i := 0; i < streams; i++ {
		rec := newJwksReceiverFixture(t, fmt.Sprintf("https://tx%d.example", i), jwksSrv.URL)
		require.NoError(t, h.streamDAO.Create(ctx, rec))
	}

	baseline := keyfuncRefresherCount()
	h.svc.LoadReceiverStreams(ctx)
	settled := baseline + streams
	requireRefresherCount(t, settled, "first preload")
	require.Len(t, h.svc.receiverStreams, streams)

	const rebuilds = 10
	for i := 1; i <= rebuilds; i++ {
		h.svc.LoadReceiverStreams(ctx)
		requireRefresherCount(t, settled, fmt.Sprintf("after rebuild %d of %d", i, rebuilds))
	}

	// The cache still verifies after all that ending: over-cancelling the
	// refreshers would be as wrong as leaking them, and EndBackground must stop
	// only the refresh loop, never the parsed keys.
	for sid := range h.svc.receiverStreams {
		jwks := h.svc.GetIssuerJwksForReceiver(ctx, sid)
		require.NotNil(t, jwks, "sid %s lost its verification material across rebuilds", sid)
		assert.Contains(t, jwks.KIDs(), "rebuild-leak")
	}
}

// TestDeleteStream_EndsTheDeletedStreamsJwksRefresherOnly covers the second
// half of GH #290's acceptance: a deleted stream must stop fetching its
// issuer's JWKS, and a stream that survives must keep its own refresher. The
// two streams use distinct issuers, which is the "issuer not referenced by any
// other stream" case the issue names.
func TestDeleteStream_EndsTheDeletedStreamsJwksRefresherOnly(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	doomedSrv := newFlakyJwksServer(t, "doomed-issuer", &key.PublicKey)
	doomedSrv.healthy.Store(true)
	survivorSrv := newFlakyJwksServer(t, "surviving-issuer", &key.PublicKey)
	survivorSrv.healthy.Store(true)

	h := newRetryHarness(t)
	endAllRefreshers(t, h.svc)
	ctx := context.Background()

	doomed := newJwksReceiverFixture(t, "https://doomed.example", doomedSrv.URL)
	require.NoError(t, h.streamDAO.Create(ctx, doomed))
	survivor := newJwksReceiverFixture(t, "https://survivor.example", survivorSrv.URL)
	require.NoError(t, h.streamDAO.Create(ctx, survivor))

	baseline := keyfuncRefresherCount()
	h.svc.LoadReceiverStreams(ctx)
	requireRefresherCount(t, baseline+2, "preload of two receiver streams")

	require.NoError(t, h.svc.DeleteStream(ctx, doomed.StreamConfiguration.Id))
	requireRefresherCount(t, baseline+1, "after deleting one of the two streams")

	surviving := h.svc.GetIssuerJwksForReceiver(ctx, survivor.StreamConfiguration.Id)
	require.NotNil(t, surviving, "the surviving stream must keep its verification material")
	assert.Contains(t, surviving.KIDs(), "surviving-issuer")
}
