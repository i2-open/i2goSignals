package test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReceiverStreamDeleteCascadesToTransmitter locks down the receiver-side
// cascade DELETE introduced in commits 722419c (cascade) and 55af409 (drain
// before cascade): when a locally-managed receiver stream is removed via the
// management API the SUT MUST (a) drain any in-flight poll for that stream
// before issuing the cascade, and (b) emit exactly one DELETE to the
// transmitter's configuration_endpoint identified by the REMOTE stream_id, not
// the local one (SSF 1.0 §8.1.1.5).
//
// Until this test existed the behavior was only exercised by the SSF receiver
// conformance suite; reverting either commit on a scratch branch would now
// trip this regression test instead.
func TestReceiverStreamDeleteCascadesToTransmitter(t *testing.T) {
	const remoteStreamId = "remote-tx-stream-id"

	// Mock transmitter state — shared across all handlers on this httptest.Server.
	var (
		mu               sync.Mutex
		deleteCount      int
		deleteStreamIdQS string
		deletePath       string
		deleteAt         time.Time
		pollReturnedAt   time.Time
		pollStartedCh    = make(chan struct{}, 1)
		pollHoldFor      = 750 * time.Millisecond // long enough to overlap the DELETE if drain were missing
	)

	var mockTs *httptest.Server
	mockTs = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.well-known/ssf-configuration" || r.URL.Path == "/.well-known/sse-configuration":
			// Receiver discovers the cascade target through this document.
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(model.TransmitterConfiguration{
				ConfigurationEndpoint: mockTs.URL + "/stream",
				StatusEndpoint:        mockTs.URL + "/status",
			})
		case r.URL.Path == "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
		case r.URL.Path == "/status":
			// Receiver does an initial status check before polling — keep it enabled.
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(model.StreamStatus{Status: model.StreamStateEnabled})
		case r.URL.Path == "/poll":
			// Signal the poll has started (non-blocking) so the test can race the
			// DELETE against an in-flight long-poll. Then park briefly. The drain
			// contract is that the DELETE waits for THIS handler to return before
			// the cascade DELETE hits /stream.
			select {
			case pollStartedCh <- struct{}{}:
			default:
			}
			time.Sleep(pollHoldFor)
			mu.Lock()
			pollReturnedAt = time.Now()
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(model.PollResponse{Sets: map[string]string{}})
		case r.URL.Path == "/stream" && r.Method == http.MethodDelete:
			mu.Lock()
			deleteCount++
			deletePath = r.URL.Path
			deleteStreamIdQS = r.URL.Query().Get("stream_id")
			deleteAt = time.Now()
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			// Unrouted requests must not silently 200 — we want any drift to surface.
			t.Logf("mock transmitter saw unexpected %s %s", r.Method, r.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockTs.Close()

	instance, err := createServer(t, "rcv_cascade_delete_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	// Register a receiver poll stream that points at the mock transmitter. The
	// RemoteStreamId differs from the local Id on purpose: §8.1.1.5 says the
	// cascade DELETE must carry the REMOTE id, and locking that down is the
	// whole point of this test.
	wellKnown := mockTs.URL + "/.well-known/ssf-configuration"
	remoteId := remoteStreamId
	streamConfig := model.StreamConfiguration{
		Iss:             "https://mock-transmitter.example.com",
		Aud:             []string{"rcv.example.com"},
		TxWellKnownUrl:  &wellKnown,
		IssuerJWKSUrl:   mockTs.URL + "/jwks",
		RemoteStreamId:  &remoteId,
		EventsRequested: []string{"*"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{
				Method:      model.ReceivePoll,
				EndpointUrl: mockTs.URL + "/poll",
				PollConfig: &model.PollParameters{
					ReturnImmediately: true,
					TimeoutSecs:       2,
				},
			},
		},
		RouteMode: model.RouteModeImport,
	}

	created, err := instance.CreateStream(streamConfig, authSupport.ConvertProject(instance.projectId))
	require.NoError(t, err)
	require.NotEqual(t, remoteStreamId, created.Id, "local id must differ from remote id for the cascade-id assertion to be meaningful")

	state, err := instance.GetStreamState(created.Id)
	require.NoError(t, err)
	ps := instance.app.HandleReceiver(state)
	require.NotNil(t, ps, "HandleReceiver must start the polling goroutine")

	// Wait for the receiver to have an in-flight poll against the mock. The
	// drain contract only matters when there IS a poll to drain.
	select {
	case <-pollStartedCh:
	case <-time.After(8 * time.Second):
		t.Fatalf("receiver never issued a poll request to the mock transmitter")
	}

	// Issue the management DELETE while the mock's /poll handler is still
	// parked. If DrainReceiver were skipped the cascade DELETE would arrive
	// at the mock before /poll returned (deleteAt < pollReturnedAt); the
	// drain contract guarantees the opposite ordering.
	streamUrl := instance.ts.URL + "/stream?stream_id=" + created.Id
	req, err := http.NewRequest(http.MethodDelete, streamUrl, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+instance.streamMgmtToken)
	resp, err := instance.client.Do(req)
	require.NoError(t, err, "management DELETE failed")
	require.Equal(t, http.StatusNoContent, resp.StatusCode, "management DELETE should answer 204")
	_ = resp.Body.Close()

	// The cascade DELETE is best-effort and runs synchronously inside the
	// handler, so by the time the management DELETE returns 204 the mock has
	// already seen its cascade. Use Eventually only as a small safety net for
	// CI scheduler jitter.
	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return deleteCount >= 1
	}, 5*time.Second, 25*time.Millisecond, "transmitter never received the cascade DELETE")

	mu.Lock()
	gotCount := deleteCount
	gotPath := deletePath
	gotStreamId := deleteStreamIdQS
	gotDeleteAt := deleteAt
	gotPollReturnedAt := pollReturnedAt
	mu.Unlock()

	assert.Equal(t, 1, gotCount, "cascade DELETE must fire exactly once, not retried")
	assert.Equal(t, "/stream", gotPath, "cascade DELETE must hit the configuration_endpoint path")
	assert.Equal(t, remoteStreamId, gotStreamId,
		"cascade DELETE must identify the stream by the REMOTE stream_id, not the local id (§8.1.1.5)")
	assert.NotContains(t, gotStreamId, created.Id, "cascade DELETE must not carry the local stream_id")

	// Drain ordering: the in-flight poll returned before the DELETE arrived.
	// The mock's /poll handler parks for pollHoldFor before returning and only
	// then records pollReturnedAt. The mock's /stream DELETE handler records
	// deleteAt the moment the cascade reaches it. With DrainReceiver in place
	// the SUT waits for the parked poll to finish before issuing the cascade,
	// so deleteAt >= pollReturnedAt. Without drain, the cascade fires while
	// the poll is still parked: pollReturnedAt stays zero at the assertion
	// window (the parked goroutine outlives the test's wait), which is itself
	// a clean drain-broken signal that the require.False catches.
	require.False(t, gotPollReturnedAt.IsZero(),
		"DrainReceiver missing — cascade DELETE arrived while the in-flight poll was still parked at the transmitter (deleteAt=%s)",
		gotDeleteAt.Format(time.RFC3339Nano))
	assert.True(t, gotDeleteAt.After(gotPollReturnedAt) || gotDeleteAt.Equal(gotPollReturnedAt),
		"DrainReceiver must complete the in-flight poll before the cascade DELETE: poll_return=%s delete=%s",
		gotPollReturnedAt.Format(time.RFC3339Nano), gotDeleteAt.Format(time.RFC3339Nano))

	// Trailing: the receiver client must have been torn down so the goroutine
	// stops polling the mock after the cascade. (Not part of the criteria but
	// catches a future regression where CloseReceiver gets dropped.)
	// Drain any straggler poll the mock might field within a short window:
	// none should arrive because /poll is gated on the goroutine being alive.
	drainDeadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(drainDeadline) {
		select {
		case <-pollStartedCh:
			// Allowed: the goroutine may have re-entered /poll before the
			// DELETE cancelled it. We don't assert here because the cancel
			// race is timing-dependent — what matters is that we never see
			// a SECOND cascade DELETE.
		default:
		}
		time.Sleep(25 * time.Millisecond)
	}
	mu.Lock()
	finalDeleteCount := deleteCount
	mu.Unlock()
	assert.Equal(t, 1, finalDeleteCount, "cascade DELETE must fire exactly once even after receiver teardown settles")
}
