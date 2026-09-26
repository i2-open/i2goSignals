package delivery

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/pkg/goSetPush"
)

// TestHTTPAdapter_PlaintextWithoutOptOutIsATransportFailure pins the end-to-end
// push path of the business-stream TLS floor (#322): a stream that has not opted
// out (tx_allow_plaintext false) pointed at a plaintext receiver never reaches
// the wire and records a transport-class failure naming ErrPlaintextNotAllowed,
// while the same stream with the opt-out delivers.
func TestHTTPAdapter_PlaintextWithoutOptOutIsATransportFailure(t *testing.T) {
	var hits int32
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer receiver.Close()

	key, kid := newTestKey(t)
	adapter := NewHTTPAdapter(nil, nil)

	refused := newPublishStream(receiver.URL + "/events")
	refused.TxAllowPlaintext = false
	out := adapter.Deliver(context.Background(), PushRequest{
		Stream: refused,
		Event:  newEventRecord(),
		Key:    key,
		Kid:    kid,
	})
	assert.Equal(t, goSetPush.ClassTransport, out.Classification.Class)
	assert.Equal(t, int32(0), atomic.LoadInt32(&hits), "no request may reach the plaintext receiver")

	// The underlying PushResult surfaces the sentinel so the router's failure
	// reason names the cause.
	res := goSetPush.PushSET(context.Background(), "unused.token.value", goSetPush.TransmitterConfig{
		EndpointURL: receiver.URL + "/events",
	})
	require.Error(t, res.Err)
	assert.True(t, errors.Is(res.Err, goSetPush.ErrPlaintextNotAllowed), "%v", res.Err)

	optedOut := newPublishStream(receiver.URL + "/events")
	out = adapter.Deliver(context.Background(), PushRequest{
		Stream: optedOut,
		Event:  newEventRecord(),
		Key:    key,
		Kid:    kid,
	})
	assert.Equal(t, goSetPush.ClassAccepted, out.Classification.Class)
	assert.Equal(t, int32(1), atomic.LoadInt32(&hits), "the opted-out stream delivers to the plaintext receiver")
}
