package eventRouter

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// TestPushStatusFetcher_PlaintextWithoutOptOutMakesNoRequest pins the TLS floor
// on the receiver-status probe (#322): the fetcher refuses a plaintext push
// endpoint with ErrPlaintextNotAllowed before any request is made.
func TestPushStatusFetcher_PlaintextWithoutOptOutMakesNoRequest(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	r := newTestRouter(t).router
	stream := &model.StreamStateRecord{}
	stream.StreamConfiguration = model.StreamConfiguration{
		Id: "abc123",
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PushTransmitMethod: &model.PushTransmitMethod{
				Method:      model.DeliveryPush,
				EndpointUrl: server.URL + "/events/abc123",
			},
		},
	}

	status, err := r.pushStatusFetcher()(context.Background(), stream)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPlaintextNotAllowed), "%v", err)
	assert.Nil(t, status)
	assert.Equal(t, int32(0), atomic.LoadInt32(&hits), "no request may reach the plaintext receiver")
}
