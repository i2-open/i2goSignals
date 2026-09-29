package delivery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingAddressStore records every UpdateRemoteAddress call so a test can
// see how often the adapter persists (issue #346).
type countingAddressStore struct {
	mu    sync.Mutex
	calls []*model.RemoteIP
}

func (c *countingAddressStore) UpdateRemoteAddress(_ context.Context, _ string, addr *model.RemoteIP) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, addr)
}

func (c *countingAddressStore) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.calls)
}

// TestHTTPAdapter_RepeatedIdenticalAddressPersistsOnce: sequential pushes over
// one kept-alive connection see the same peer address, so only the first
// persists it; the rest match what was last recorded and write nothing.
func TestHTTPAdapter_RepeatedIdenticalAddressPersistsOnce(t *testing.T) {
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer receiver.Close()

	store := &countingAddressStore{}
	adapter := &HTTPAdapter{addressStore: store}
	stream := newForwardStream(receiver.URL + "/events")

	var addrs []string
	for i := 0; i < 5; i++ {
		out := adapter.Deliver(context.Background(), PushRequest{Stream: stream, Event: newEventRecord()})
		require.Equal(t, goSetPush.ClassAccepted, out.Classification.Class)
		addrs = append(addrs, out.RemoteAddress)
	}
	for _, a := range addrs[1:] {
		require.Equal(t, addrs[0], a, "precondition: pushes reuse one kept-alive connection")
	}

	assert.Equal(t, 1, store.count(), "an unchanged peer address must not be re-persisted")
	require.NotNil(t, stream.RemoteAddress)
	assert.Equal(t, addrs[0], stream.RemoteAddress.IP)
}

// TestHTTPAdapter_ConcurrentDeliveriesOnOneStream: many goroutines deliver on
// the same *StreamStateRecord at once. Under -race this must not report a data
// race on RemoteAddress, and the in-memory value must match the last persisted
// one.
func TestHTTPAdapter_ConcurrentDeliveriesOnOneStream(t *testing.T) {
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer receiver.Close()

	store := &countingAddressStore{}
	adapter := &HTTPAdapter{addressStore: store}
	stream := newForwardStream(receiver.URL + "/events")

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 4; j++ {
				out := adapter.Deliver(context.Background(), PushRequest{Stream: stream, Event: newEventRecord()})
				assert.Equal(t, goSetPush.ClassAccepted, out.Classification.Class)
			}
		}()
	}
	wg.Wait()

	require.GreaterOrEqual(t, store.count(), 1)
	store.mu.Lock()
	last := store.calls[len(store.calls)-1]
	store.mu.Unlock()
	require.NotNil(t, stream.RemoteAddress)
	assert.True(t, last.Equals(stream.RemoteAddress), "in-memory address converges to the last persisted one")
}
