package eventRouter

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/internal/eventRouter/delivery"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
)

// TestPushBatch_ConcurrentHTTPDeliveriesRecordRemoteAddressWithoutRace is the
// regression test for issue #346: one push stream, a worker pool of at least
// two, one pushBatch with several work items, and a real HTTP receiver. Every
// worker shares the stream's *StreamStateRecord, and each successful POST
// records the dialed peer address on it. Under `go test -race` this failed
// before the adapter serialised the compare-and-persist per stream.
func TestPushBatch_ConcurrentHTTPDeliveriesRecordRemoteAddressWithoutRace(t *testing.T) {
	t.Setenv("I2SIG_PUSH_CONCURRENCY", "4")
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Hold each POST briefly so the workers overlap on separate connections.
		time.Sleep(5 * time.Millisecond)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer receiver.Close()

	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	persistence, err := dbProviders.OpenPersistence("memorydb:", "push_remote_address_test")
	require.NoError(t, err)
	t.Cleanup(func() {
		if persistence.Storage != nil {
			_ = persistence.Storage.Close()
		}
	})

	r := NewRouter(RouterDeps{
		StreamService:        persistence.StreamService,
		KeyService:           persistence.KeyService,
		EventService:         persistence.EventService,
		Coordinator:          persistence.Coordinator,
		SubjectFilterService: persistence.SubjectFilterService,
		PushDelivery:         delivery.NewHTTPAdapter(persistence.StreamService, nil),
	}, "node-push-remote-address").(*router)
	t.Cleanup(r.Shutdown)
	require.GreaterOrEqual(t, r.pushConcurrency, 2)

	h := &filterPushHarness{
		router:        r,
		streamService: persistence.StreamService,
		keyService:    persistence.KeyService,
		eventService:  persistence.EventService,
		subjectFilter: persistence.SubjectFilterService,
	}
	stream := h.createPushStream(t, "NONE")
	stream.Delivery.PushTransmitMethod.EndpointUrl = receiver.URL + "/events"
	stream.TxAllowPlaintext = true // plaintext httptest receiver (#322)
	sid := stream.StreamConfiguration.Id
	jtis := h.addPendingEvents(t, sid, 12)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	res := r.pushBatch(jtis, stream, key, "kid-346", 0)

	require.Empty(t, res.failedJti)
	require.Equal(t, 12, res.acked)
	require.NotNil(t, stream.RemoteAddress, "a successful push records the peer address")

	persisted, err := persistence.StreamService.GetStreamState(t.Context(), sid)
	require.NoError(t, err)
	require.NotNil(t, persisted.RemoteAddress, "the peer address is persisted")
	require.Equal(t, "http", persisted.RemoteAddress.Protocol)
}
