package eventRouter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/internal/eventRouter/peer"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

func newPeerWiringRouter(t *testing.T, name string, transport peer.PeerTransport) (*router, *dbProviders.Persistence) {
	t.Helper()
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	persistence, err := dbProviders.OpenPersistence("memorydb:", name)
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
		PeerTransport:        transport,
	}, "node-a").(*router)
	t.Cleanup(r.Shutdown)
	return r, persistence
}

// A router built without an injected transport sends wakes over HTTP: the
// wake reaches the owner node's /_cluster/wake-transmitter route as a
// WakeMessage body with a cluster token over (sid, mode).
func TestRouter_DefaultPeerTransportIsHTTP(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", "wiring-secret")
	type hit struct {
		path string
		msg  peer.WakeMessage
		ok   bool
	}
	got := make(chan hit, 1)
	nodeB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m peer.WakeMessage
		_ = json.NewDecoder(r.Body).Decode(&m)
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		got <- hit{r.URL.Path, m, authSupport.ValidateClusterToken("wiring-secret", tok, m.Sid, m.Mode, 30*time.Second)}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer nodeB.Close()

	r, persistence := newPeerWiringRouter(t, "peer_wiring_http", nil)
	require.NotNil(t, r.peers)
	require.NoError(t, persistence.Coordinator.RegisterNode(model.ClusterNode{Id: "node-b", Address: nodeB.URL, LastSeenAt: time.Now()}))

	r.sendWakeup("s-358", peer.ModePoll, "node-b", "")

	select {
	case h := <-got:
		assert.Equal(t, peer.WakeTransmitterPath, h.path)
		assert.Equal(t, peer.WakeMessage{Sid: "s-358", Mode: peer.ModePoll}, h.msg)
		assert.True(t, h.ok, "the wake carries a valid cluster token")
	case <-time.After(5 * time.Second):
		t.Fatal("the wake never reached node-b")
	}
}

type recordingTransport struct {
	mu    sync.Mutex
	wakes []string
}

func (rt *recordingTransport) Wake(_ context.Context, owner string, msg peer.WakeMessage) error {
	rt.mu.Lock()
	rt.wakes = append(rt.wakes, owner+"|"+msg.Sid+"|"+msg.Mode+"|"+msg.Reason)
	rt.mu.Unlock()
	return nil
}

func (rt *recordingTransport) Claim(context.Context, string, peer.ClaimRequest) (peer.ClaimResponse, error) {
	return peer.ClaimResponse{NotOwner: true}, nil
}

// Every wake the router sends, owner-directed or SSTP broadcast, goes through
// the injected transport.
func TestRouter_WakesGoThroughInjectedTransport(t *testing.T) {
	rt := &recordingTransport{}
	r, _ := newPeerWiringRouter(t, "peer_wiring_injected", rt)

	r.sendWakeup("s1", peer.ModePush, "node-b", ReasonFilterChange)
	r.sendSstpWake(peer.WakeSstpServerPath, peer.ModeSstpServer, "p1")

	rt.mu.Lock()
	defer rt.mu.Unlock()
	assert.Equal(t, []string{"node-b|s1|push|" + ReasonFilterChange, "|p1|sstp-server|"}, rt.wakes)
}

func TestRouter_HandleClaimAnswersNotOwner(t *testing.T) {
	r, _ := newPeerWiringRouter(t, "peer_wiring_claim", &recordingTransport{})
	resp := r.HandleClaim(context.Background(), peer.ClaimRequest{Sid: "s1", Mode: peer.ModePoll, MaxEvents: 5})
	assert.True(t, resp.NotOwner)
	assert.Empty(t, resp.Refs)
}

// A wake for a stream with no resident buffer is a harmless no-op in every mode.
func TestRouter_HandleWakeUnknownStreamIsNoop(t *testing.T) {
	r, _ := newPeerWiringRouter(t, "peer_wiring_wake", &recordingTransport{})
	for _, mode := range []string{peer.ModePush, peer.ModePoll, peer.ModeSstpClient, peer.ModeSstpServer, "bogus"} {
		r.HandleWake(peer.WakeMessage{Sid: "absent", Mode: mode})
	}
	r.HandleWake(peer.WakeMessage{Sid: "absent", Mode: peer.ModePush, Reason: ReasonFilterChange})
}
