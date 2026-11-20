package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gatedRenewCoordinator grants the first acquire, then blocks every later
// acquire-or-renew while armed. It logs each completed operation in order.
type gatedRenewCoordinator struct {
	oneShotCoordinator
	armed   atomic.Bool
	entered atomic.Int64
	gate    chan struct{}
	opsMu   sync.Mutex
	ops     []string
}

func (c *gatedRenewCoordinator) record(op string) {
	c.opsMu.Lock()
	c.ops = append(c.ops, op)
	c.opsMu.Unlock()
}

func (c *gatedRenewCoordinator) opsCopy() []string {
	c.opsMu.Lock()
	defer c.opsMu.Unlock()
	return append([]string(nil), c.ops...)
}

func (c *gatedRenewCoordinator) TryAcquireOrRenewLease(resource, nodeId string, d time.Duration) (bool, int64, time.Time, error) {
	if c.armed.Load() {
		c.entered.Add(1)
		<-c.gate
	}
	c.record("renew")
	return true, 1, time.Now().Add(d), nil
}

func (c *gatedRenewCoordinator) ReleaseLeaseIfOwned(resource, nodeId string) error {
	c.record("release")
	return nil
}

func (c *gatedRenewCoordinator) releases() int {
	n := 0
	for _, op := range c.opsCopy() {
		if op == "release" {
			n++
		}
	}
	return n
}

func idleSstpPeer(t *testing.T) *httptest.Server {
	t.Helper()
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", goSetSstp.ContentType)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(goSetSstp.Message{})
	}))
	t.Cleanup(peer.Close)
	return peer
}

func joinTestPair(pairId, url string) model.StreamStateRecord {
	return model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:               "tx-" + pairId,
			Iss:              "https://issuer.example.com",
			Aud:              []string{"https://peer.example.com"},
			RouteMode:        model.RouteModeForward,
			TxAllowPlaintext: true,
		},
		Status: model.StreamStateEnabled,
		PairId: pairId,
		SstpMethod: &model.SstpMethod{
			Role:        model.SstpRoleInitiator,
			EndpointUrl: url,
		},
	}
}

func joinTestConfig() SstpDialerConfig {
	return SstpDialerConfig{
		BaseDelay:           5 * time.Millisecond,
		MaxDelay:            20 * time.Millisecond,
		BackoffFactor:       2.0,
		LeaseDuration:       time.Second,
		HeartbeatInterval:   20 * time.Millisecond,
		HeartbeatRetryDelay: 5 * time.Millisecond,
		Jitter:              func() time.Duration { return 0 },
		HTTPClient:          &http.Client{Timeout: time.Second},
		BackfillBatch:       10,
	}
}

// A heartbeat renewal in flight when the pair stops must finish before the
// lease is released: a renewal landing after the release re-takes the lease
// (the renew filter matches owner=me) and holds it until it expires.
func TestSstpDialer_ReleaseWaitsForInFlightRenewal(t *testing.T) {
	const pairId = "pair-hb-join"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := newFakeSstpOutbound(ctx, joinTestPair(pairId, idleSstpPeer(t).URL))
	coord := &gatedRenewCoordinator{gate: make(chan struct{})}
	var once sync.Once
	unblock := func() { once.Do(func() { close(coord.gate) }) }
	t.Cleanup(unblock)

	dialer := NewSstpDialer(coord, "node-hb", nil, joinTestConfig())
	dialer.Bind(fake)
	dialer.RegisterPair(pairId)

	require.Eventually(t, func() bool { return len(coord.opsCopy()) >= 2 }, 3*time.Second, time.Millisecond,
		"the pair acquired its lease and renewed it")
	coord.armed.Store(true)
	require.Eventually(t, func() bool { return coord.entered.Load() > 0 }, 3*time.Second, time.Millisecond,
		"a heartbeat renewal is in flight")

	stopped := make(chan struct{})
	go func() { dialer.UnregisterPair(pairId); close(stopped) }()
	assert.Never(t, func() bool { return coord.releases() > 0 }, 150*time.Millisecond, time.Millisecond,
		"the lease is not released while a renewal is in flight")

	coord.armed.Store(false)
	unblock()
	<-stopped
	require.Eventually(t, func() bool { return coord.releases() > 0 }, 3*time.Second, time.Millisecond)
	ops := coord.opsCopy()
	assert.Equal(t, "release", ops[len(ops)-1], "nothing renews the lease after its release: %v", ops)
}

// Shutdown waits for every pair loop to exit and release its lease, so the
// application can close storage behind it.
func TestSstpDialer_ShutdownWaitsForPairLoops(t *testing.T) {
	const pairId = "pair-shutdown-join"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := newFakeSstpOutbound(ctx, joinTestPair(pairId, idleSstpPeer(t).URL))
	coord := &gatedRenewCoordinator{gate: make(chan struct{})}

	dialer := NewSstpDialer(coord, "node-shutdown", nil, joinTestConfig())
	dialer.Bind(fake)
	dialer.RegisterPair(pairId)
	require.Eventually(t, func() bool { return len(coord.opsCopy()) >= 1 }, 3*time.Second, time.Millisecond)

	cancel()
	dialer.Shutdown()
	assert.Equal(t, 1, coord.releases(), "the loop released its lease before Shutdown returned")
}

// After Shutdown no pair loop starts: a RegisterPair that arrives later (a
// stream update racing the shutdown) is refused rather than leaking a loop
// nothing will stop.
func TestSstpDialer_RegisterPairAfterShutdownIsRefused(t *testing.T) {
	const pairId = "pair-after-shutdown"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := newFakeSstpOutbound(ctx, joinTestPair(pairId, idleSstpPeer(t).URL))
	coord := &gatedRenewCoordinator{gate: make(chan struct{})}

	dialer := NewSstpDialer(coord, "node-after-shutdown", nil, joinTestConfig())
	dialer.Bind(fake)
	dialer.Shutdown()
	dialer.RegisterPair(pairId)

	dialer.mu.Lock()
	running := len(dialer.running)
	dialer.mu.Unlock()
	assert.Zero(t, running, "no pair loop starts after Shutdown")
	time.Sleep(50 * time.Millisecond)
	assert.Empty(t, coord.opsCopy(), "nothing acquires a lease after Shutdown")
}
