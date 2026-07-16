package server

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// PRD #49 slice 2a — dialer-relocation tests.
//
// This file carries the two required behavioral pins for the relocated
// SSTP dialer:
//
//  1. TestSstpDialer_ProductionWiring_LivesInServer (AC 3) — the production
//     server boot path in internal/server registers/starts the SSTP dialer
//     loop; internal/eventRouter no longer starts any SSTP dialer goroutine.
//     Verified by asserting that (a) eventRouter.RouterDeps exposes
//     SstpDialerHooks as the server-implemented seam, (b) SstpDialer — the
//     loop's owner — is defined in the internal/server package, and (c)
//     SstpDialer implements eventRouter.SstpDialerHooks. A resurrected
//     router-owned dialer would fail (b) at compile time.
//
//  2. TestSstpDialer_BasicDialAndAck (AC 5a) — a live httptest.NewServer
//     responding with goSetSstp.Message shapes proves the relocated loop
//     dials the peer, sends the SET, receives an ack response, and updates
//     outbound state via the narrow router surface. Parity / tracer with
//     the pre-relocation coverage. Full behavioral coverage of ingest
//     paths, retransmit, and credential selection is the explicit
//     responsibility of slices 2b/2c.

// ---------------------------------------------------------------------------
// AC 3: production-wiring pin
// ---------------------------------------------------------------------------

// TestSstpDialer_ProductionWiring_LivesInServer proves AC 3 verbatim.
func TestSstpDialer_ProductionWiring_LivesInServer(t *testing.T) {
	// (a) RouterDeps exposes SstpDialerHooks: the seam is a public field on
	// the router's deps, so the composition root must fill it in — the
	// router cannot self-construct one.
	depsType := reflect.TypeOf(eventRouter.RouterDeps{})
	hookField, ok := depsType.FieldByName("SstpDialerHooks")
	require.True(t, ok, "eventRouter.RouterDeps must expose SstpDialerHooks — the seam the server fills in")
	hookIfaceType := reflect.TypeOf((*eventRouter.SstpDialerHooks)(nil)).Elem()
	require.Equal(t, hookIfaceType, hookField.Type,
		"RouterDeps.SstpDialerHooks must be typed as eventRouter.SstpDialerHooks")

	// (b) SstpDialer — the loop's owner — is defined in internal/server.
	dialerType := reflect.TypeOf(SstpDialer{})
	require.True(t, strings.HasSuffix(dialerType.PkgPath(), "/internal/server"),
		"SstpDialer (the SSTP dialer loop owner) must live in internal/server, got %q", dialerType.PkgPath())

	// (c) SstpDialer implements eventRouter.SstpDialerHooks — the hook the
	// router calls to register/unregister pairs. Compile-time assertion.
	var _ eventRouter.SstpDialerHooks = (*SstpDialer)(nil)
}

// ---------------------------------------------------------------------------
// AC 5a: basic dial-and-ack cycle
// ---------------------------------------------------------------------------

// fakeSstpOutbound is a hand-rolled test double of eventRouter.SstpOutbound.
// It records what the dialer asks for and returns test-controlled data,
// without spinning up a full router — the router-side behavior of the
// surface is covered by the router package's own tests (sstp_outbound.go
// facades over pre-existing router helpers). The dialer's responsibility
// exercised here is: does it drive the loop through the facade correctly,
// dial the peer, and process the ack.
type fakeSstpOutbound struct {
	mu sync.Mutex

	pair    model.StreamStateRecord
	present bool

	events  map[string]*model.EventRecord
	claimed map[string]bool

	wake chan struct{}

	acked    []string
	released []string
	paused   string

	ctx context.Context
}

func newFakeSstpOutbound(ctx context.Context, pair model.StreamStateRecord, evs ...*model.EventRecord) *fakeSstpOutbound {
	f := &fakeSstpOutbound{
		pair:    pair,
		present: true,
		events:  map[string]*model.EventRecord{},
		claimed: map[string]bool{},
		wake:    make(chan struct{}, 1),
		ctx:     ctx,
	}
	for _, ev := range evs {
		f.events[ev.Jti] = ev
	}
	return f
}

func (f *fakeSstpOutbound) WakeCh(pairId string) <-chan struct{} { return f.wake }

func (f *fakeSstpOutbound) RefreshPair(pairId string) (model.StreamStateRecord, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pair, f.present
}

func (f *fakeSstpOutbound) ClaimOutbound(pairId string, max int) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0)
	for jti := range f.events {
		if f.claimed[jti] {
			continue
		}
		f.claimed[jti] = true
		out = append(out, jti)
		if len(out) >= max {
			break
		}
	}
	return out
}

func (f *fakeSstpOutbound) ResolveEvents(pairId string, claimed []string) []*model.EventRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*model.EventRecord, 0, len(claimed))
	for _, jti := range claimed {
		if ev, ok := f.events[jti]; ok {
			out = append(out, ev)
		}
	}
	return out
}

func (f *fakeSstpOutbound) AckOutbound(stream *model.StreamStateRecord, acked []string, sent []*model.EventRecord, fencingToken int64) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	sentSet := map[string]bool{}
	for _, ev := range sent {
		sentSet[ev.Jti] = true
	}
	effective := acked
	if len(effective) == 0 {
		effective = make([]string, 0, len(sent))
		for _, ev := range sent {
			effective = append(effective, ev.Jti)
		}
	}
	count := 0
	for _, jti := range effective {
		if !sentSet[jti] {
			continue
		}
		f.acked = append(f.acked, jti)
		delete(f.events, jti) // buffer-removal parity
		delete(f.claimed, jti)
		count++
	}
	return count
}

func (f *fakeSstpOutbound) ReleaseOutbound(pairId string, events []*model.EventRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ev := range events {
		f.released = append(f.released, ev.Jti)
		delete(f.claimed, ev.Jti)
	}
}

func (f *fakeSstpOutbound) ReleaseJtis(pairId string, jtis []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, jti := range jtis {
		f.released = append(f.released, jti)
		delete(f.claimed, jti)
	}
}

func (f *fakeSstpOutbound) PauseOutbound(stream *model.StreamStateRecord, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paused = reason
	f.pair.Status = model.StreamStatePause
}

func (f *fakeSstpOutbound) LoadSigningKey(streamID, issuer string) (*rsa.PrivateKey, string) {
	// Unused in the forward-mode dial-and-ack test.
	return nil, ""
}

func (f *fakeSstpOutbound) AcquireSecondPushSlot(pairId string) bool { return true }
func (f *fakeSstpOutbound) ReleaseSecondPushSlot(pairId string)      {}
func (f *fakeSstpOutbound) BackfillBatch() int                       { return 100 }
func (f *fakeSstpOutbound) Ctx() context.Context                     { return f.ctx }

var _ eventRouter.SstpOutbound = (*fakeSstpOutbound)(nil)

func (f *fakeSstpOutbound) ackedCopy() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.acked))
	copy(out, f.acked)
	return out
}

// ---------------------------------------------------------------------------
// Fake coordinator: always grants the lease. Records release calls.
// ---------------------------------------------------------------------------

type oneShotCoordinator struct {
	mu       sync.Mutex
	acquired atomic.Bool
	releases atomic.Int64
	fencing  int64
}

func (c *oneShotCoordinator) TryAcquireOrRenewLease(resource, nodeId string, d time.Duration) (bool, int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.acquired.Store(true)
	c.fencing++
	return true, c.fencing, nil
}

func (c *oneShotCoordinator) ReleaseLeaseIfOwned(resource, nodeId string) error {
	c.releases.Add(1)
	return nil
}

func (c *oneShotCoordinator) GetLeaseOwner(resource string) (string, time.Time, int64, error) {
	return "", time.Time{}, 0, nil
}

func (c *oneShotCoordinator) RegisterNode(node model.ClusterNode) error    { return nil }
func (c *oneShotCoordinator) GetActiveNodeCount() (int64, error)           { return 1, nil }
func (c *oneShotCoordinator) GetActiveNodes() ([]model.ClusterNode, error) { return nil, nil }
func (c *oneShotCoordinator) GetNode(nodeId string) (*model.ClusterNode, error) {
	return &model.ClusterNode{Id: nodeId}, nil
}

var _ cluster.ClusterCoordinator = (*oneShotCoordinator)(nil)

// TestSstpDialer_BasicDialAndAck: the dial-and-ack tracer (AC 5a).
func TestSstpDialer_BasicDialAndAck(t *testing.T) {
	const (
		pairId = "pair-dial-ack"
		txSid  = "tx-dial-ack"
		jti    = "sstp-dial-1"
	)

	// httptest peer: accepts the POST, decodes the request body, echoes an
	// ack for every JTI it saw. This is the wire shape the relocated
	// dialer's Exchange call produces.
	var (
		mu           sync.Mutex
		requestCount int
		lastBody     goSetSstp.Message
	)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "expected POST", http.StatusMethodNotAllowed)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var msg goSetSstp.Message
		require.NoError(t, json.Unmarshal(raw, &msg), "peer must receive a well-formed SSTP request body")
		mu.Lock()
		requestCount++
		lastBody = msg
		acks := make([]string, 0, len(msg.Sets))
		for j := range msg.Sets {
			acks = append(acks, j)
		}
		mu.Unlock()
		resp := goSetSstp.Message{Ack: acks}
		w.Header().Set("Content-Type", goSetSstp.ContentType)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer peer.Close()

	pair := model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:        txSid,
			Iss:       "https://issuer.example.com",
			Aud:       []string{"https://peer.example.com"},
			RouteMode: model.RouteModeForward,
		},
		Status: model.StreamStateEnabled,
		PairId: pairId,
		SstpMethod: &model.SstpMethod{
			Role:                model.SstpRoleInitiator,
			EndpointUrl:         peer.URL,
			AuthorizationHeader: "Bearer test-token",
		},
	}
	ev := &model.EventRecord{
		Jti:      jti,
		Original: `{"jti":"` + jti + `","raw":true}`,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := newFakeSstpOutbound(ctx, pair, ev)
	coord := &oneShotCoordinator{}

	cfg := SstpDialerConfig{
		BaseDelay:           5 * time.Millisecond,
		MaxDelay:            50 * time.Millisecond,
		BackoffFactor:       2.0,
		LeaseDuration:       500 * time.Millisecond,
		HeartbeatInterval:   200 * time.Millisecond,
		HeartbeatRetryDelay: 10 * time.Millisecond,
		Jitter:              func() time.Duration { return 0 },
		HTTPClient:          &http.Client{Timeout: 2 * time.Second},
		BackfillBatch:       10,
	}

	dialer := NewSstpDialer(coord, "node-test", nil, cfg)
	dialer.Bind(fake)
	dialer.RegisterPair(pairId)
	t.Cleanup(func() { dialer.UnregisterPair(pairId) })

	require.Eventually(t, func() bool {
		mu.Lock()
		rc := requestCount
		mu.Unlock()
		return rc >= 1 && len(fake.ackedCopy()) >= 1
	}, 3*time.Second, 20*time.Millisecond,
		"dialer must dial the peer and process the ack via the narrow outbound surface")

	mu.Lock()
	require.Contains(t, lastBody.Sets, jti,
		"the relocated dialer must POST the outbound SET verbatim to the peer (RouteModeForward)")
	mu.Unlock()

	assert.Contains(t, fake.ackedCopy(), jti,
		"the narrow outbound surface must record the peer's ack via AckOutbound")

	assert.True(t, coord.acquired.Load(),
		"dialer must acquire the sstp-client:<PairId> lease via cluster.Coordinator")
}

// ---------------------------------------------------------------------------
// AC 2 (PRD 49 slice 2b, issue #242): the dialer routes each SSTP cycle
// through the credential-chain resolver so PeerServerAlias-configured
// transport posture applies and the per-pair bearer wins Authorization.
// ---------------------------------------------------------------------------

// TestSstpDialer_UsesResolveClientForCredentialChain proves the dialer
// consults cfg.ResolveClient on every cycle rather than reaching into
// SstpMethod.AuthorizationHeader / cfg.HTTPClient directly. This is the
// wiring seam AC 2 requires: the SSTP dialer + push delivery share ONE
// resolver (sa.ResolveTransmitterClient in production), so a rotated
// per-pair bearer / PeerServerAlias TLS posture is picked up automatically.
//
// Assertion strategy: wire a stub ResolveClient that returns a
// distinctive Authorization header and record its invocation. The stub's
// header must land on the peer's inbound request — proving deliver()
// preferred the resolver's output over the raw SstpMethod bearer.
func TestSstpDialer_UsesResolveClientForCredentialChain(t *testing.T) {
	const (
		pairId = "pair-resolver-wired"
		txSid  = "tx-resolver-wired"
		jti    = "sstp-resolver-1"
	)

	var (
		mu           sync.Mutex
		gotAuth      string
		requestCount int
	)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		requestCount++
		mu.Unlock()
		raw, _ := io.ReadAll(r.Body)
		var msg goSetSstp.Message
		require.NoError(t, json.Unmarshal(raw, &msg))
		acks := make([]string, 0, len(msg.Sets))
		for j := range msg.Sets {
			acks = append(acks, j)
		}
		w.Header().Set("Content-Type", goSetSstp.ContentType)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(goSetSstp.Message{Ack: acks})
	}))
	defer peer.Close()

	pair := model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:        txSid,
			Iss:       "https://issuer.example.com",
			Aud:       []string{"https://peer.example.com"},
			RouteMode: model.RouteModeForward,
		},
		Status: model.StreamStateEnabled,
		PairId: pairId,
		SstpMethod: &model.SstpMethod{
			Role:                model.SstpRoleInitiator,
			EndpointUrl:         peer.URL,
			AuthorizationHeader: "Bearer STALE-inline-bearer",
			// PeerServerAlias would drive TLS posture in production;
			// the stub resolver stands in for it here.
			PeerServerAlias: "stub-peer-alias",
		},
	}
	ev := &model.EventRecord{Jti: jti, Original: `{"jti":"` + jti + `","raw":true}`}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := newFakeSstpOutbound(ctx, pair, ev)
	coord := &oneShotCoordinator{}

	var resolverInvocations atomic.Int64
	cfg := SstpDialerConfig{
		BaseDelay:           5 * time.Millisecond,
		MaxDelay:            50 * time.Millisecond,
		BackoffFactor:       2.0,
		LeaseDuration:       500 * time.Millisecond,
		HeartbeatInterval:   200 * time.Millisecond,
		HeartbeatRetryDelay: 10 * time.Millisecond,
		Jitter:              func() time.Duration { return 0 },
		HTTPClient:          &http.Client{Timeout: 2 * time.Second},
		BackfillBatch:       10,
		ResolveClient: func(ctx context.Context, s *model.StreamStateRecord) (*http.Client, string, func(), error) {
			resolverInvocations.Add(1)
			require.Equal(t, pairId, s.PairId,
				"resolver must receive the live stream record for this pair")
			// The resolver is authoritative — it can return an
			// Authorization value different from the raw SstpMethod bearer
			// (e.g. after a bearer rotation). The dialer must use THIS.
			return &http.Client{Timeout: 2 * time.Second}, "Bearer FRESH-from-resolver", func() {}, nil
		},
	}

	dialer := NewSstpDialer(coord, "node-resolver-test", nil, cfg)
	dialer.Bind(fake)
	dialer.RegisterPair(pairId)
	t.Cleanup(func() { dialer.UnregisterPair(pairId) })

	require.Eventually(t, func() bool {
		mu.Lock()
		rc := requestCount
		mu.Unlock()
		return rc >= 1
	}, 3*time.Second, 20*time.Millisecond,
		"dialer must dial the peer at least once")

	mu.Lock()
	auth := gotAuth
	mu.Unlock()

	assert.Equal(t, "Bearer FRESH-from-resolver", auth,
		"deliver() must use the resolver's Authorization header, not the raw SstpMethod bearer (AC 2 wiring)")
	assert.Greater(t, resolverInvocations.Load(), int64(0),
		"deliver() must call cfg.ResolveClient on each cycle (AC 2)")
}

// TestSstpDialer_FallsBackToInlineClientWhenResolverErrors proves the
// safety net: a resolver failure must not stop the dialer — it falls back
// to cfg.HTTPClient + the raw SstpMethod.AuthorizationHeader so a mis-
// configured resolver cannot silently blackhole outbound SSTP traffic.
func TestSstpDialer_FallsBackToInlineClientWhenResolverErrors(t *testing.T) {
	const (
		pairId = "pair-resolver-error"
		txSid  = "tx-resolver-error"
		jti    = "sstp-resolver-err-1"
	)

	var (
		mu      sync.Mutex
		gotAuth string
	)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		mu.Unlock()
		raw, _ := io.ReadAll(r.Body)
		var msg goSetSstp.Message
		_ = json.Unmarshal(raw, &msg)
		acks := make([]string, 0, len(msg.Sets))
		for j := range msg.Sets {
			acks = append(acks, j)
		}
		w.Header().Set("Content-Type", goSetSstp.ContentType)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(goSetSstp.Message{Ack: acks})
	}))
	defer peer.Close()

	pair := model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:        txSid,
			Iss:       "https://issuer.example.com",
			Aud:       []string{"https://peer.example.com"},
			RouteMode: model.RouteModeForward,
		},
		Status: model.StreamStateEnabled,
		PairId: pairId,
		SstpMethod: &model.SstpMethod{
			Role:                model.SstpRoleInitiator,
			EndpointUrl:         peer.URL,
			AuthorizationHeader: "Bearer inline-fallback",
		},
	}
	ev := &model.EventRecord{Jti: jti, Original: `{"jti":"` + jti + `","raw":true}`}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := newFakeSstpOutbound(ctx, pair, ev)
	coord := &oneShotCoordinator{}

	cfg := SstpDialerConfig{
		BaseDelay:           5 * time.Millisecond,
		MaxDelay:            50 * time.Millisecond,
		BackoffFactor:       2.0,
		LeaseDuration:       500 * time.Millisecond,
		HeartbeatInterval:   200 * time.Millisecond,
		HeartbeatRetryDelay: 10 * time.Millisecond,
		Jitter:              func() time.Duration { return 0 },
		HTTPClient:          &http.Client{Timeout: 2 * time.Second},
		BackfillBatch:       10,
		ResolveClient: func(ctx context.Context, s *model.StreamStateRecord) (*http.Client, string, func(), error) {
			return nil, "", nil, assert.AnError
		},
	}

	dialer := NewSstpDialer(coord, "node-fallback", nil, cfg)
	dialer.Bind(fake)
	dialer.RegisterPair(pairId)
	t.Cleanup(func() { dialer.UnregisterPair(pairId) })

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return gotAuth != ""
	}, 3*time.Second, 20*time.Millisecond,
		"dialer must fall through to the inline HTTPClient when the resolver errors")

	mu.Lock()
	auth := gotAuth
	mu.Unlock()
	assert.Equal(t, "Bearer inline-fallback", auth,
		"resolver error must fall back to SstpMethod.AuthorizationHeader + cfg.HTTPClient — never black-hole traffic")
}
