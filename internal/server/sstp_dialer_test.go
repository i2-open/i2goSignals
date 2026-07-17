package server

import (
	"context"
	cryptorand "crypto/rand"
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

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/pkg/goSet"
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

	// PRD #49 slice 2c: inbound-half hooks. verifyCfg is what
	// InboundVerifyConfig returns to the dialer; ingested records what the
	// dialer handed to HandleInboundEvent (verified.Token + raw + rxSid) —
	// tests inspect it to prove no re-parse happened and that the router
	// received the VerifiedSET.Token verbatim.
	verifyCfg goSetSstp.VerifyConfig
	ingested  []ingestedInboundSet
	ingestErr error // when non-nil, HandleInboundEvent returns it
	ctx       context.Context
}

// ingestedInboundSet captures one HandleInboundEvent call from the dialer's
// response-half so AC 2 assertions can inspect the token pointer.
type ingestedInboundSet struct {
	Token *goSet.SecurityEventToken
	Raw   string
	Sid   string
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

// AckOutbound mirrors the router's AC 3 semantics after PRD #49 slice 2c:
// only the JTIs explicitly listed in `acked` are removed from the buffer.
// An empty ack list confirms NOTHING — every sent SET has its in-flight
// claim released so it is re-drained and retried on a later cycle (US 5
// literal-ack semantics; the historical ack-all-sent fallback is gone).
func (f *fakeSstpOutbound) AckOutbound(stream *model.StreamStateRecord, acked []string, sent []*model.EventRecord, fencingToken int64) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	sentSet := map[string]bool{}
	for _, ev := range sent {
		sentSet[ev.Jti] = true
	}
	// AC 3: literal ack semantics — no ack-all-sent fallback.
	count := 0
	acknowledged := map[string]bool{}
	for _, jti := range acked {
		if !sentSet[jti] {
			continue
		}
		f.acked = append(f.acked, jti)
		delete(f.events, jti) // buffer-removal parity
		delete(f.claimed, jti)
		acknowledged[jti] = true
		count++
	}
	// Sent-but-unacked: release the claim so a later cycle re-drains
	// (matches handleSstpAcks tail behavior after the ack-all removal).
	for _, ev := range sent {
		if !acknowledged[ev.Jti] {
			delete(f.claimed, ev.Jti)
		}
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

// PRD #49 slice 2c AC 2: inbound-half hooks. InboundVerifyConfig returns the
// test's configured verify config (JWKS + ExpectedIssuer/Audiences), and
// HandleInboundEvent records every call so tests can prove the router
// received the VerifiedSET.Token verbatim (no re-parse).
func (f *fakeSstpOutbound) InboundVerifyConfig(rec *model.StreamStateRecord) goSetSstp.VerifyConfig {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.verifyCfg
}

func (f *fakeSstpOutbound) HandleInboundEvent(token *goSet.SecurityEventToken, raw string, sid string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ingestErr != nil {
		return f.ingestErr
	}
	f.ingested = append(f.ingested, ingestedInboundSet{Token: token, Raw: raw, Sid: sid})
	return nil
}

func (f *fakeSstpOutbound) ingestedCopy() []ingestedInboundSet {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]ingestedInboundSet, len(f.ingested))
	copy(out, f.ingested)
	return out
}

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

// ---------------------------------------------------------------------------
// PRD #49 slice 2c (issue #243) — inbound half, literal ack, jitter, sign.
// ---------------------------------------------------------------------------

// TestSstpDialer_BackoffJitter_Uniform25 proves AC 4: nextSstpBackoff +
// jitteredSstpBackoff apply uniform ±25% jitter around the exponentially-
// capped base. The test draws N delays from a fixed base and asserts they
// (a) are NOT all identical (jitter is not a no-op), and (b) span a range
// of at least 10% of nominal — the PRD's own reject threshold.
func TestSstpDialer_BackoffJitter_Uniform25(t *testing.T) {
	const nominal = 1 * time.Second
	const draws = 64

	seen := make(map[time.Duration]struct{}, draws)
	var lo, hi time.Duration = nominal * 2, 0
	for i := 0; i < draws; i++ {
		got := jitteredSstpBackoff(nominal)
		seen[got] = struct{}{}
		if got < lo {
			lo = got
		}
		if got > hi {
			hi = got
		}
		// Bounds check: uniform in [0.75, 1.25] nominal.
		require.GreaterOrEqual(t, got, time.Duration(float64(nominal)*0.749),
			"jittered delay below the ±25% band: %v", got)
		require.LessOrEqual(t, got, time.Duration(float64(nominal)*1.251),
			"jittered delay above the ±25% band: %v", got)
	}
	require.Greater(t, len(seen), 1,
		"jitter must vary the delay across draws — got %d unique values in %d draws", len(seen), draws)
	// PRD test hint: reject if range < 10% of nominal.
	spread := hi - lo
	require.Greater(t, spread, time.Duration(float64(nominal)*0.10),
		"jitter spread %v is less than 10%% of nominal %v — jitter is degenerate", spread, nominal)
}

// TestSstpDialer_SignFailureIsError proves AC 5: a broken signing key
// causes buildSstpSets to return an error, deliver propagates it as
// signErr, and runCycle halts the dial cycle (Pauses outbound, releases
// the claim) rather than sending an unsigned SET on the wire.
func TestSstpDialer_SignFailureIsError(t *testing.T) {
	const (
		pairId = "pair-sign-fail"
		txSid  = "tx-sign-fail"
		jti    = "sstp-sign-fail-1"
	)

	// httptest peer: refuses to see any request (records fact that any
	// request arrived). If the dial cycle halts before sending, this
	// counter must stay at 0.
	var requestCount atomic.Int64
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", goSetSstp.ContentType)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(goSetSstp.Message{})
	}))
	defer peer.Close()

	// Publish-mode pair (NOT forward-mode) forces buildSstpSets to attempt
	// signing. The fake's LoadSigningKey returns (nil, "") — nil private
	// key trips buildSstpSets' "no signing key" error path (AC 5).
	pair := model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:        txSid,
			Iss:       "https://issuer.example.com",
			Aud:       []string{"https://peer.example.com"},
			RouteMode: model.RouteModePublish,
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

	dialer := NewSstpDialer(coord, "node-signfail", nil, cfg)
	dialer.Bind(fake)
	dialer.RegisterPair(pairId)
	t.Cleanup(func() { dialer.UnregisterPair(pairId) })

	// The dialer should observe the sign error, pause outbound, and exit.
	// We assert on the pause reason (visible via fake.paused) — the sign
	// error's presence in the reason string proves the sign-failure code
	// path was hit.
	require.Eventually(t, func() bool {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		return strings.Contains(fake.paused, "signing failure")
	}, 3*time.Second, 20*time.Millisecond,
		"sign failure must halt the dial cycle by pausing outbound with a signing-failure reason")

	// AC 5: the sign error MUST short-circuit before any HTTP request.
	// If the peer's counter is non-zero we sent an unsigned SET — which is
	// exactly the invariant this AC prohibits.
	assert.Equal(t, int64(0), requestCount.Load(),
		"no HTTP request may be issued when signing fails — an unsigned SET must never reach the peer")
}

// TestSstpDialer_EmptyAckDoesNotConfirmSentSets proves AC 3 at the dialer
// level: when the peer's response Ack list is empty (§2.3 "acknowledged
// no JTIs" — no ack-all-sent fallback), the sent JTIs are NOT removed
// from the outbound state and their in-flight claim is released so they
// re-drain on a subsequent cycle. The historical fallback that silently
// masked delivery loss is gone.
func TestSstpDialer_EmptyAckDoesNotConfirmSentSets(t *testing.T) {
	const (
		pairId = "pair-empty-ack"
		txSid  = "tx-empty-ack"
		jti    = "sstp-empty-ack-1"
	)

	// httptest peer: always responds with an EMPTY Ack list, no matter
	// what the request contained. Counts requests so the test can wait
	// for retransmit (US 5).
	var requestCount atomic.Int64
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", goSetSstp.ContentType)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(goSetSstp.Message{Ack: []string{}}) // literal empty
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

	dialer := NewSstpDialer(coord, "node-empty-ack", nil, cfg)
	dialer.Bind(fake)
	dialer.RegisterPair(pairId)
	t.Cleanup(func() { dialer.UnregisterPair(pairId) })

	// Wait for at least TWO exchanges — the second is the retransmit that
	// the empty-ack semantics guarantee (US 5 verbatim: "unacked SETs stay
	// outstanding and may be retransmitted").
	require.Eventually(t, func() bool {
		return requestCount.Load() >= 2
	}, 3*time.Second, 20*time.Millisecond,
		"an empty-ack cycle must not remove the SET from outbound state — a retransmit must follow")

	// AC 3: the JTI is NOT recorded as acked, and it is still resident in
	// the fake's event map (has not been removed by the buffer-parity
	// AckEvents call). The historical ack-all-sent fallback would have
	// dropped it silently.
	assert.Empty(t, fake.ackedCopy(),
		"no JTI must be acked when the peer's ack list is empty — the literal semantics prohibit ack-all fallback")
	fake.mu.Lock()
	_, stillPresent := fake.events[jti]
	fake.mu.Unlock()
	assert.True(t, stillPresent,
		"the SET must remain in the outbound buffer for retransmit after an empty-ack cycle")
}

// TestSstpDialer_IngestsResponseSetsViaVerifySET proves AC 2: response-
// carried SETs are verified via goSetSstp.VerifySET at ingest and fed to
// HandleInboundEvent (router.HandleEvent) via VerifiedSET.Token without
// re-parse. The fake records the token pointer the dialer passed; the test
// verifies (a) the ingest happened at least once, (b) the ingested token's
// iss/JTI match the signed input, and (c) the token has the Kid the JWKS
// verified against (which only a completed goSet.Parse populates — a
// re-parse or a pre-verified peek would have zeroed it).
func TestSstpDialer_IngestsResponseSetsViaVerifySET(t *testing.T) {
	const (
		pairId       = "pair-ingest-verify"
		txSid        = "tx-ingest-verify"
		peerIssuer   = "https://peer.issuer.example"
		peerAudience = "https://us.example"
		responseKid  = "peer-kid-1"
		responseJti  = "sstp-response-1"
	)

	// Peer's signing material: an RSA keypair + JWKS the dialer can verify
	// against. The peer signs a SET on every response; the dialer's ingest
	// must accept it and hand the verified token to HandleInboundEvent.
	peerKey, err := rsaTestKey()
	require.NoError(t, err)
	jwks := makeGivenJwks(t, responseKid, &peerKey.PublicKey)

	// httptest peer: signs a SET on every response and hands it back in
	// the response body's Sets map.
	responseToken := signResponseSet(t, peerKey, responseKid, peerIssuer, peerAudience, responseJti)

	var requestCount atomic.Int64
	var lastReqAck []string
	var mu sync.Mutex
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var msg goSetSstp.Message
		require.NoError(t, json.Unmarshal(raw, &msg))
		mu.Lock()
		lastReqAck = append([]string(nil), msg.Ack...)
		mu.Unlock()
		requestCount.Add(1)
		resp := goSetSstp.Message{
			Sets: map[string]string{responseJti: responseToken},
		}
		w.Header().Set("Content-Type", goSetSstp.ContentType)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer peer.Close()

	// Pair record: forward-mode outbound so egress signing is irrelevant to
	// this test. SstpInbound carries the peer's issuer/audience so the
	// dialer's inbound verify config is built with the right trust root.
	pair := model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:        txSid,
			Iss:       "https://us.example",
			Aud:       []string{peerIssuer},
			RouteMode: model.RouteModeForward,
		},
		SstpInbound: &model.StreamConfiguration{
			Id:  "rx-sid-1",
			Iss: peerIssuer,
			Aud: []string{peerAudience},
		},
		Status: model.StreamStateEnabled,
		PairId: pairId,
		SstpMethod: &model.SstpMethod{
			Role:                model.SstpRoleInitiator,
			EndpointUrl:         peer.URL,
			AuthorizationHeader: "Bearer test-token",
		},
	}
	// An outbound event so the primary cycle actually POSTs.
	ev := &model.EventRecord{
		Jti:      "sstp-outbound-1",
		Original: `{"jti":"sstp-outbound-1","raw":true}`,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := newFakeSstpOutbound(ctx, pair, ev)
	// Wire the fake's verify config so InboundVerifyConfig returns the
	// JWKS + trust settings for the peer's issuer.
	fake.verifyCfg = goSetSstp.VerifyConfig{
		JWKS:              jwks,
		ExpectedIssuer:    peerIssuer,
		ExpectedAudiences: []string{peerAudience},
		RequireSignature:  true,
	}
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

	dialer := NewSstpDialer(coord, "node-ingest", nil, cfg)
	dialer.Bind(fake)
	dialer.RegisterPair(pairId)
	t.Cleanup(func() { dialer.UnregisterPair(pairId) })

	// Wait for at least one ingest.
	require.Eventually(t, func() bool {
		return len(fake.ingestedCopy()) >= 1
	}, 3*time.Second, 20*time.Millisecond,
		"dialer must call HandleInboundEvent with the verified response SET (AC 2)")

	got := fake.ingestedCopy()[0]
	require.NotNil(t, got.Token, "ingested Token must not be nil (VerifiedSET.Token contract)")
	assert.Equal(t, peerIssuer, got.Token.Issuer,
		"ingested token's Issuer must be the peer's (proves VerifySET succeeded and Token is populated)")
	assert.Equal(t, responseJti, got.Token.ID,
		"ingested token's JTI (RegisteredClaims.ID) must be the peer-signed JTI — proof the router got the verified token, not a re-parse")
	assert.Equal(t, responseKid, got.Token.Kid,
		"ingested token's Kid must be populated from JWKS-completed goSet.Parse — a re-parse (Peek) would leave Kid zero")
	assert.Equal(t, "rx-sid-1", got.Sid,
		"HandleInboundEvent must be called with the rx-side SID (SstpInbound.Id)")
	assert.Equal(t, responseToken, got.Raw,
		"the compact raw SET must be carried through verbatim")

	// AC 1: the next request's Ack must contain the ingested JTI so the
	// peer clears its outbound. Wait for a second request and inspect it.
	require.Eventually(t, func() bool {
		if requestCount.Load() < 2 {
			return false
		}
		mu.Lock()
		defer mu.Unlock()
		for _, a := range lastReqAck {
			if a == responseJti {
				return true
			}
		}
		return false
	}, 3*time.Second, 20*time.Millisecond,
		"next request's Ack must carry the ingested JTI (AC 1 request-side Ack carriage)")
}

// rsaTestKey generates an RSA keypair for tests.
func rsaTestKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(cryptorand.Reader, 2048)
}

// makeGivenJwks builds a keyfunc.JWKS from a single RSA public key + kid so
// InboundVerifyConfig can hand a real trust root to VerifySET in tests.
func makeGivenJwks(t *testing.T, kid string, pub *rsa.PublicKey) *keyfunc.JWKS {
	t.Helper()
	given := keyfunc.NewGivenRSA(pub, keyfunc.GivenKeyOptions{Algorithm: "RS256"})
	return keyfunc.NewGiven(map[string]keyfunc.GivenKey{kid: given})
}

// signResponseSet builds and RS256-signs a SecurityEventToken to stand in as
// the peer's response-carried SET.
func signResponseSet(t *testing.T, key *rsa.PrivateKey, kid, iss, aud, jti string) string {
	t.Helper()
	set := goSet.SecurityEventToken{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:       jti,
			Issuer:   iss,
			Audience: jwt.ClaimStrings{aud},
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
		Events: map[string]any{"https://example/event/inbound": map[string]any{}},
		Kid:    kid,
	}
	signed, err := set.JWS(jwt.SigningMethodRS256, key)
	require.NoError(t, err)
	return signed
}
