package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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

// A peer may ship queued outbound SETs on ANY 200, including the response to a
// returnEvents=false second push. runSecondPush ingests those, but it runs
// in its own goroutine while the pair loop holds its pending feedback as a value
// it cannot touch — so the feedback used to be computed and thrown away. The
// peer therefore never learned we had taken the SETs, its outbound never cleared
// them, and it resent them every cycle forever: exactly the infinite-resend loop
// the setErr/ack carriage exists to break (code-review finding on spec #247).
func TestPushWhilePollHeld_DefersInboundFeedbackForTheNextRequest(t *testing.T) {
	const (
		pairId       = "pair-second-push-feedback"
		txSid        = "tx-second-push-feedback"
		peerIssuer   = "https://peer.issuer.example"
		peerAudience = "https://us.example"
		responseKid  = "peer-kid-second-push"
		responseJti  = "sstp-second-push-response-1"
	)

	peerKey, err := rsaTestKey()
	require.NoError(t, err)
	jwks := makeGivenJwks(t, responseKid, &peerKey.PublicKey)
	responseToken := signResponseSet(t, peerKey, responseKid, peerIssuer, peerAudience, responseJti)

	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var msg goSetSstp.Message
		require.NoError(t, json.Unmarshal(raw, &msg))
		// The second push declines long-polling but the peer answers with a
		// queued SET anyway — permitted by §2.1 and the case this test pins.
		resp := goSetSstp.Message{
			Ack:  []string{"sstp-outbound-second-push"},
			Sets: map[string]string{responseJti: responseToken},
		}
		w.Header().Set("Content-Type", goSetSstp.ContentType)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer peer.Close()

	pair := model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:               txSid,
			Iss:              "https://us.example",
			Aud:              []string{peerIssuer},
			RouteMode:        model.RouteModeForward,
			TxAllowPlaintext: true, // loopback httptest peer (#322)
		},
		SstpInbound: &model.StreamConfiguration{
			Id:  "rx-sid-second-push",
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
	ev := &model.EventRecord{
		Jti:      "sstp-outbound-second-push",
		Original: `{"jti":"sstp-outbound-second-push","raw":true}`,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := newFakeSstpOutbound(ctx, pair, ev)
	fake.verifyCfg = goSetSstp.VerifyConfig{
		JWKS:              jwks,
		ExpectedIssuer:    peerIssuer,
		ExpectedAudiences: []string{peerAudience},
		RequireSignature:  true,
	}

	dialer := NewSstpDialer(&oneShotCoordinator{}, "node-second-push", nil, SstpDialerConfig{
		BaseDelay:     5 * time.Millisecond,
		MaxDelay:      50 * time.Millisecond,
		BackoffFactor: 2.0,
		Jitter:        func() time.Duration { return 0 },
		HTTPClient:    &http.Client{Timeout: 2 * time.Second},
		BackfillBatch: 10,
	})
	dialer.Bind(fake)

	// Drive the second push directly: the wake-driven spawn is the pair loop's
	// concern, and this is the goroutine whose feedback was being dropped.
	cls, _ := dialer.runSecondPush(ctx, &pair, 1)
	require.Equal(t, goSetSstp.ClassOK, cls.Class)

	require.Len(t, fake.ingestedCopy(), 1, "the response SET must still be ingested")

	deferred := dialer.takeDeferredFeedback(pairId)
	assert.Equal(t, []string{responseJti}, deferred.Acks,
		"the second push's ack must be deferred for the pair loop's next request")

	assert.True(t, dialer.takeDeferredFeedback(pairId).empty(),
		"taking the deferred feedback must hand it over exactly once")
}

// TestPushWhilePollHeld_DrainsUntilOutboundEmpty pins the drain loop: with a
// batch size of one and three queued SETs, one second push must POST three
// times and clear all three, rather than sending one batch and leaving the
// rest stranded until the primary long-poll returns.
func TestPushWhilePollHeld_DrainsUntilOutboundEmpty(t *testing.T) {
	const (
		pairId = "pair-second-push-drain"
		txSid  = "tx-second-push-drain"
	)

	var requestCount atomic.Int64
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var msg goSetSstp.Message
		require.NoError(t, json.Unmarshal(raw, &msg))
		require.Len(t, msg.Sets, 1, "BackfillBatch=1 must cap each second-push request at one SET")
		requestCount.Add(1)
		acks := make([]string, 0, 1)
		for jti := range msg.Sets {
			acks = append(acks, jti)
		}
		w.Header().Set("Content-Type", goSetSstp.ContentType)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(goSetSstp.Message{Ack: acks})
	}))
	defer peer.Close()

	pair := model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:               txSid,
			Iss:              "https://us.example",
			Aud:              []string{"https://peer.example"},
			RouteMode:        model.RouteModeForward,
			TxAllowPlaintext: true, // loopback httptest peer (#322)
		},
		Status: model.StreamStateEnabled,
		PairId: pairId,
		SstpMethod: &model.SstpMethod{
			Role:                model.SstpRoleInitiator,
			EndpointUrl:         peer.URL,
			AuthorizationHeader: "Bearer test-token",
		},
	}
	evs := make([]*model.EventRecord, 0, 3)
	for i := 1; i <= 3; i++ {
		jti := fmt.Sprintf("sstp-drain-%d", i)
		evs = append(evs, &model.EventRecord{Jti: jti, Original: `{"jti":"` + jti + `","raw":true}`})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := newFakeSstpOutbound(ctx, pair, evs...)

	dialer := NewSstpDialer(&oneShotCoordinator{}, "node-second-push-drain", nil, SstpDialerConfig{
		BaseDelay:     5 * time.Millisecond,
		MaxDelay:      50 * time.Millisecond,
		BackoffFactor: 2.0,
		Jitter:        func() time.Duration { return 0 },
		HTTPClient:    &http.Client{Timeout: 2 * time.Second},
		BackfillBatch: 1,
	})
	dialer.Bind(fake)

	cls, _ := dialer.runSecondPush(ctx, &pair, 1)
	require.Equal(t, goSetSstp.ClassOK, cls.Class)

	assert.Equal(t, int64(3), requestCount.Load(),
		"the second push must keep POSTing until the outbound buffer is empty")
	assert.ElementsMatch(t, []string{"sstp-drain-1", "sstp-drain-2", "sstp-drain-3"}, fake.ackedCopy(),
		"every queued SET must be acked by the drain loop")
	assert.Empty(t, fake.ClaimOutbound(pairId, 10),
		"nothing may be left unclaimed once the drain loop returns")
}

// The store must survive several second pushes before the pair loop drains it,
// and must not accumulate duplicates.
func TestDeferredFeedback_AccumulatesUntilTaken(t *testing.T) {
	d := NewSstpDialer(&oneShotCoordinator{}, "node-defer", nil, SstpDialerConfig{})

	d.deferFeedback("pair-a", sstpPendingFeedback{Acks: []string{"jti-1"}})
	d.deferFeedback("pair-a", sstpPendingFeedback{Acks: []string{"jti-1", "jti-2"}})
	d.deferFeedback("pair-a", sstpPendingFeedback{
		SetErrs: map[string]goSetSstp.SetErr{"jti-3": {Err: goSetSstp.ErrCodeInvalidRequest}},
	})
	d.deferFeedback("pair-b", sstpPendingFeedback{Acks: []string{"other-pair"}})

	got := d.takeDeferredFeedback("pair-a")
	assert.Equal(t, []string{"jti-1", "jti-2"}, got.Acks, "a repeated ack must not be carried twice")
	assert.Len(t, got.SetErrs, 1)
	assert.Contains(t, got.SetErrs, "jti-3")

	assert.Equal(t, []string{"other-pair"}, d.takeDeferredFeedback("pair-b").Acks,
		"the store is per-pair")
}

// Empty feedback must not create an entry — the common case is a second push
// whose response carried no SETs at all.
func TestDeferredFeedback_EmptyIsNotStored(t *testing.T) {
	d := NewSstpDialer(&oneShotCoordinator{}, "node-defer-empty", nil, SstpDialerConfig{})

	d.deferFeedback("pair-a", sstpPendingFeedback{})

	d.deferredMu.Lock()
	defer d.deferredMu.Unlock()
	assert.Empty(t, d.deferred, "empty feedback must not allocate a per-pair entry")
}

// A removed pair's feedback has nobody left to carry it and must not leak.
func TestDeferredFeedback_DroppedOnUnregister(t *testing.T) {
	d := NewSstpDialer(&oneShotCoordinator{}, "node-defer-drop", nil, SstpDialerConfig{})

	d.deferFeedback("pair-gone", sstpPendingFeedback{Acks: []string{"jti-1"}})
	d.UnregisterPair("pair-gone")

	assert.True(t, d.takeDeferredFeedback("pair-gone").empty(),
		"UnregisterPair must drop the pair's deferred feedback")
}

// merge is what folds the deferred value into the loop's carried one; acks
// de-duplicate and setErrs union.
func TestPendingFeedback_Merge(t *testing.T) {
	carried := sstpPendingFeedback{
		Acks:    []string{"jti-1", "jti-2"},
		SetErrs: map[string]goSetSstp.SetErr{"jti-bad": {Err: goSetSstp.ErrCodeInvalidRequest}},
	}

	carried.merge(sstpPendingFeedback{
		Acks:    []string{"jti-2", "jti-3"},
		SetErrs: map[string]goSetSstp.SetErr{"jti-worse": {Err: goSetSstp.ErrSetParse}},
	})

	assert.Equal(t, []string{"jti-1", "jti-2", "jti-3"}, carried.Acks,
		"acks must de-duplicate and keep order")
	assert.Len(t, carried.SetErrs, 2)
	assert.Contains(t, carried.SetErrs, "jti-bad")
	assert.Contains(t, carried.SetErrs, "jti-worse")
}

// Merging into a zero value must allocate rather than panic on the nil map.
func TestPendingFeedback_MergeIntoZeroValue(t *testing.T) {
	var carried sstpPendingFeedback

	carried.merge(sstpPendingFeedback{
		Acks:    []string{"jti-1"},
		SetErrs: map[string]goSetSstp.SetErr{"jti-bad": {Err: goSetSstp.ErrCodeInvalidRequest}},
	})

	assert.Equal(t, []string{"jti-1"}, carried.Acks)
	assert.Contains(t, carried.SetErrs, "jti-bad")
	assert.False(t, carried.empty())
}

// secondPushKPeer is a loopback SSTP peer that holds every request until
// release is closed, records the peak number of requests open at once, checks
// the Q7.2 wire shape of each (returnEvents=false, no Ack), and acks what it
// was sent.
type secondPushKPeer struct {
	srv      *httptest.Server
	release  chan struct{}
	open     atomic.Int64
	peak     atomic.Int64
	requests atomic.Int64
	mu       sync.Mutex
	seen     map[string]int
}

func newSecondPushKPeer(t *testing.T) *secondPushKPeer {
	p := &secondPushKPeer{release: make(chan struct{}), seen: map[string]int{}}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var msg goSetSstp.Message
		if err := json.Unmarshal(raw, &msg); err != nil {
			t.Errorf("bad second-push body: %v", err)
		}
		if msg.ReturnEvents == nil || *msg.ReturnEvents {
			t.Errorf("a second push must carry returnEvents=false")
		}
		if len(msg.Ack) != 0 {
			t.Errorf("a second push must carry no Ack, got %v", msg.Ack)
		}
		p.requests.Add(1)
		n := p.open.Add(1)
		for {
			old := p.peak.Load()
			if n <= old || p.peak.CompareAndSwap(old, n) {
				break
			}
		}
		<-p.release
		p.open.Add(-1)
		acks := make([]string, 0, len(msg.Sets))
		p.mu.Lock()
		for jti := range msg.Sets {
			acks = append(acks, jti)
			p.seen[jti]++
		}
		p.mu.Unlock()
		w.Header().Set("Content-Type", goSetSstp.ContentType)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(goSetSstp.Message{Ack: acks})
	}))
	return p
}

// runSecondPushK starts callers concurrent second pushes against a fake
// outbound bounded to k slots, holding the peer until the slots are full.
// It returns the peer, the fake, and how many calls returned while the peer
// was still holding (the rejected ones).
func runSecondPushK(t *testing.T, k, callers, queued int) (*secondPushKPeer, *fakeSstpOutbound, int64) {
	t.Helper()
	peer := newSecondPushKPeer(t)
	t.Cleanup(peer.srv.Close)

	pairId := fmt.Sprintf("pair-second-push-k%d", k)
	pair := model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:               "tx-" + pairId,
			Iss:              "https://us.example",
			Aud:              []string{"https://peer.example"},
			RouteMode:        model.RouteModeForward,
			TxAllowPlaintext: true, // loopback httptest peer (#322)
		},
		Status: model.StreamStateEnabled,
		PairId: pairId,
		SstpMethod: &model.SstpMethod{
			Role:                model.SstpRoleInitiator,
			EndpointUrl:         peer.srv.URL,
			AuthorizationHeader: "Bearer test-token",
		},
	}
	evs := make([]*model.EventRecord, 0, queued)
	for i := 1; i <= queued; i++ {
		jti := fmt.Sprintf("sstp-k-%d", i)
		evs = append(evs, &model.EventRecord{Jti: jti, Original: `{"jti":"` + jti + `","raw":true}`})
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	fake := newFakeSstpOutbound(ctx, pair, evs...)
	fake.slotMax = k

	dialer := NewSstpDialer(&oneShotCoordinator{}, "node-"+pairId, nil, SstpDialerConfig{
		BaseDelay:     5 * time.Millisecond,
		MaxDelay:      50 * time.Millisecond,
		BackoffFactor: 2.0,
		Jitter:        func() time.Duration { return 0 },
		HTTPClient:    &http.Client{Timeout: 5 * time.Second},
		BackfillBatch: 1,
	})
	dialer.Bind(fake)

	var returned atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cls, _ := dialer.runSecondPush(ctx, &pair, 1)
			assert.Equal(t, goSetSstp.ClassOK, cls.Class)
			returned.Add(1)
		}()
	}

	require.Eventually(t, func() bool {
		return peer.open.Load() == int64(k) && returned.Load() == int64(callers-k)
	}, 5*time.Second, 5*time.Millisecond, "K second pushes open, the rest turned away")
	// Hold briefly: no further push may open while all K slots are held.
	time.Sleep(50 * time.Millisecond)
	rejected := returned.Load()
	close(peer.release)
	wg.Wait()
	return peer, fake, rejected
}

// #339: with I2SIG_SSTP_PUSH_INFLIGHT K=2 two second pushes are on the wire
// at once, a third wake is turned away, the two draw disjoint claims so no SET
// is sent twice, and every queued SET is acked. Each request keeps the Q7.2
// shape (returnEvents=false, no Ack).
func TestPushWhilePollHeld_KSecondPushesInFlight(t *testing.T) {
	peer, fake, rejected := runSecondPushK(t, 2, 3, 6)

	assert.Equal(t, int64(2), peer.peak.Load(), "K=2 second pushes on the wire at once")
	assert.Equal(t, int64(1), rejected, "the third concurrent second push is turned away")
	assert.Equal(t, 2, fake.slotPeak)
	assert.Equal(t, 0, fake.slotsHeld, "every slot is released")
	assert.Len(t, fake.ackedCopy(), 6, "every queued SET is acked")
	peer.mu.Lock()
	defer peer.mu.Unlock()
	require.Len(t, peer.seen, 6)
	for jti, n := range peer.seen {
		assert.Equal(t, 1, n, "%s rides exactly one second push (disjoint claims)", jti)
	}
}

// #339: K=1 reproduces the Q7.2 single slot — one second push on the wire,
// every other concurrent wake turned away.
func TestPushWhilePollHeld_KOneIsTheSingleSlot(t *testing.T) {
	peer, fake, rejected := runSecondPushK(t, 1, 3, 3)

	assert.Equal(t, int64(1), peer.peak.Load(), "K=1: one second push at a time")
	assert.Equal(t, int64(2), rejected)
	assert.Equal(t, 1, fake.slotPeak)
	assert.Len(t, fake.ackedCopy(), 3, "the single push drains the whole buffer")
}
