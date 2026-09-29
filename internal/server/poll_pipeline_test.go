package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetPoll"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	pipelineTestIss = "https://pipeline-tx.example.com"
	pipelineTestAud = "https://pipeline-rcv.example.com"
)

// fakePollRouter stands in for the EventRouter on the poll-receive path: it
// records every ingest and can fail a JTI's first attempts with a store error.
// Only HandleEvents / HandleEventsCtx are implemented; the embedded nil
// interface panics if the loop reaches for anything else.
type fakePollRouter struct {
	eventRouter.EventRouter
	mu        sync.Mutex
	stored    map[string]int // successful first-time stores
	dups      int            // re-received JTIs absorbed by dedup
	attempts  map[string]int
	failFirst map[string]int // jti -> number of attempts that fail
}

func newFakePollRouter() *fakePollRouter {
	return &fakePollRouter{stored: map[string]int{}, attempts: map[string]int{}, failFirst: map[string]int{}}
}

func (f *fakePollRouter) HandleEvents(tokens []*goSet.SecurityEventToken, raws []string, sid string) []error {
	return f.HandleEventsCtx(context.Background(), tokens, raws, sid)
}

func (f *fakePollRouter) HandleEventsCtx(_ context.Context, tokens []*goSet.SecurityEventToken, _ []string, _ string) []error {
	f.mu.Lock()
	defer f.mu.Unlock()
	errs := make([]error, len(tokens))
	for i, tok := range tokens {
		jti := tok.ID
		f.attempts[jti]++
		if f.attempts[jti] <= f.failFirst[jti] {
			errs[i] = eventRouter.ErrStoreUnavailable
			continue
		}
		if f.stored[jti] > 0 {
			f.dups++ // ADR 0017: a duplicate is swallowed, never stored twice
			continue
		}
		f.stored[jti] = 1
	}
	return errs
}

func (f *fakePollRouter) storedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.stored)
}

func (f *fakePollRouter) attemptsFor(jti string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attempts[jti]
}

// pollRecord is one poll the fake transmitter served.
type pollRecord struct {
	acks     []string
	setErrs  []string
	returned []string
}

// fakePollTx is an RFC 8936 transmitter. In claim mode a SET handed out is not
// handed out again until acked (goSignals #337 disjoint claims); otherwise every
// poll returns the oldest un-acked SETs, as a transmitter without claims does.
type fakePollTx struct {
	mu        sync.Mutex
	order     []string
	sets      map[string]string
	acked     map[string]bool
	claimed   map[string]bool
	claimMode bool
	maxEvents int
	// hold delays the body after the headers are flushed.
	hold time.Duration
	// block holds every poll open after its headers until the request ends.
	block    bool
	inflight atomic.Int32
	maxSeen  atomic.Int32
	records  []pollRecord
	// onAck observes each ack as it arrives.
	onAck func(jti string)
}

func (tx *fakePollTx) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/poll" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	n := tx.inflight.Add(1)
	defer tx.inflight.Add(-1)
	for {
		m := tx.maxSeen.Load()
		if n <= m || tx.maxSeen.CompareAndSwap(m, n) {
			break
		}
	}

	var req goSetPoll.PollRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	tx.mu.Lock()
	rec := pollRecord{acks: append([]string(nil), req.Acks...)}
	for jti := range req.SetErrs {
		rec.setErrs = append(rec.setErrs, jti)
	}
	for _, jti := range req.Acks {
		tx.acked[jti] = true
		if tx.onAck != nil {
			tx.onAck(jti)
		}
	}
	sets := map[string]string{}
	for _, jti := range tx.order {
		if len(sets) >= tx.maxEvents {
			break
		}
		if tx.acked[jti] || (tx.claimMode && tx.claimed[jti]) {
			continue
		}
		tx.claimed[jti] = true
		sets[jti] = tx.sets[jti]
		rec.returned = append(rec.returned, jti)
	}
	more := false
	for _, jti := range tx.order {
		if !tx.acked[jti] && !tx.claimed[jti] {
			more = true
			break
		}
	}
	tx.records = append(tx.records, rec)
	tx.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	if tx.block {
		<-r.Context().Done()
		return
	}
	if tx.hold > 0 {
		time.Sleep(tx.hold)
	}
	_ = json.NewEncoder(w).Encode(goSetPoll.PollResponse{Sets: sets, MoreAvailable: more})
}

func (tx *fakePollTx) snapshot() []pollRecord {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	return append([]pollRecord(nil), tx.records...)
}

func (tx *fakePollTx) allAcked() bool {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	return len(tx.acked) >= len(tx.order)
}

func (tx *fakePollTx) ackedJti(jti string) bool {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	return tx.acked[jti]
}

// pipelineHarness is a poll-receiver stream wired to a fake transmitter and a
// fake router, with signed SETs the receiver verifies against its own key store.
type pipelineHarness struct {
	t      *testing.T
	tx     *fakePollTx
	router *fakePollRouter
	ps     *ClientPollStream
	sid    string
	done   chan struct{}
}

func newPipelineHarness(t *testing.T, depth string, nSets int, tx *fakePollTx) *pipelineHarness {
	t.Helper()
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	t.Setenv("I2SIG_POLL_PIPELINE_DEPTH", depth)
	persistence, err := dbProviders.OpenPersistence("", "test_poll_pipeline")
	require.NoError(t, err)

	ctx := context.Background()
	_, err = persistence.KeyService.CreateKeyPair(ctx, pipelineTestIss, "sig", "test-project")
	require.NoError(t, err)
	signer, kid, err := persistence.KeyService.GetPrivateKeyWithKeyname(ctx, pipelineTestIss)
	require.NoError(t, err)

	tx.sets = map[string]string{}
	tx.acked = map[string]bool{}
	tx.claimed = map[string]bool{}
	for i := 0; i < nSets; i++ {
		jti := fmt.Sprintf("jti-%05d", i)
		set := goSet.SecurityEventToken{
			RegisteredClaims: jwt.RegisteredClaims{
				ID:       jti,
				Issuer:   pipelineTestIss,
				Audience: jwt.ClaimStrings{pipelineTestAud},
				IssuedAt: jwt.NewNumericDate(time.Now()),
			},
			SubjectId: &goSet.SubjectIdentifier{
				Format:                  "iss_sub",
				IssuerSubjectIdentifier: goSet.IssuerSubjectIdentifier{Issuer: "https://idp.example.com", Sub: "user-42"},
			},
			Events: map[string]any{"https://schemas.openid.net/secevent/caep/event-type/session-revoked": map[string]any{}},
		}
		set.Kid = kid
		signed, err := set.JWS(jwt.SigningMethodRS256, signer)
		require.NoError(t, err)
		tx.order = append(tx.order, jti)
		tx.sets[jti] = signed
	}

	ts := httptest.NewServer(tx)
	t.Cleanup(ts.Close)

	atx := authSupport.ConvertProject("test-project")
	createCtx := context.WithValue(ctx, authSupport.AuthContextKey, atx)
	created, err := persistence.StreamService.CreateStream(createCtx, model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{
		Iss:              pipelineTestIss,
		Aud:              []string{pipelineTestAud},
		TxAllowPlaintext: true, // loopback httptest transmitter (#322)
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{
				Method:      model.ReceivePoll,
				EndpointUrl: ts.URL + "/poll",
				PollConfig: &model.PollParameters{
					ReturnImmediately: true,
					MaxEvents:         int32(tx.maxEvents),
				},
			},
		},
	}}, atx.ProjectId, nil)
	require.NoError(t, err)

	router := newFakePollRouter()
	sa := newTestApplication(persistence)
	sa.EventRouter = router
	loopCtx, cancel := context.WithCancel(context.Background())
	h := &pipelineHarness{
		t:      t,
		tx:     tx,
		router: router,
		sid:    created.Id,
		done:   make(chan struct{}),
		ps: &ClientPollStream{
			sa:     sa,
			stream: &model.StreamStateRecord{StreamConfiguration: created, Status: model.StreamStateEnabled},
			active: true,
			ctx:    loopCtx,
			cancel: cancel,
		},
	}
	t.Cleanup(h.stop)
	return h
}

func (h *pipelineHarness) start() {
	go func() {
		defer close(h.done)
		h.ps.runPollLoop(h.sid)
	}()
}

func (h *pipelineHarness) stop() {
	h.ps.Close()
	select {
	case <-h.done:
	case <-time.After(5 * time.Second):
		h.t.Fatal("poll loop did not stop")
	}
}

// Depth 1 is the one-poll-at-a-time loop: one request outstanding, and the
// acks earned by response N ride request N+1, exactly.
func TestPollPipeline_Depth1_IsOnePollAtATime(t *testing.T) {
	tx := &fakePollTx{claimMode: true, maxEvents: 10, hold: 5 * time.Millisecond}
	h := newPipelineHarness(t, "1", 50, tx)
	h.start()

	require.Eventually(t, tx.allAcked, 10*time.Second, 10*time.Millisecond)
	h.stop()

	assert.Equal(t, int32(1), tx.maxSeen.Load(), "depth 1 never has two polls outstanding")
	recs := tx.snapshot()
	for i := 1; i < len(recs); i++ {
		want := append([]string(nil), recs[i-1].returned...)
		got := append([]string(nil), recs[i].acks...)
		sort.Strings(want)
		sort.Strings(got)
		assert.Equalf(t, want, got, "poll %d acks exactly what response %d returned", i, i-1)
	}
	assert.Equal(t, 50, h.router.storedCount())
	assert.Zero(t, h.router.dups)
}

// Depth 2 and 4 keep that many polls outstanding (and never more) while the
// transmitter holds each body after its headers, and ingest every SET once.
func TestPollPipeline_KeepsDepthOutstanding(t *testing.T) {
	for _, depth := range []int{2, 4} {
		t.Run(fmt.Sprintf("depth=%d", depth), func(t *testing.T) {
			tx := &fakePollTx{claimMode: true, maxEvents: 5, hold: 100 * time.Millisecond}
			h := newPipelineHarness(t, fmt.Sprint(depth), 200, tx)
			h.start()

			require.Eventually(t, tx.allAcked, 20*time.Second, 10*time.Millisecond)
			assert.Equal(t, int32(depth), tx.maxSeen.Load(), "the pipeline fills to its depth and no further")
			h.stop()

			assert.Equal(t, 200, h.router.storedCount(), "every SET stored")
			assert.Zero(t, h.router.dups, "disjoint claims: no SET received twice")
		})
	}
}

// A SET whose ingest fails is not acked (ADR 0038); the transmitter sends it
// again and it is acked only once it has been stored.
func TestPollPipeline_FailedIngestIsNotAcked(t *testing.T) {
	for _, depth := range []string{"1", "2"} {
		t.Run("depth="+depth, func(t *testing.T) {
			const bad = "jti-00003"
			tx := &fakePollTx{maxEvents: 10}
			var ackedBeforeStored atomic.Bool
			h := newPipelineHarness(t, depth, 20, tx)
			h.router.failFirst[bad] = 2
			tx.onAck = func(jti string) {
				if jti == bad && h.router.attemptsFor(bad) <= 2 {
					ackedBeforeStored.Store(true)
				}
			}
			h.start()

			require.Eventually(t, tx.allAcked, 10*time.Second, 10*time.Millisecond)
			h.stop()

			assert.False(t, ackedBeforeStored.Load(), "a SET whose store failed is never acked")
			assert.GreaterOrEqual(t, h.router.attemptsFor(bad), 3, "the failed SET was received again")
			assert.True(t, tx.ackedJti(bad))
			assert.Equal(t, 20, h.router.storedCount(), "every SET stored exactly once; re-receipts absorbed")
		})
	}
}

// Stop cancels every outstanding poll: the transmitter holds both open, and
// Close ends them and the loop promptly. The outstanding gauge tracks the
// pipeline and its series is removed when the receiver stops.
func TestPollPipeline_StopCancelsOutstanding(t *testing.T) {
	tx := &fakePollTx{claimMode: true, maxEvents: 5, block: true}
	h := newPipelineHarness(t, "2", 0, tx)
	h.start()

	require.Eventually(t, func() bool { return tx.inflight.Load() == 2 }, 5*time.Second, 10*time.Millisecond,
		"the second poll goes out once the first has begun to stream")
	assert.Equal(t, 2.0, testutil.ToFloat64(pollOutstandingGauge.WithLabelValues(h.sid)))

	start := time.Now()
	h.stop()
	assert.Less(t, time.Since(start), 2*time.Second, "stop does not wait out a held poll")
	assert.Eventually(t, func() bool { return tx.inflight.Load() == 0 }, 2*time.Second, 10*time.Millisecond,
		"both outstanding polls were cancelled")
	assert.Equal(t, 0, testutil.CollectAndCount(pollOutstandingGauge, "goSignals_router_poll_receiver_outstanding"),
		"the stream's series is removed when the receiver stops")
}
