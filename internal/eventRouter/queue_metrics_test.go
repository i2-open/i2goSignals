package eventRouter

import (
	"context"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/dao/daometrics"
	"github.com/i2-open/i2goSignals/internal/eventRouter/buffer"
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	goSetSstp "github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Queue and acknowledgement time histograms and per-stream backlog gauges
// (#352). The histograms are process-wide, so each test reads the change in
// their sample counts.

type waitCounts map[string][2]uint64 // tfr -> {queue time, ack time}

func histSamples(t *testing.T, vec *prometheus.HistogramVec, tfr string) uint64 {
	t.Helper()
	m := &dto.Metric{}
	require.NoError(t, vec.WithLabelValues(tfr).(prometheus.Metric).Write(m))
	return m.GetHistogram().GetSampleCount()
}

func readWaits(t *testing.T) waitCounts {
	t.Helper()
	out := waitCounts{}
	for _, tfr := range []string{tfrPush, tfrPoll, tfrSstp} {
		out[tfr] = [2]uint64{histSamples(t, queueTimeHist, tfr), histSamples(t, ackTimeHist, tfr)}
	}
	return out
}

// waitDelta returns, per tfr, how many queue and ack time samples were added
// since before.
func waitDelta(t *testing.T, before waitCounts) waitCounts {
	t.Helper()
	now := readWaits(t)
	out := waitCounts{}
	for tfr, n := range now {
		out[tfr] = [2]uint64{n[0] - before[tfr][0], n[1] - before[tfr][1]}
	}
	return out
}

// requireOneObservation asserts exactly one sample in each histogram under
// tfr and none under the other transports.
func requireOneObservation(t *testing.T, before waitCounts, tfr string) {
	t.Helper()
	require.Eventually(t, func() bool { return waitDelta(t, before)[tfr] == [2]uint64{1, 1} }, 2*time.Second, 5*time.Millisecond,
		"one queue time and one ack time sample under tfr %s", tfr)
	for other, d := range waitDelta(t, before) {
		if other != tfr {
			assert.Equal(t, [2]uint64{0, 0}, d, "no samples under tfr %s", other)
		}
	}
}

func TestQueueMetrics_TfrOf(t *testing.T) {
	poll := &model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{Delivery: &model.OneOfStreamConfigurationDelivery{PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll}}}}
	assert.Equal(t, tfrPoll, tfrOf(poll))
	push := &model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{Delivery: &model.OneOfStreamConfigurationDelivery{PushTransmitMethod: &model.PushTransmitMethod{Method: model.DeliveryPush}}}}
	assert.Equal(t, tfrPush, tfrOf(push))
	assert.Equal(t, tfrSstp, tfrOf(sstpServerPairState("tx", "rx", "p")))
	assert.Equal(t, tfrSstp, tfrOf(sstpClientPairForMatch("tx", "p")))
}

// Push: one SET pushed and accepted.
func TestQueueMetrics_Push(t *testing.T) {
	h := newFilterPushRouter(t)
	stream := h.createPushStream(t, model.DefaultSubjectsAll)
	sid := stream.StreamConfiguration.Id
	registerPush(h.router, stream)
	jti := h.addPendingEvent(t, sid, emailSubjectFor("push@example.com"), false)
	jtis, _ := h.router.pendingJtis(context.Background(), sid, model.PollParameters{MaxEvents: 10, ReturnImmediately: true})
	require.Equal(t, []string{jti}, jtis)

	before := readWaits(t)
	res := h.router.pushBatch(jtis, stream, nil, "")
	require.Equal(t, 1, res.acked)
	requireOneObservation(t, before, tfrPush)
}

// registerPush adds stream to the router's push streams and gives this node
// its lease, as the running server does before its push runner delivers.
func registerPush(r *router, stream *model.StreamStateRecord) {
	sid := stream.StreamConfiguration.Id
	r.mu.Lock()
	r.pushStreams[sid] = *stream
	r.mu.Unlock()
	r.leases.note(cluster.PushTransmitterResource(sid), time.Now(), true, time.Now().Add(time.Minute), time.Minute)
}

// Poll: one SET returned by a poll and acknowledged on the next.
func TestQueueMetrics_Poll(t *testing.T) {
	h := newFilterPushRouter(t)
	stream := h.createPollStream(t, model.DefaultSubjectsAll)
	sid := stream.StreamConfiguration.Id
	jti := h.addPendingEvent(t, sid, emailSubjectFor("poll@example.com"), false)
	h.loadPollBuffer(t, sid, jti)

	before := readWaits(t)
	sets, status := h.pollImmediate(sid)
	require.Equal(t, 200, status)
	require.Len(t, sets, 1)
	var wire string
	for k := range sets {
		wire = k
	}
	_, _, status = h.router.PollStreamHandler(context.Background(), sid, model.PollParameters{
		MaxEvents: 10, ReturnImmediately: true, Acks: []string{wire},
	})
	require.Equal(t, 200, status)
	requireOneObservation(t, before, tfrPoll)
}

// SSTP acceptor: the pair's outbound SET returned in one response and
// acknowledged in the next request.
func TestQueueMetrics_SstpAcceptor(t *testing.T) {
	h := newSstpRunnerHarness(t)
	txSid, rxSid, pairId := "sstp-tx-352", "sstp-rx-352", "pair-352"
	rec := sstpServerPairState(txSid, rxSid, pairId)
	require.NoError(t, h.router.streamService.PersistStreamStateRecord(context.Background(), rec))
	h.router.mu.Lock()
	h.router.sstpServerStreams[txSid] = *rec
	h.router.mu.Unlock()

	jti := "sstp-out-352"
	h.persistOutboundEvent(t, txSid, jti)
	resolved, err := h.router.streamService.GetStreamStateByPairId(context.Background(), pairId)
	require.NoError(t, err)

	before := readWaits(t)
	resp, _ := h.router.SstpServerHandler(context.Background(), resolved, goSetSstp.Message{}, nil)
	require.Len(t, resp.Sets, 1)
	var wire string
	for k := range resp.Sets {
		wire = k
	}
	// The acknowledging request then long-polls for more; nothing is pending.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, _ = h.router.SstpServerHandler(ctx, resolved, goSetSstp.Message{Ack: []string{wire}}, nil)
	requireOneObservation(t, before, tfrSstp)
}

// SSTP dialer: the pair's outbound SET claimed, sent and acknowledged by the
// peer.
func TestQueueMetrics_SstpDialer(t *testing.T) {
	h := newSstpRunnerHarness(t)
	r := h.router
	txSid, pairId := "sstp-tx-dial-352", "pair-dial-352"
	pair := sstpClientPairForMatch(txSid, pairId)
	r.mu.Lock()
	r.sstpClientStreams[pairId] = *pair
	r.sstpBuffers[pairId] = buffer.CreateEventPollBuffer(nil, 1, 1)
	r.rebuildRoutingLocked()
	r.mu.Unlock()
	r.NoteLease(pairId, time.Now(), true, time.Now().Add(time.Minute), time.Minute)

	jti := "sstp-dial-352"
	h.persistOutboundEvent(t, txSid, jti)

	before := readWaits(t)
	claimed := r.ClaimOutbound(pairId, 1)
	require.Equal(t, []string{jti}, claimed)
	events := r.ResolveEvents(pairId, claimed)
	require.Len(t, events, 1)
	wire := r.OutboundAckJti(pair, jti)
	r.OutboundHandedOut(pair, []string{wire})
	require.Equal(t, 1, r.AckOutbound(pair, []string{wire}, events))
	if ack := r.sstpAcker(pairId); ack != nil {
		_ = ack.flush()
	}
	requireOneObservation(t, before, tfrSstp)
}

// A subject-filtered SET is never sent: it is discarded from the backlog and
// observed in neither histogram.
func TestQueueMetrics_SubjectFilteredNotObserved(t *testing.T) {
	t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
	h := newFilterPushRouter(t)
	stream := h.createPushStream(t, model.DefaultSubjectsNone)
	sid := stream.StreamConfiguration.Id
	jti := h.addPendingEvent(t, sid, emailSubjectFor("alice@example.com"), false)
	_, _ = h.router.pendingJtis(context.Background(), sid, model.PollParameters{MaxEvents: 10, ReturnImmediately: true})
	depth, _ := h.router.queueFor(sid).Backlog()
	require.Equal(t, int64(1), depth)

	before := readWaits(t)
	_, _, _ = h.router.prepareAndSendEvent(jti, stream, nil, "")
	require.Equal(t, 0, h.adapter.Calls())
	require.Equal(t, 0, h.pendingCount(sid))
	depth, _ = h.router.queueFor(sid).Backlog()
	assert.Equal(t, int64(0), depth, "the discarded SET leaves the backlog")
	for tfr, d := range waitDelta(t, before) {
		assert.Equal(t, [2]uint64{0, 0}, d, "no samples under tfr %s", tfr)
	}
}

// After an ownership change the new owner acknowledges a SET it never handed
// out: no acknowledgement-time observation is made for it, while a SET it did
// hand out is observed.
func TestQueueMetrics_FailoverSkipsUnseenHandOut(t *testing.T) {
	oldOwner, dao, rec := queueRouter(t, model.RouteModeForward, "a", "b")
	sid := rec.StreamConfiguration.Id
	_, _ = oldOwner.pendingJtis(context.Background(), sid, model.PollParameters{MaxEvents: 10, ReturnImmediately: true})
	oldOwner.queueFor(sid).MarkHandedOut([]string{"a", "b"}, time.Now())

	newOwner := &router{
		eventService:      services.NewEventService(dao),
		pushStreams:       map[string]model.StreamStateRecord{sid: rec},
		pollStreams:       map[string]model.StreamStateRecord{},
		sstpClientStreams: map[string]model.StreamStateRecord{},
		sstpServerStreams: map[string]model.StreamStateRecord{},
	}
	_, _ = newOwner.pendingJtis(context.Background(), sid, model.PollParameters{MaxEvents: 10, ReturnImmediately: true})
	newOwner.queueFor(sid).MarkHandedOut([]string{"b"}, time.Now())

	before := readWaits(t)
	n, err := newOwner.queueFor(sid).AckInbound(context.Background(), []string{"a", "b"}, true)
	require.NoError(t, err)
	require.Equal(t, int64(2), n)
	assert.Equal(t, [2]uint64{1, 1}, waitDelta(t, before)[tfrPush], "only the SET the new owner handed out is observed")
}

// daoOps is the number of EventDAO calls m has recorded.
func daoOps(t *testing.T, m *daometrics.Metrics) uint64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	reg.MustRegister(m.OpDuration)
	mfs, err := reg.Gather()
	require.NoError(t, err)
	var n uint64
	for _, mf := range mfs {
		for _, mt := range mf.GetMetric() {
			n += mt.GetHistogram().GetSampleCount()
		}
	}
	return n
}

type gaugeRow struct {
	depth, age float64
}

func scrapeBacklog(t *testing.T, c prometheus.Collector) map[string]gaugeRow {
	t.Helper()
	ch := make(chan prometheus.Metric, 64)
	c.Collect(ch)
	close(ch)
	out := map[string]gaugeRow{}
	for m := range ch {
		d := &dto.Metric{}
		require.NoError(t, m.Write(d))
		var sid string
		for _, l := range d.GetLabel() {
			if l.GetName() == "stream_id" {
				sid = l.GetValue()
			}
		}
		row := out[sid]
		switch m.Desc() {
		case backlogDepthDesc:
			row.depth = d.GetGauge().GetValue()
		case backlogOldestAgeDesc:
			row.age = d.GetGauge().GetValue()
		}
		out[sid] = row
	}
	return out
}

// The backlog gauges come from the owning node's DeliveryQueue: no EventDAO
// call at scrape; a stream this node does not own, or has removed, is not
// reported.
func TestBacklogCollector_ReadsOwnedQueuesWithoutStore(t *testing.T) {
	r, dao, rec := queueRouter(t, model.RouteModeForward, "a", "b", "c")
	sid := rec.StreamConfiguration.Id
	m := daometrics.NewMetrics()
	r.eventService = services.NewEventService(daometrics.Wrap(dao, m))
	_, _ = r.pendingJtis(context.Background(), sid, model.PollParameters{MaxEvents: 10, ReturnImmediately: true})
	_, oldest := r.queueFor(sid).Backlog()
	require.False(t, oldest.IsZero())

	// A second pushed stream this node has a queue for but does not own.
	other, _, otherRec := queueRouter(t, model.RouteModeForward)
	_ = other
	otherSid := otherRec.StreamConfiguration.Id
	r.pushStreams[otherSid] = otherRec
	r.queueFor(otherSid)

	r.leases = newLeaseManager(&countingLeaseStore{})
	r.leases.note(cluster.PushTransmitterResource(sid), time.Now(), true, time.Now().Add(time.Minute), time.Minute)

	c := &backlogCollector{r: r, now: func() time.Time { return oldest.Add(3 * time.Second) }}
	callsBefore := daoOps(t, m)
	rows := scrapeBacklog(t, c)
	assert.Equal(t, callsBefore, daoOps(t, m), "a scrape makes no EventDAO call")
	require.Contains(t, rows, sid)
	assert.Equal(t, float64(3), rows[sid].depth)
	assert.InDelta(t, 3.0, rows[sid].age, 0.001)
	assert.NotContains(t, rows, otherSid, "a stream this node does not own is not reported")

	// Acknowledged down to empty: depth and age read 0.
	_, err := r.queueFor(sid).AckInbound(context.Background(), []string{"a", "b", "c"}, true)
	require.NoError(t, err)
	rows = scrapeBacklog(t, c)
	assert.Equal(t, gaugeRow{}, rows[sid])

	// Removed: the series stops.
	r.dropQueue(sid)
	assert.NotContains(t, scrapeBacklog(t, c), sid)
}
