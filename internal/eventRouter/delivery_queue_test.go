package eventRouter

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wireAcks maps inbound JTIs to the acknowledgement JTIs a receiver of sid
// acks (#363): the jti of the SET the router handed out.
func wireAcks(r *router, sid string, inbound ...string) []string {
	if len(inbound) == 0 {
		return nil
	}
	q := r.queueFor(sid)
	out := make([]string, len(inbound))
	for i, jti := range inbound {
		out[i] = q.AckJtiOf(jti, nil)
	}
	return out
}

// inboundSets re-keys a poll response (keyed by acknowledgement JTI) by the
// inbound JTIs of the references the queue holds, so a test written against
// inbound JTIs reads it unchanged. A key the queue does not hold is kept.
func inboundSets(r *router, sid string, sets map[string]string) map[string]string {
	if sets == nil {
		return nil
	}
	q := r.queueFor(sid)
	q.mu.Lock()
	byAck := make(map[string]string, len(q.refs))
	for _, qr := range q.refs {
		byAck[qr.ref.AckJti] = qr.ref.Jti
	}
	q.mu.Unlock()
	out := make(map[string]string, len(sets))
	for k, v := range sets {
		if in, ok := byAck[k]; ok {
			k = in
		}
		out[k] = v
	}
	return out
}

// queueRouter is a bare router over a memory store holding one stream sid of
// the given route mode with pending references jtis, written as ingest writes
// them (ackJti from the stream's route mode).
func queueRouter(t *testing.T, routeMode string, jtis ...string) (*router, *memory.EventDAOMemory, model.StreamStateRecord) {
	t.Helper()
	dao := memory.NewEventDAO()
	id := model.NewRecordId()
	rec := model.StreamStateRecord{Id: id}
	rec.StreamConfiguration.Id = id.Hex()
	rec.StreamConfiguration.RouteMode = routeMode
	sid := id.Hex()
	now := time.Now()
	for i, jti := range jtis {
		require.NoError(t, dao.AddPending(context.Background(), interfaces.PendingRef{Jti: jti, AckJti: rec.AckJti(jti), EnqueuedAt: now.Add(time.Duration(i) * time.Millisecond)}, sid))
	}
	r := newBareRouter(RouterDeps{EventService: services.NewEventService(dao)})
	r.pushStreams[sid] = rec
	return r, dao, rec
}

func pendingAckJtis(t *testing.T, dao *memory.EventDAOMemory, sid string) map[string]string {
	t.Helper()
	page, err := dao.GetPendingForStream(context.Background(), sid, 0)
	require.NoError(t, err)
	out := map[string]string{}
	for _, ref := range page.Refs {
		out[ref.Jti] = ref.AckJti
	}
	return out
}

// A re-signing stream's references carry the derived acknowledgement JTI; a
// Forward stream's carry the inbound JTI.
func TestStreamStateRecord_AckJti(t *testing.T) {
	id := model.NewRecordId()
	rec := model.StreamStateRecord{Id: id}
	inbound := "0190a3c4-1111-7abc-8def-0123456789ab"
	for _, mode := range []string{model.RouteModePublish, model.RouteModeImport, ""} {
		rec.StreamConfiguration.RouteMode = mode
		assert.Equal(t, goSet.DeriveCopyJti(id.Hex(), inbound), rec.AckJti(inbound), "mode %q", mode)
	}
	rec.StreamConfiguration.RouteMode = model.RouteModeForward
	assert.Equal(t, inbound, rec.AckJti(inbound))
}

// A pending read seeds the queue; one wire ack batch is one AckBatch call,
// and the dropped references are returned by inbound JTI.
func TestDeliveryQueue_OneAckPerBatch(t *testing.T) {
	r, dao, rec := queueRouter(t, model.RouteModePublish, "a", "b", "c")
	sid := rec.StreamConfiguration.Id
	jtis, _ := r.pendingJtis(context.Background(), sid, model.PollParameters{MaxEvents: 10})
	require.ElementsMatch(t, []string{"a", "b", "c"}, jtis)
	q := r.queueFor(sid)
	depth, oldest := q.Backlog()
	assert.Equal(t, int64(3), depth)
	assert.False(t, oldest.IsZero())

	writes := testutil.ToFloat64(ackWritesTotal)
	batches := testutil.ToFloat64(ackBatchesTotal)
	inbound, n, err := q.AckWire(context.Background(), []string{rec.AckJti("a"), rec.AckJti("b")}, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(2), n)
	assert.ElementsMatch(t, []string{"a", "b"}, inbound)
	assert.Equal(t, writes+1, testutil.ToFloat64(ackWritesTotal), "one AckBatch per batch")
	assert.Equal(t, batches+1, testutil.ToFloat64(ackBatchesTotal))
	assert.Equal(t, map[string]string{"c": rec.AckJti("c")}, pendingAckJtis(t, dao, sid))
	depth, _ = q.Backlog()
	assert.Equal(t, int64(1), depth)
}

// A served re-signed SET acknowledged by the receiver stores its outbound
// copy (jti = AckJti, originalJti = inbound); a setErr and a forwarded SET
// store none.
func TestDeliveryQueue_CopiesWithOriginalJti(t *testing.T) {
	r, dao, rec := queueRouter(t, model.RouteModePublish, "a", "b")
	sid := rec.StreamConfiguration.Id
	_, _ = r.pendingJtis(context.Background(), sid, model.PollParameters{MaxEvents: 10})
	q := r.queueFor(sid)
	for _, jti := range []string{"a", "b"} {
		signed := goSet.SecurityEventToken{}
		signed.ID = q.AckJtiOf(jti, nil)
		q.Served(&model.EventRecord{Jti: jti, Types: []string{"t"}}, &signed, "jws-"+jti)
	}
	_, _, err := q.AckWire(context.Background(), []string{rec.AckJti("a")}, []string{rec.AckJti("b")})
	require.NoError(t, err)

	copyA := findCopy(t, dao, rec.AckJti("a"))
	require.NotNil(t, copyA, "the acked SET's outbound copy is stored")
	assert.Equal(t, "a", copyA.OriginalJti)
	assert.Equal(t, sid, copyA.Sid)
	assert.Equal(t, "jws-a", copyA.Original)
	assert.Nil(t, findCopy(t, dao, rec.AckJti("b")), "a setErr stores no copy")

	f, fdao, frec := queueRouter(t, model.RouteModeForward, "x")
	fsid := frec.StreamConfiguration.Id
	_, _ = f.pendingJtis(context.Background(), fsid, model.PollParameters{MaxEvents: 10})
	fq := f.queueFor(fsid)
	fq.Served(&model.EventRecord{Jti: "x"}, nil, "orig")
	_, _, err = fq.AckWire(context.Background(), []string{"x"}, nil)
	require.NoError(t, err)
	assert.Empty(t, pendingAckJtis(t, fdao, fsid), "a Forward SET is acked by its inbound JTI")
}

// readCountingDAO counts the store reads the delivery queue can make.
type readCountingDAO struct {
	interfaces.EventDAO
	reads atomic.Int64
}

func (d *readCountingDAO) GetPendingForStream(ctx context.Context, sid string, limit int32) (interfaces.PendingPage, error) {
	d.reads.Add(1)
	return d.EventDAO.GetPendingForStream(ctx, sid, limit)
}

func (d *readCountingDAO) StoredAckJtis(ctx context.Context, sid string, jtis []string) (map[string]string, error) {
	d.reads.Add(1)
	return d.EventDAO.StoredAckJtis(ctx, sid, jtis)
}

func (d *readCountingDAO) FindByJTIs(ctx context.Context, jtis []string) ([]*model.EventRecord, error) {
	d.reads.Add(1)
	return d.EventDAO.FindByJTIs(ctx, jtis)
}

// A backlog larger than the window is counted from the pending read, not
// held. Acknowledging the held window and refilling leaves the queue's depth
// and oldest enqueue time equal to the store's, and Backlog reads nothing
// from the store (#363).
func TestDeliveryQueue_BacklogOverWindow(t *testing.T) {
	r, dao, rec := queueRouter(t, model.RouteModePublish, "a", "b", "c", "d", "e")
	counting := &readCountingDAO{EventDAO: dao}
	r.eventService = services.NewEventService(counting)
	sid := rec.StreamConfiguration.Id
	ctx := context.Background()
	q := newDeliveryQueue(r, sid, 2)
	r.queues.Store(sid, q)
	_, _ = r.pendingJtis(ctx, sid, model.PollParameters{MaxEvents: 10})
	q.mu.Lock()
	held := len(q.refs)
	q.mu.Unlock()
	assert.Equal(t, 2, held, "the queue holds at most its window")
	depth, oldest := q.Backlog()
	assert.Equal(t, int64(5), depth)
	assert.False(t, oldest.IsZero())

	n, err := q.AckInbound(ctx, []string{"a", "b"}, true)
	require.NoError(t, err)
	require.Equal(t, int64(2), n)
	_, _ = r.pendingJtis(ctx, sid, model.PollParameters{MaxEvents: 10})

	store, err := dao.GetPendingForStream(ctx, sid, 10)
	require.NoError(t, err)
	storeOldest := time.Time{}
	for _, ref := range store.Refs {
		if storeOldest.IsZero() || ref.EnqueuedAt.Before(storeOldest) {
			storeOldest = ref.EnqueuedAt
		}
	}
	require.Equal(t, int64(3), store.Total)
	require.Len(t, store.Refs, 3)

	before := counting.reads.Load()
	depth, oldest = q.Backlog()
	assert.Equal(t, before, counting.reads.Load(), "Backlog reads nothing from the store")
	assert.Equal(t, store.Total, depth, "depth matches the store after the refill")
	assert.True(t, storeOldest.Equal(oldest), "oldest matches the store after the refill: want %v, got %v", storeOldest, oldest)
}

// Route-mode change, both directions: to Forward rewrites every pending row's
// acknowledgement JTI to its inbound JTI; to a re-signing mode keeps the rows
// as written (the held value is authoritative).
func TestDeliveryQueue_RouteModeChange(t *testing.T) {
	r, dao, rec := queueRouter(t, model.RouteModePublish, "a", "b")
	sid := rec.StreamConfiguration.Id
	_, _ = r.pendingJtis(context.Background(), sid, model.PollParameters{MaxEvents: 10})
	assert.Equal(t, rec.AckJti("a"), pendingAckJtis(t, dao, sid)["a"])

	fw := rec
	fw.StreamConfiguration.RouteMode = model.RouteModeForward
	r.pushStreams[sid] = fw
	r.queueFor(sid).routeModeChanged(context.Background())
	assert.Equal(t, map[string]string{"a": "a", "b": "b"}, pendingAckJtis(t, dao, sid))
	assert.Equal(t, "a", r.queueFor(sid).AckJtiOf("a", nil))

	r.pushStreams[sid] = rec
	r.queueFor(sid).routeModeChanged(context.Background())
	_, _ = r.pendingJtis(context.Background(), sid, model.PollParameters{MaxEvents: 10})
	assert.Equal(t, "a", r.queueFor(sid).AckJtiOf("a", nil), "a row written under Forward keeps its acknowledgement JTI")
	_, err := r.queueFor(sid).AckInbound(context.Background(), []string{"a", "b"}, true)
	require.NoError(t, err)
	assert.Empty(t, pendingAckJtis(t, dao, sid))
}

func findCopy(t *testing.T, dao *memory.EventDAOMemory, jti string) *model.EventRecord {
	t.Helper()
	rec, err := dao.FindByJTI(context.Background(), jti)
	if err != nil {
		return nil
	}
	return rec
}

// The fan-out wake accepts references under r.mu (RLock). acceptLocked must
// not take r.mu again: with a writer waiting, a nested RLock deadlocks.
func TestDeliveryQueue_AcceptLockedNoNestedRLock(t *testing.T) {
	r, _, rec := queueRouter(t, model.RouteModeForward)
	sid := rec.StreamConfiguration.Id
	q := r.queueFor(sid)
	r.mu.RLock()
	writerDone := make(chan struct{})
	go func() {
		r.mu.Lock()
		r.mu.Unlock()
		close(writerDone)
	}()
	time.Sleep(20 * time.Millisecond) // let the writer queue on r.mu
	done := make(chan struct{})
	go func() {
		q.acceptLocked(context.Background(), []interfaces.PendingRef{{Jti: "a", AckJti: "a", EnqueuedAt: time.Now()}})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		r.mu.RUnlock()
		t.Fatal("acceptLocked blocked on r.mu with a writer waiting")
	}
	r.mu.RUnlock()
	<-writerDone
	assert.Equal(t, "a", q.AckJtiOf("a", nil))
}

// S2: rows keep the ackJti written at ingest and nothing is re-derived. After a
// change from Forward to a re-signing mode, a reference beyond the queue's
// window is signed and acknowledged under its stored ackJti (the inbound JTI),
// not the stream's derived one.
func TestDeliveryQueue_BeyondWindowUsesStoredAckJti(t *testing.T) {
	r, dao, rec := queueRouter(t, model.RouteModeForward, "a", "b", "c")
	sid := rec.StreamConfiguration.Id
	q := newDeliveryQueue(r, sid, 1)
	r.queues.Store(sid, q)
	_, _ = r.pendingJtis(context.Background(), sid, model.PollParameters{MaxEvents: 1})

	pub := rec
	pub.StreamConfiguration.RouteMode = model.RouteModePublish
	r.pushStreams[sid] = pub
	q.routeModeChanged(context.Background())
	require.NotEqual(t, "c", pub.AckJti("c"), "the derived value differs from the stored one")

	assert.Equal(t, "c", q.AckJtiOf("c", &pub), "a reference the queue does not hold takes its stored ackJti")
	assert.Equal(t, []string{"b", "c"}, q.AckJtisOf([]string{"b", "c"}, &pub))
	assert.Equal(t, "c", q.RefOf("c", &pub).AckJti)

	n, err := q.AckInbound(context.Background(), []string{"c"}, true)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n, "the acknowledgement matches the stored row")
	assert.Equal(t, map[string]string{"a": "a", "b": "b"}, pendingAckJtis(t, dao, sid))
	assert.Nil(t, findCopy(t, dao, pub.AckJti("c")), "no copy under a re-derived JTI")
}

// failingAckReadDAO fails every StoredAckJtis read.
type failingAckReadDAO struct {
	interfaces.EventDAO
}

func (failingAckReadDAO) StoredAckJtis(context.Context, string, []string) (map[string]string, error) {
	return nil, errors.New("store down")
}

// S2: rows keep the ackJti written at ingest; nothing is re-derived. A failed
// stored-ackJti read leaves the unheld references unresolved (empty): no sign
// site may hand them out under a derived JTI, so they stay pending and are
// delivered on a later read. A held reference still resolves from memory.
func TestDeliveryQueue_FailedStoredAckReadDerivesNothing(t *testing.T) {
	r, dao, rec := queueRouter(t, model.RouteModeForward, "a", "b")
	sid := rec.StreamConfiguration.Id
	q := newDeliveryQueue(r, sid, 1)
	r.queues.Store(sid, q)
	_, _ = r.pendingJtis(context.Background(), sid, model.PollParameters{MaxEvents: 1})
	pub := rec
	pub.StreamConfiguration.RouteMode = model.RouteModePublish
	r.pushStreams[sid] = pub
	r.eventService = services.NewEventService(failingAckReadDAO{EventDAO: dao})

	assert.Equal(t, []string{"a", ""}, q.AckJtisOf([]string{"a", "b"}, &pub), "a failed read must not derive")
	assert.Equal(t, "", q.AckJtiOf("b", &pub))
	assert.Equal(t, "", q.RefOf("b", &pub).AckJti)

	// Served records an unheld SET under the JTI it was signed with, without
	// reading the store.
	wide := newDeliveryQueue(r, sid, 5)
	signed := goSet.SecurityEventToken{}
	signed.ID = "b"
	wide.Served(&model.EventRecord{Jti: "b"}, &signed, "jws-b")
	wide.mu.Lock()
	qr, ok := wide.refs["b"]
	wide.mu.Unlock()
	require.True(t, ok)
	assert.Equal(t, "b", qr.ref.AckJti)
}

// A poll response leaves out a SET whose stored ackJti could not be read: it
// is not signed under a derived JTI, and stays pending (#363, S2).
func TestAssemblePollResponse_FailedStoredAckReadLeavesSetPending(t *testing.T) {
	r, dao, rec := queueRouter(t, model.RouteModePublish, "a", "b")
	sid := rec.StreamConfiguration.Id
	for _, jti := range []string{"a", "b"} {
		require.NoError(t, dao.Insert(context.Background(), &model.EventRecord{Jti: jti, Sid: sid, Event: goSet.SecurityEventToken{}}))
	}
	q := newDeliveryQueue(r, sid, 1)
	r.queues.Store(sid, q)
	_, _ = r.pendingJtis(context.Background(), sid, model.PollParameters{MaxEvents: 1})
	r.eventService = services.NewEventService(failingAckReadDAO{EventDAO: dao})
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	sets, err := r.assemblePollResponse(sid, &rec, nil, []string{"a", "b"}, false, key, "kid")
	require.NoError(t, err)
	assert.Len(t, sets, 1, "only the held reference is handed out")
	assert.Contains(t, sets, rec.AckJti("a"))
	assert.NotContains(t, sets, rec.AckJti("b"), "signed under a derived JTI after a failed read")
	assert.Contains(t, pendingAckJtis(t, dao, sid), "b", "the SET stays pending")
}
