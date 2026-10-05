package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/memory_provider"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tableRouter is a router double that implements eventRouter.StreamTable: it
// records each stream-table sync and each stream-changed broadcast, and its
// syncs report the store's streams as the real router would.
type tableRouter struct {
	recordingRouter
	app        *SignalsApplication
	mu         sync.Mutex
	syncs      int
	broadcasts []string
}

func (tr *tableRouter) StreamIds() []string { return nil }

func (tr *tableRouter) SyncStreamTable(ctx context.Context) (map[string]model.StreamStateRecord, error) {
	tr.mu.Lock()
	tr.syncs++
	tr.mu.Unlock()
	return tr.app.StreamService.LoadStateMap(ctx)
}

func (tr *tableRouter) BroadcastStreamChanged(sid string) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.broadcasts = append(tr.broadcasts, sid)
}

func (tr *tableRouter) AwaitPushStopped(context.Context, string) bool { return true }

func (tr *tableRouter) syncCount() int {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return tr.syncs
}

func (tr *tableRouter) broadcastSids() []string {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return append([]string(nil), tr.broadcasts...)
}

var _ eventRouter.StreamTable = (*tableRouter)(nil)

// tableApp is the real test application with the router replaced by a
// tableRouter.
type tableApp struct {
	*statusRefreshApp
	router *tableRouter
}

func (a *tableApp) GetEventRouter() eventRouter.EventRouter { return a.router }

func newTableApp(t *testing.T) *tableApp {
	t.Helper()
	base := newStatusRefreshApp(t)
	tr := &tableRouter{app: base.SignalsApplication}
	base.EventRouter = tr
	return &tableApp{statusRefreshApp: base, router: tr}
}

func streamChangedReq(secret, sid string) *http.Request {
	return wakeSstpReq("/_cluster/stream-changed", secret, sid, eventRouter.StreamChangedMode)
}

// An authenticated stream-changed call reconciles the stream it names before
// it answers 202: a stream now in the store is served, one gone from the store
// is removed. Every call does so (a create followed at once by a delete of the
// same stream must both be seen), and only that stream is touched; the full
// store scan and the cluster-row purge stay on the periodic sync, so a large
// store cannot hold the peer's call past its bound (#349).
func TestStreamChanged_ReconcilesOnlyTheNamedStream(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", "test-secret")
	base := newStatusRefreshApp(t)
	sr := &servingRouter{app: base.SignalsApplication, served: map[string]bool{}}
	base.EventRouter = sr
	// A stream this node serves that is no longer in the store: only a full
	// sync would remove it.
	sr.served["gone-elsewhere"] = true

	persistStatusPlain(t, base, model.StreamStateEnabled, "")
	w := httptest.NewRecorder()
	base.StreamChanged(w, streamChangedReq("test-secret", statusPlainSid))
	assert.Equal(t, http.StatusAccepted, w.Code)
	assert.True(t, sr.serves(statusPlainSid), "the created stream is served before the call answers")
	assert.True(t, sr.serves("gone-elsewhere"), "no other stream is reconciled")

	require.NoError(t, base.StreamService.DeleteStream(context.Background(), statusPlainSid))
	w = httptest.NewRecorder()
	base.StreamChanged(w, streamChangedReq("test-secret", statusPlainSid))
	assert.Equal(t, http.StatusAccepted, w.Code)
	assert.False(t, sr.serves(statusPlainSid), "the deleted stream is removed before the call answers")
	assert.True(t, sr.serves("gone-elsewhere"), "no other stream is reconciled")
	assert.Zero(t, sr.syncCount(), "no full stream-table sync")
}

// A stream-changed call without a valid cluster token is refused and changes
// nothing; a token minted for a wake-up route does not validate here.
func TestStreamChanged_RejectsUnauthenticated(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", "test-secret")
	app := newTableApp(t)

	body, _ := json.Marshal(map[string]string{"sid": "sid-1", "mode": eventRouter.StreamChangedMode})
	w := httptest.NewRecorder()
	app.StreamChanged(w, httptest.NewRequest(http.MethodPost, "/_cluster/stream-changed", bytes.NewReader(body)))
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	w = httptest.NewRecorder()
	app.StreamChanged(w, wakeSstpReq("/_cluster/stream-changed", "test-secret", "sid-1", "sstp-client"))
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	assert.Equal(t, 0, app.router.syncCount())
}

// Creating a stream and deleting it tell the other nodes, each before the
// request answers, so a peer serves the new stream (and stops serving the
// deleted one) without waiting for its periodic sync (#349, #350).
func TestStreamCreateAndDelete_AnnounceToPeers(t *testing.T) {
	app := newTableApp(t)
	bearer := app.adminBearer(t)

	create := *statusPlainRecord("DEFAULT", "", "")
	create.StreamConfiguration.Id = ""
	body, err := json.Marshal(create)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/stream", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+bearer)
	rr := httptest.NewRecorder()
	StreamCreateHandler(app, rr, req)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	var created model.StreamConfiguration
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &created))
	assert.Equal(t, []string{created.Id}, app.router.broadcastSids(), "a create is announced")

	req = httptest.NewRequest(http.MethodDelete, "/stream?stream_id="+created.Id, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	rr = httptest.NewRecorder()
	StreamDeleteHandler(app, rr, req)
	require.Equal(t, http.StatusNoContent, rr.Code, rr.Body.String())
	assert.Equal(t, []string{created.Id, created.Id}, app.router.broadcastSids(), "a delete is announced")
}

// After a successful stream-table sync the cluster rows left behind are
// purged: a node silent for longer than the GC window, and an expired lease
// whose stream is gone from the store. A lease whose stream still exists keeps
// its row, and with it its fencing history (#350).
func TestSyncStreamTable_PurgesStaleClusterRows(t *testing.T) {
	app := newTableApp(t)
	persistStatusPlain(t, app.statusRefreshApp, model.StreamStateEnabled, "")
	coord, ok := app.Coordinator.(*memory_provider.MemoryCoordinator)
	require.True(t, ok)

	past := time.Now().UTC().Add(-10 * time.Minute)
	coord.SetClock(func() time.Time { return past })
	gone, live := cluster.PushTransmitterResource("deleted-sid"), cluster.PushTransmitterResource(statusPlainSid)
	for _, res := range []string{gone, live} {
		ok, _, _, err := coord.TryAcquireOrRenewLease(res, "node-old", time.Second)
		require.NoError(t, err)
		require.True(t, ok)
	}
	coord.SetClock(nil)
	require.NoError(t, coord.RegisterNode(model.ClusterNode{Id: "node-old", LastSeenAt: past}))
	require.NoError(t, coord.RegisterNode(model.ClusterNode{Id: "node-now", LastSeenAt: time.Now().UTC()}))

	app.syncStreamTable()
	require.Equal(t, 1, app.router.syncCount())

	_, token, _, _ := coord.TryAcquireOrRenewLease(gone, "node-now", time.Second)
	assert.Equal(t, int64(1), token, "the deleted stream's lease row is purged")
	_, token, _, _ = coord.TryAcquireOrRenewLease(live, "node-now", time.Second)
	assert.Equal(t, int64(2), token, "a live stream's lease row is kept")
	old, _ := coord.GetNode("node-old")
	assert.Nil(t, old, "a node silent past the GC window is purged")
	current, _ := coord.GetNode("node-now")
	assert.NotNil(t, current)
}

// #349 review: a stream-changed call from a peer reconciles the receivers too.
// When the store cannot be read, the reconcile must keep the receivers this
// node runs — as it keeps the router's streams — rather than read the failed
// read as "no receivers" and close every poll and push receiver client.
func TestSyncStreamTable_StoreReadErrorKeepsReceivers(t *testing.T) {
	app := newTableApp(t)
	dao := &failingStreamDAO{StreamDAO: memory.NewStreamDAO()}
	app.statusRefreshApp.withStreamDAO(dao)

	pollCancelled, pushCancelled := false, false
	pollRec := &model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{Id: "rcv-poll"}}
	pushRec := &model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{Id: "rcv-push"}}
	app.pollClients = map[string]*ClientPollStream{
		"rcv-poll": {stream: pollRec, active: true, cancel: func() { pollCancelled = true }},
	}
	app.pushClients = map[string]*ReceiverPushStream{
		"rcv-push": {stream: pushRec, active: true, cancel: func() { pushCancelled = true }},
	}

	dao.failList = true
	app.syncStreamTable()

	assert.Contains(t, app.pollClients, "rcv-poll", "a failed store read keeps the poll receiver")
	assert.Contains(t, app.pushClients, "rcv-push", "a failed store read keeps the push receiver")
	assert.False(t, pollCancelled)
	assert.False(t, pushCancelled)
}

// servingRouter is a router double that tracks the streams it serves the way
// the real router does: UpdateStreamState adds one, RemoveStream drops it, and
// a stream-table sync adds every stream in the store and drops the rest.
type servingRouter struct {
	recordingRouter
	app    *SignalsApplication
	mu     sync.Mutex
	served map[string]bool
	syncs  int
	// runnerStopped, when set, stands in for a held stream's push runner:
	// AwaitPushStopped waits for it to close.
	runnerStopped chan struct{}
}

func (sr *servingRouter) syncCount() int {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	return sr.syncs
}

func (sr *servingRouter) UpdateStreamState(state *model.StreamStateRecord) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.served[state.StreamConfiguration.Id] = true
}

func (sr *servingRouter) RemoveStream(sid string) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	delete(sr.served, sid)
}

func (sr *servingRouter) serves(sid string) bool {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	return sr.served[sid]
}

func (sr *servingRouter) StreamIds() []string {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	ids := make([]string, 0, len(sr.served))
	for sid := range sr.served {
		ids = append(ids, sid)
	}
	return ids
}

func (sr *servingRouter) SyncStreamTable(ctx context.Context) (map[string]model.StreamStateRecord, error) {
	sr.mu.Lock()
	sr.syncs++
	sr.mu.Unlock()
	known := sr.StreamIds()
	states, err := sr.app.StreamService.LoadStateMap(ctx)
	if err != nil {
		return nil, err
	}
	for _, state := range states {
		sr.UpdateStreamState(&state)
	}
	for _, sid := range known {
		if _, ok := states[sid]; !ok {
			sr.RemoveStream(sid)
		}
	}
	return states, nil
}

func (sr *servingRouter) BroadcastStreamChanged(string) {}

func (sr *servingRouter) AwaitPushStopped(ctx context.Context, _ string) bool {
	if sr.runnerStopped == nil {
		return true
	}
	select {
	case <-sr.runnerStopped:
		return true
	case <-ctx.Done():
		return false
	}
}

var _ eventRouter.StreamTable = (*servingRouter)(nil)

type servingApp struct {
	*statusRefreshApp
	router *servingRouter
}

func (a *servingApp) GetEventRouter() eventRouter.EventRouter { return a.router }

// gatedDeleteStreamDAO holds a stream delete until the test opens the gate,
// and says when a delete has started.
type gatedDeleteStreamDAO struct {
	interfaces.StreamDAO
	entered chan struct{}
	gate    chan struct{}
}

func (d *gatedDeleteStreamDAO) Delete(ctx context.Context, id string) error {
	close(d.entered)
	<-d.gate
	return d.StreamDAO.Delete(ctx, id)
}

// #350 review: a stream delete stops the router's stream and then deletes it
// from the store. A stream-table sync that runs between the two used to read
// the stream from the store and serve it again, writing pending markers for a
// deleted stream until the next periodic sync. The delete and the sync are
// serialized, so once both are done the deleted stream is not served.
func TestStreamDelete_ConcurrentSyncDoesNotReAddTheStream(t *testing.T) {
	base := newStatusRefreshApp(t)
	dao := &gatedDeleteStreamDAO{StreamDAO: memory.NewStreamDAO(), entered: make(chan struct{}), gate: make(chan struct{})}
	base.withStreamDAO(dao)
	sr := &servingRouter{app: base.SignalsApplication, served: map[string]bool{}}
	base.EventRouter = sr
	app := &servingApp{statusRefreshApp: base, router: sr}
	persistStatusPlain(t, base, model.StreamStateEnabled, "")
	sr.UpdateStreamState(statusPlainRecord("DEFAULT", "", ""))
	bearer := base.adminBearer(t)

	deleted := make(chan int, 1)
	go func() {
		req := httptest.NewRequest(http.MethodDelete, "/stream?stream_id="+statusPlainSid, nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		rr := httptest.NewRecorder()
		StreamDeleteHandler(app, rr, req)
		deleted <- rr.Code
	}()
	<-dao.entered // the router has stopped the stream; the store delete is held

	synced := make(chan struct{})
	go func() {
		defer close(synced)
		base.syncStreamTable()
	}()
	select {
	case <-synced:
	case <-time.After(200 * time.Millisecond):
	}
	close(dao.gate)
	require.Equal(t, http.StatusNoContent, <-deleted)
	<-synced

	assert.False(t, sr.serves(statusPlainSid), "the deleted stream is not served again")
}

// A status change and a stream update are announced to the other nodes too,
// so a pause or disable stops the stream's runner on whichever node holds its
// lease, and a re-enable or config change is served cluster-wide without
// waiting for the periodic sync. A status request that changes nothing is not
// announced.
func TestStreamStatusAndUpdate_AnnounceToPeers(t *testing.T) {
	app := newTableApp(t)
	persistStatusPlain(t, app.statusRefreshApp, model.StreamStateEnabled, "")
	bearer := app.adminBearer(t)

	postStatus := func(status string) {
		body, err := json.Marshal(model.UpdateStreamStatus{Status: status, Reason: "operator"})
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/status?stream_id="+statusPlainSid, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+bearer)
		rr := httptest.NewRecorder()
		UpdateStatusHandler(app, rr, req)
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	}

	postStatus(model.StreamStatePause)
	assert.Equal(t, []string{statusPlainSid}, app.router.broadcastSids(), "a pause is announced")
	postStatus(model.StreamStatePause)
	assert.Len(t, app.router.broadcastSids(), 1, "an unchanged status is not announced")
	postStatus(model.StreamStateEnabled)
	assert.Len(t, app.router.broadcastSids(), 2, "a re-enable is announced")

	body, err := json.Marshal(map[string]any{"stream_id": statusPlainSid, "description": "updated"})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPatch, "/stream", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+bearer)
	rr := httptest.NewRecorder()
	StreamUpdateHandler(app, rr, req)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, []string{statusPlainSid, statusPlainSid, statusPlainSid}, app.router.broadcastSids(), "an update is announced")
}

// A stream-changed call whose store read fails answers 503, not 202: the 202
// is the ack the peer's broadcast waits for, so it must mean this node has
// reconciled the stream. The peer then retries. Nothing is removed.
func TestStreamChanged_StoreReadErrorIsNotAcked(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", "test-secret")
	base := newStatusRefreshApp(t)
	dao := &failingStreamDAO{StreamDAO: memory.NewStreamDAO()}
	base.withStreamDAO(dao)
	sr := &servingRouter{app: base.SignalsApplication, served: map[string]bool{"sid-1": true}}
	base.EventRouter = sr

	dao.failFind = true
	w := httptest.NewRecorder()
	base.StreamChanged(w, streamChangedReq("test-secret", "sid-1"))
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.True(t, sr.serves("sid-1"), "a failed read removes nothing")
}

// A stream-changed call that holds a stream (a pause, a disable or a delete)
// answers 202 only once this node's push runner for it has stopped, so the
// peer's ack means nothing more is sent; a runner still running after
// streamChangedStopTimeout gets 503, and the peer retries. An enabled stream
// is acked without waiting.
func TestStreamChanged_HeldStreamAckedAfterTheRunnerStops(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", "test-secret")
	base := newStatusRefreshApp(t)
	sr := &servingRouter{app: base.SignalsApplication, served: map[string]bool{}, runnerStopped: make(chan struct{})}
	base.EventRouter = sr

	persistStatusPlain(t, base, model.StreamStateEnabled, "")
	w := httptest.NewRecorder()
	base.StreamChanged(w, streamChangedReq("test-secret", statusPlainSid))
	assert.Equal(t, http.StatusAccepted, w.Code, "an enabled stream does not wait for a runner")

	persistStatusPlain(t, base, model.StreamStatePause, "operator hold")
	answered := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		base.StreamChanged(w, streamChangedReq("test-secret", statusPlainSid))
		answered <- w.Code
	}()
	select {
	case code := <-answered:
		t.Fatalf("answered %d before the runner stopped", code)
	case <-time.After(200 * time.Millisecond):
	}
	close(sr.runnerStopped)
	select {
	case code := <-answered:
		assert.Equal(t, http.StatusAccepted, code)
	case <-time.After(2 * time.Second):
		t.Fatal("no answer after the runner stopped")
	}
}

// A held stream whose runner does not stop within streamChangedStopTimeout
// is not acked: the call answers 503 and the peer retries.
func TestStreamChanged_HeldStreamRunnerNotStoppedIsNotAcked(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", "test-secret")
	base := newStatusRefreshApp(t)
	sr := &servingRouter{app: base.SignalsApplication, served: map[string]bool{}, runnerStopped: make(chan struct{})}
	base.EventRouter = sr
	persistStatusPlain(t, base, model.StreamStateDisable, "operator hold")

	start := time.Now()
	w := httptest.NewRecorder()
	base.StreamChanged(w, streamChangedReq("test-secret", statusPlainSid))
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.GreaterOrEqual(t, time.Since(start), streamChangedStopTimeout)
}
