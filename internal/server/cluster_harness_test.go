package server

// cluster_harness_test.go — the two-node cluster harness (#358, spec #112).
//
// Two full goSignals servers share one Mongo replica set (MONGO_URL), each with
// its own node id, and reach each other through the in-process PeerTransport
// instead of HTTP. The harness skips when MONGO_URL is unset, so `go test ./...`
// stays fast on a laptop. Harness tests of later #112 slices go in this
// package and build on clusterHarness.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/i2-open/i2goSignals/internal/dao/pendingref"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"net"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/internal/eventRouter/peer"
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
)

const (
	harnessIssuer  = "https://harness.example.com"
	harnessProject = "harness-project"
	harnessSecret  = "harness-cluster-secret"
)

// harnessNode is one live server of the harness.
type harnessNode struct {
	*sstpNode
	id  string
	dao *countingEventDAO // the node's EventService writes through it
}

// clusterHarness is two (or more) goSignals nodes on one Mongo database,
// joined by an in-process PeerTransport.
type clusterHarness struct {
	t        *testing.T
	url      string
	db       string
	admin    *dbProviders.Persistence // setup and cleanup only; runs no router
	inproc   *peer.InProcess
	dropping atomic.Bool  // when true, every wake is lost
	dropped  atomic.Int64 // wakes lost so far
	mu       sync.Mutex
	nodes    map[string]*harnessNode

	claimMu       sync.Mutex
	claimCalls    map[string]int    // Claim calls by calling node
	claimInflight map[string]int    // Claim calls under way, by "caller>owner"
	claimLog      []harnessClaimEnd // every finished Claim call
}

// harnessClaimEnd is one finished peer Claim call.
type harnessClaimEnd struct {
	caller, owner string
	refs          int
	err           error
	at            time.Time
}

// newClusterHarness opens the shared database and installs the harness's
// PeerTransport seam. It skips the test when MONGO_URL is unset or Mongo is
// unreachable. Nodes are started with start.
func newClusterHarness(t *testing.T) *clusterHarness {
	t.Helper()
	url := os.Getenv("MONGO_URL")
	if url == "" {
		t.Skip("two-node cluster harness needs MONGO_URL (a Mongo replica set); skipping")
	}
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", harnessSecret)
	t.Setenv("I2SIG_STORE_MONGO_FALLBACK_MEM", "FALSE")
	t.Setenv("I2SIG_SHUTDOWN_DRAIN", "0")
	// The periodic sweep that recovers a lost wake runs every second.
	t.Setenv("I2SIG_PUSH_BACKFILL_INTERVAL", "1")

	h := &clusterHarness{
		t:      t,
		url:    url,
		db:     fmt.Sprintf("cluster_harness_%d", time.Now().UnixNano()),
		inproc: peer.NewInProcess(),
		nodes:  map[string]*harnessNode{},
	}
	h.admin = h.open("admin")
	if err := h.admin.Storage.Check(); err != nil {
		_ = h.admin.Storage.Close()
		t.Skipf("mongo unreachable (%v); set MONGO_URL or start the dev stack", err)
	}
	ctx := context.Background()
	require.NoError(t, h.admin.KeyService.InitializeTokenKey(ctx, "DEFAULT"))
	_, err := h.admin.KeyService.CreateKeyPair(ctx, harnessIssuer, "sig", "")
	require.NoError(t, err)
	// The SSTP e2e bootstrap issuer, for pairs built with symmetricBootstrap.
	_, err = h.admin.KeyService.CreateKeyPair(ctx, "https://e2e.example.com", "sig", "")
	require.NoError(t, err)

	t.Cleanup(func() {
		h.mu.Lock()
		ids := make([]string, 0, len(h.nodes))
		for id := range h.nodes {
			ids = append(ids, id)
		}
		h.mu.Unlock()
		for _, id := range ids {
			h.stop(id)
		}
		_ = h.admin.Storage.ResetDb(false)
		_ = h.admin.Storage.Close()
	})
	return h
}

// appOptions wires a node into the harness: the router runs on the
// in-process PeerTransport and registers with it, and the SSTP dialer takes
// over a lease in seconds, not the production 25 second re-acquire spin.
func (h *clusterHarness) appOptions() []AppOption {
	return []AppOption{
		WithPeerTransport(func(nodeID string) peer.PeerTransport {
			return &droppingTransport{inner: h.inproc.For(nodeID), h: h, self: nodeID}
		}),
		WithRouterHook(func(nodeID string, r eventRouter.EventRouter) {
			if handler, ok := r.(peer.Handler); ok {
				h.inproc.Register(nodeID, handler)
			}
		}),
		WithSstpDialerTuning(func(cfg *SstpDialerConfig) {
			cfg.LeaseDuration = 3 * time.Second
			cfg.HeartbeatInterval = 500 * time.Millisecond
			cfg.HeartbeatRetryDelay = 100 * time.Millisecond
		}),
	}
}

// open opens a persistence on the shared database with its own change-stream
// resume file.
func (h *clusterHarness) open(name string) *dbProviders.Persistence {
	h.t.Helper()
	h.t.Setenv("I2SIG_STORE_MONGO_RESUME_FILE", filepath.Join(h.t.TempDir(), name+"_resume.json"))
	p, err := dbProviders.OpenPersistence(h.url, h.db)
	if err != nil {
		h.t.Skipf("mongo unreachable (%v); set MONGO_URL or start the dev stack", err)
	}
	return p
}

// start boots node id on a loopback listener and waits until it serves.
func (h *clusterHarness) start(id string) *harnessNode {
	h.t.Helper()
	p := h.open(id)
	dao := &countingEventDAO{EventDAO: p.EventDAO}
	p.EventService = services.NewEventService(dao)
	h.t.Setenv("I2SIG_CLUSTER_NODE_ID", id)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(h.t, err)
	baseURL := "http://" + listener.Addr().String()
	app := StartServer(listener.Addr().String(), p, baseURL+"/", h.appOptions()...)
	go func() { _ = app.Server.Serve(listener) }()
	waitServing(h.t, baseURL)

	n := &harnessNode{sstpNode: &sstpNode{app: app, persistence: p, baseURL: baseURL, projectId: harnessProject}, id: id, dao: dao}
	h.mu.Lock()
	h.nodes[id] = n
	h.mu.Unlock()
	return n
}

// stop takes node id out of the cluster the way a crashed or drained node
// leaves: unreachable to its peers, then shut down.
func (h *clusterHarness) stop(id string) {
	h.mu.Lock()
	n, ok := h.nodes[id]
	delete(h.nodes, id)
	h.mu.Unlock()
	if !ok {
		return
	}
	h.inproc.Unregister(id)
	n.app.Shutdown()
}

// leaseOwner waits for resource to have an owner and returns it.
func (h *clusterHarness) leaseOwner(resource string, timeout time.Duration) string {
	h.t.Helper()
	var owner string
	require.Eventually(h.t, func() bool {
		o, until, _, err := h.admin.Coordinator.GetLeaseOwner(resource)
		if err != nil || o == "" || time.Now().After(until) {
			return false
		}
		owner = o
		return true
	}, timeout, 50*time.Millisecond, "no node took the lease %s", resource)
	return owner
}

// pendingFor returns the stream's undelivered JTIs from the shared store.
func (h *clusterHarness) pendingFor(sid string) []string {
	ids, _ := h.admin.EventService.GetEventIds(context.Background(), sid, model.PollParameters{MaxEvents: 1000, ReturnImmediately: true})
	return pendingref.RefJtis(ids)
}

// persistStream stores a stream and loads it into every running node's router.
func (h *clusterHarness) persistStream(rec *model.StreamStateRecord) {
	h.t.Helper()
	ctx := context.Background()
	oid, err := bson.ObjectIDFromHex(rec.StreamConfiguration.Id)
	require.NoError(h.t, err, "stream ids are ObjectID hex")
	rec.Id = oid
	require.NoError(h.t, h.admin.StreamService.PersistStreamStateRecord(ctx, rec))
	stored, err := h.admin.StreamService.GetStreamState(ctx, rec.StreamConfiguration.Id)
	require.NoError(h.t, err)
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, n := range h.nodes {
		n.app.EventRouter.UpdateStreamState(stored)
	}
}

// droppingTransport is the in-process transport with a switch that loses
// every wake, so a test can prove correctness does not depend on wakes.
type droppingTransport struct {
	inner peer.PeerTransport
	h     *clusterHarness
	self  string
}

func (d *droppingTransport) Wake(ctx context.Context, owner string, msg peer.WakeMessage) error {
	if d.h.dropping.Load() {
		d.h.dropped.Add(1)
		return nil
	}
	return d.inner.Wake(ctx, owner, msg)
}

// Claim counts the call for its caller and records when it ends. The
// in-process call returns when the owner's HandleClaim does.
func (d *droppingTransport) Claim(ctx context.Context, owner string, req peer.ClaimRequest) (peer.ClaimResponse, error) {
	key := d.self + ">" + owner
	d.h.claimMu.Lock()
	if d.h.claimCalls == nil {
		d.h.claimCalls = map[string]int{}
		d.h.claimInflight = map[string]int{}
	}
	d.h.claimCalls[d.self]++
	d.h.claimInflight[key]++
	d.h.claimMu.Unlock()
	resp, err := d.inner.Claim(ctx, owner, req)
	d.h.claimMu.Lock()
	d.h.claimInflight[key]--
	d.h.claimLog = append(d.h.claimLog, harnessClaimEnd{caller: d.self, owner: owner, refs: len(resp.Refs), err: err, at: time.Now()})
	d.h.claimMu.Unlock()
	return resp, err
}

// claimsBy is the number of Claim calls node caller has made.
func (h *clusterHarness) claimsBy(caller string) int {
	h.claimMu.Lock()
	defer h.claimMu.Unlock()
	return h.claimCalls[caller]
}

// inflight is the number of Claim calls from caller to owner under way.
func (h *clusterHarness) inflight(caller, owner string) int {
	h.claimMu.Lock()
	defer h.claimMu.Unlock()
	return h.claimInflight[caller+">"+owner]
}

// claimEnds returns the finished Claim calls from caller to owner.
func (h *clusterHarness) claimEnds(caller, owner string) []harnessClaimEnd {
	h.claimMu.Lock()
	defer h.claimMu.Unlock()
	var out []harnessClaimEnd
	for _, e := range h.claimLog {
		if e.caller == caller && e.owner == owner {
			out = append(out, e)
		}
	}
	return out
}

// countingEventDAO counts one node's event-store calls: the request-path
// writes, the SET body reads and the WatchPending callbacks per stream. The
// background maintenance writes (SweepExpired, MigrateLegacyDeliveries) are
// not counted.
type countingEventDAO struct {
	interfaces.EventDAO
	writes    atomic.Int64
	bodyReads atomic.Int64
	watched   sync.Map // stream id -> *atomic.Int64
}

func (d *countingEventDAO) wrote() { d.writes.Add(1) }

// watchedFor is the number of WatchPending callbacks for sid on this node.
func (d *countingEventDAO) watchedFor(sid string) int64 {
	if v, ok := d.watched.Load(sid); ok {
		return v.(*atomic.Int64).Load()
	}
	return 0
}

func (d *countingEventDAO) Insert(ctx context.Context, record *model.EventRecord) error {
	d.wrote()
	return d.EventDAO.Insert(ctx, record)
}

func (d *countingEventDAO) InsertMany(ctx context.Context, records []*model.EventRecord) ([]error, error) {
	d.wrote()
	return d.EventDAO.InsertMany(ctx, records)
}

func (d *countingEventDAO) InsertWithPending(ctx context.Context, records []*model.EventRecord, pending map[string][]interfaces.PendingRef) ([]error, error) {
	d.wrote()
	return d.EventDAO.InsertWithPending(ctx, records, pending)
}

func (d *countingEventDAO) AddPending(ctx context.Context, ref interfaces.PendingRef, streamID string) error {
	d.wrote()
	return d.EventDAO.AddPending(ctx, ref, streamID)
}

func (d *countingEventDAO) AddPendingMany(ctx context.Context, refs []interfaces.PendingRef, streamID string) error {
	d.wrote()
	return d.EventDAO.AddPendingMany(ctx, refs, streamID)
}

func (d *countingEventDAO) EnsurePending(ctx context.Context, jti string, ackJtis map[string]string) ([]string, error) {
	d.wrote()
	return d.EventDAO.EnsurePending(ctx, jti, ackJtis)
}

func (d *countingEventDAO) RemovePendingMany(ctx context.Context, jtis []string, streamID string) ([]interfaces.DeliverableEvent, error) {
	d.wrote()
	return d.EventDAO.RemovePendingMany(ctx, jtis, streamID)
}

func (d *countingEventDAO) ClearPendingForStream(ctx context.Context, streamID string) (int64, error) {
	d.wrote()
	return d.EventDAO.ClearPendingForStream(ctx, streamID)
}

func (d *countingEventDAO) Ack(ctx context.Context, batch interfaces.AckBatch) (int64, error) {
	d.wrote()
	return d.EventDAO.Ack(ctx, batch)
}

func (d *countingEventDAO) ResetPendingAckJti(ctx context.Context, streamID string) (int64, error) {
	d.wrote()
	return d.EventDAO.ResetPendingAckJti(ctx, streamID)
}

func (d *countingEventDAO) RemoveDelivered(ctx context.Context, jti string, streamID string) error {
	d.wrote()
	return d.EventDAO.RemoveDelivered(ctx, jti, streamID)
}

func (d *countingEventDAO) DeleteBodyIfUnreferenced(ctx context.Context, jti string) (bool, error) {
	d.wrote()
	return d.EventDAO.DeleteBodyIfUnreferenced(ctx, jti)
}

func (d *countingEventDAO) FindByJTI(ctx context.Context, jti string) (*model.EventRecord, error) {
	d.bodyReads.Add(1)
	return d.EventDAO.FindByJTI(ctx, jti)
}

func (d *countingEventDAO) FindByJTIs(ctx context.Context, jtis []string) ([]*model.EventRecord, error) {
	d.bodyReads.Add(1)
	return d.EventDAO.FindByJTIs(ctx, jtis)
}

func (d *countingEventDAO) WatchPending(ctx context.Context, callback func(ref interfaces.PendingRef, streamID string)) error {
	return d.EventDAO.WatchPending(ctx, func(ref interfaces.PendingRef, streamID string) {
		v, _ := d.watched.LoadOrStore(streamID, new(atomic.Int64))
		v.(*atomic.Int64).Add(1)
		callback(ref, streamID)
	})
}

func waitServing(t *testing.T, baseURL string) {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	tlsSupport.CheckCaInstalled(client)
	require.Eventually(t, func() bool {
		resp, err := client.Get(baseURL + "/.well-known/ssf-configuration")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 10*time.Second, 50*time.Millisecond, "server %s did not come up", baseURL)
}

// setJti reads the jti claim of a compact JWS without verifying it.
func setJti(token string) string {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) < 2 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Jti string `json:"jti"`
	}
	_ = json.Unmarshal(raw, &claims)
	return claims.Jti
}

// pushReceiver is an RFC 8935 receiver that records the JTIs pushed to it.
type pushReceiver struct {
	srv  *httptest.Server
	mu   sync.Mutex
	seen map[string]int
}

func newPushReceiver(t *testing.T) *pushReceiver {
	pr := &pushReceiver{seen: map[string]int{}}
	pr.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(strings.Builder)
		_, _ = fmt.Fprint(buf, readAll(r))
		if jti := setJti(buf.String()); jti != "" {
			pr.mu.Lock()
			pr.seen[jti]++
			pr.mu.Unlock()
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(pr.srv.Close)
	return pr
}

func readAll(r *http.Request) string {
	var sb strings.Builder
	b := make([]byte, 4096)
	for {
		n, err := r.Body.Read(b)
		sb.Write(b[:n])
		if err != nil {
			return sb.String()
		}
	}
}

func (pr *pushReceiver) has(jti string) bool {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	return pr.seen[jti] > 0
}

// A wake lost between nodes is harmless: an event ingested on the node that
// does not own a push stream's lease, with every wake dropped, still reaches
// the receiver through the owner's periodic sweep.
func TestClusterHarness_LostWakeRecoveredBySweep(t *testing.T) {
	h := newClusterHarness(t)
	a := h.start("node-a")
	b := h.start("node-b")
	rcv := newPushReceiver(t)

	sid := model.NewRecordId().Hex()
	h.persistStream(&model.StreamStateRecord{
		ProjectId: harnessProject,
		StreamConfiguration: model.StreamConfiguration{
			Id:               sid,
			Iss:              harnessIssuer,
			Aud:              []string{"https://receiver.example.com"},
			RouteMode:        model.RouteModePublish,
			TxAllowPlaintext: true,
			Delivery: &model.OneOfStreamConfigurationDelivery{PushTransmitMethod: &model.PushTransmitMethod{
				Method: model.DeliveryPush, EndpointUrl: rcv.srv.URL + "/events"}},
		},
		Status: model.StreamStateEnabled,
	})

	owner := h.leaseOwner(cluster.PushTransmitter.Resource(sid), 20*time.Second)
	ingest := a
	if owner == a.id {
		ingest = b
	}
	require.NotEqual(t, owner, ingest.id)

	h.dropping.Store(true)
	ev, err := ingest.app.EventRouter.GenerateVerifyEvent(sid, "lost-wake")
	require.NoError(t, err)
	require.NotNil(t, ev)

	// The receiver sees the re-signed SET under its derived jti (#363).
	require.Eventually(t, func() bool { return rcv.has(goSet.DeriveCopyJti(sid, ev.Jti)) }, 20*time.Second, 100*time.Millisecond,
		"the SET ingested on %s never reached the receiver through owner %s's sweep", ingest.id, owner)
	assert.Positive(t, h.dropped.Load(), "the owner was sent a wake, and it was lost")
	require.Eventually(t, func() bool { return len(h.pendingFor(sid)) == 0 }, 10*time.Second, 100*time.Millisecond,
		"the delivered SET is acknowledged")
}

// A poll transmitter with ingest on node A and the poll receiver on node B:
// every SET is delivered exactly once and acknowledged: node-b serves the poll
// through the poll-transmitter lease owner's one queue (#365).
func TestClusterHarness_PollIngestOnAReceiverOnB(t *testing.T) {
	h := newClusterHarness(t)
	a := h.start("node-a")
	b := h.start("node-b")

	sid := model.NewRecordId().Hex()
	h.persistStream(&model.StreamStateRecord{
		ProjectId: harnessProject,
		StreamConfiguration: model.StreamConfiguration{
			Id:        sid,
			Iss:       harnessIssuer,
			Aud:       []string{"https://receiver.example.com"},
			RouteMode: model.RouteModePublish,
			Delivery:  &model.OneOfStreamConfigurationDelivery{PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll}},
		},
		Status: model.StreamStateEnabled,
	})

	const n = 20
	want := map[string]bool{}
	for i := 0; i < n; i++ {
		ev, err := a.app.EventRouter.GenerateVerifyEvent(sid, fmt.Sprintf("poll-%d", i))
		require.NoError(t, err)
		want[goSet.DeriveCopyJti(sid, ev.Jti)] = true // the re-signed SET's jti (#363)
	}

	seen := map[string]bool{}
	dups := map[string]int{}
	var acks []string
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		sets, _, status := b.app.EventRouter.PollStreamHandler(context.Background(), sid, model.PollParameters{MaxEvents: 10, ReturnImmediately: true, Acks: acks})
		require.Equal(t, http.StatusOK, status)
		acks = acks[:0]
		for jti := range sets {
			if seen[jti] {
				dups[jti]++
			}
			seen[jti] = true
			acks = append(acks, jti)
		}
		if len(acks) == 0 && allSeen(want, seen) && len(h.pendingFor(sid)) == 0 {
			break
		}
		if len(sets) == 0 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	for jti := range want {
		assert.Truef(t, seen[jti], "SET %s ingested on node-a was polled from node-b", jti)
	}
	assert.Empty(t, h.pendingFor(sid), "every SET polled from node-b is acknowledged")
	assert.Empty(t, dups, "no SET is delivered twice")
}

// An SSTP responder pair with ingest on node A and the dialing peer connected
// to node B: every SET is delivered exactly once and acknowledged, through the
// acceptor lease owner's one queue (#365).
func TestClusterHarness_SstpIngestOnAPeerOnB(t *testing.T) {
	t.Setenv("I2SIG_POLL_DEFAULT_TIMEOUT", "2")
	h := newClusterHarness(t)
	a := h.start("node-a")

	// A responder pair with no peer alias is created locally only; this test
	// is the dialing peer.
	boot := symmetricBootstrap("", "https://e2e.example.com", []string{"https://aud.example.com"})
	body, err := json.Marshal(boot)
	require.NoError(t, err)
	status, respBody := a.httpDo(t, http.MethodPost, "/stream", a.adminBearer(t), body)
	require.Equalf(t, http.StatusCreated, status, "pair create: %s", respBody)
	var rec model.StreamStateRecord
	require.NoError(t, json.Unmarshal(respBody, &rec))
	txSid := rec.StreamConfiguration.Id
	_, err = h.admin.KeyService.CreateKeyPair(context.Background(), rec.StreamConfiguration.Iss, "sig", harnessProject)
	require.NoError(t, err)

	// Node B joins after the pair exists and loads it from the shared store.
	b := h.start("node-b")

	const n = 20
	want := map[string]bool{}
	for i := 0; i < n; i++ {
		ev, err := a.app.EventRouter.GenerateVerifyEvent(txSid, fmt.Sprintf("sstp-%d", i))
		require.NoError(t, err)
		want[rec.AckJti(ev.Jti)] = true // the jti the peer sees (#363)
	}

	seen := map[string]bool{}
	dups := map[string]int{}
	var acks []string
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		ret := true
		msg := goSetSstp.Message{Sets: map[string]string{}, Ack: acks, ReturnImmediately: &ret}
		raw, err := json.Marshal(msg)
		require.NoError(t, err)
		st, out := b.sstpPostRaw(t, "/sstp/"+rec.PairId, rec.SstpMethod.AuthorizationHeader, raw)
		require.Equalf(t, http.StatusOK, st, "SSTP cycle on node-b: %s", out)
		var resp goSetSstp.Message
		require.NoError(t, json.Unmarshal(out, &resp))
		acks = nil
		for jti := range resp.Sets {
			if seen[jti] {
				dups[jti]++
			}
			seen[jti] = true
			acks = append(acks, jti)
		}
		if len(acks) == 0 && allSeen(want, seen) && len(h.pendingFor(txSid)) == 0 {
			break
		}
		if len(resp.Sets) == 0 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	for jti := range want {
		assert.Truef(t, seen[jti], "SET %s ingested on node-a was returned to the peer on node-b", jti)
	}
	assert.Empty(t, h.pendingFor(txSid), "every SET returned on node-b is acknowledged")
	assert.Empty(t, dups, "no SET is delivered twice")
}

func allSeen(want, seen map[string]bool) bool {
	for jti := range want {
		if !seen[jti] {
			return false
		}
	}
	return true
}

// runLeaseTakeoverOnHarness is TestLeaseTakeover_NewOwnerNoDuplicateInbound
// (sstp_pair_e2e_test.go) on the harness. Cluster nodes node-a and node-b hold
// the initiator side of an SSTP pair whose responder is a third, standalone
// server. node-a owns the sstp-client lease and receives the first SET; when
// node-a stops, node-b takes the lease over and receives the second. Every SET
// is acknowledged at the responder and stored once in the cluster.
func runLeaseTakeoverOnHarness(t *testing.T) {
	// The responder holds each SSTP long-poll this long; shutdown waits on it.
	t.Setenv("I2SIG_POLL_DEFAULT_TIMEOUT", "2")
	// The responder's leased queue claims each SET it sends (#365); one the
	// initiator drops unacked comes back after the claim TTL, not on the
	// next request.
	t.Setenv("I2SIG_POLL_CLAIM_TTL", "1s")
	h := newClusterHarness(t)
	a := h.start("node-a")

	// The responder: a standalone memory-provider server outside the cluster.
	t.Setenv("I2SIG_CLUSTER_NODE_ID", "responder")
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	rp, err := dbProviders.OpenPersistence("memorydb:", "harness-responder")
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, rp.KeyService.InitializeTokenKey(ctx, "DEFAULT"))
	_, err = rp.KeyService.CreateKeyPair(ctx, "https://e2e.example.com", "sig", "")
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	rURL := "http://" + listener.Addr().String()
	rApp := StartServer(listener.Addr().String(), rp, rURL+"/", h.appOptions()...)
	go func() { _ = rApp.Server.Serve(listener) }()
	t.Cleanup(rApp.Shutdown)
	waitServing(t, rURL)
	responder := &sstpNode{app: rApp, persistence: rp, baseURL: rURL, projectId: "e2e-project"}

	// Pair create on the responder cascades the initiator mirror to node-a.
	responder.registerPeer(t, "cluster", a.sstpNode)
	// The cluster verifies the responder's SETs against the responder's
	// published JWKS, not a key of its own for the same issuer name.
	boot := symmetricBootstrap("cluster", "https://e2e.example.com", []string{"https://aud.example.com"})
	boot.Primary.IssJwksUrl = rURL + "/jwks/" + neturl.PathEscape("https://e2e.example.com")
	body, err := json.Marshal(boot)
	require.NoError(t, err)
	status, respBody := responder.httpDo(t, http.MethodPost, "/stream", responder.adminBearer(t), body)
	require.Equalf(t, http.StatusCreated, status, "pair create: %s", respBody)
	var rec model.StreamStateRecord
	require.NoError(t, json.Unmarshal(respBody, &rec))
	_, err = rp.KeyService.CreateKeyPair(ctx, rec.StreamConfiguration.Iss, "sig", responder.projectId)
	require.NoError(t, err)
	require.NotEmpty(t, rec.SstpMethod.PeerPairId, "the cascade names the initiator pair")
	resource := cluster.SstpClient.Resource(rec.SstpMethod.PeerPairId)

	require.Equal(t, "node-a", h.leaseOwner(resource, 20*time.Second), "node-a, the only node, dials")
	// node-b joins after the pair exists and waits for the lease.
	h.start("node-b")

	deliver := func(state string) string {
		ev, err := rApp.EventRouter.GenerateVerifyEvent(rec.StreamConfiguration.Id, state)
		require.NoError(t, err)
		// The cluster stores the responder's re-signed SET under its derived jti (#363).
		rcvJti := rec.AckJti(ev.Jti)
		require.Eventually(t, func() bool {
			return h.admin.EventService.GetEventRecord(ctx, rcvJti) != nil
		}, 20*time.Second, 100*time.Millisecond, "SET %s reached the cluster", state)
		require.Eventually(t, func() bool {
			ids, _ := rp.EventService.GetEventIds(ctx, rec.StreamConfiguration.Id, model.PollParameters{MaxEvents: 100, ReturnImmediately: true})
			return len(ids) == 0
		}, 20*time.Second, 100*time.Millisecond, "SET %s acknowledged at the responder", state)
		return rcvJti
	}

	first := deliver("before-takeover")
	h.stop("node-a")
	require.Eventually(t, func() bool {
		o, until, _, err := h.admin.Coordinator.GetLeaseOwner(resource)
		return err == nil && o == "node-b" && time.Now().Before(until)
	}, 20*time.Second, 100*time.Millisecond, "node-b took the sstp-client lease over")
	second := deliver("after-takeover")

	recs := h.admin.EventService.GetEventRecords(ctx, []string{first, second})
	assert.Len(t, recs, 2, "each inbound SET is stored once in the cluster")
}

// harnessPollStream stores an enabled RFC 8936 poll transmitter and returns
// its id.
func (h *clusterHarness) harnessPollStream() string {
	sid := model.NewRecordId().Hex()
	h.persistStream(&model.StreamStateRecord{
		ProjectId: harnessProject,
		StreamConfiguration: model.StreamConfiguration{
			Id:        sid,
			Iss:       harnessIssuer,
			Aud:       []string{"https://receiver.example.com"},
			RouteMode: model.RouteModePublish,
			Delivery:  &model.OneOfStreamConfigurationDelivery{PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll}},
		},
		Status: model.StreamStateEnabled,
	})
	return sid
}

// pollOwner has first serve a poll on sid, which takes the poll-transmitter
// lease when no node holds it, and returns the lease owner and the other node.
func (h *clusterHarness) pollOwner(first, second *harnessNode, sid string) (owner, other *harnessNode) {
	h.t.Helper()
	_, _, status := first.app.EventRouter.PollStreamHandler(context.Background(), sid, model.PollParameters{MaxEvents: 1, ReturnImmediately: true})
	require.Equal(h.t, http.StatusOK, status)
	if h.leaseOwner(cluster.PollTransmitter.Resource(sid), 20*time.Second) == first.id {
		return first, second
	}
	return second, first
}

// holdsQueue reports whether node n holds a queue for sid.
func holdsQueue(n *harnessNode, sid string) bool {
	return n.app.EventRouter.(interface{ HoldsQueue(string) bool }).HoldsQueue(sid)
}

// The WatchPending callback offers a reference only to a queue this node
// holds (#365): on the poll-transmitter lease's non-owner the callback fires
// for the stream and creates no queue, and the owner serves the SET.
func TestClusterHarness_WatchPendingNonOwnerDrops(t *testing.T) {
	t.Setenv("I2SIG_STORE_MONGO_WATCH_ENABLED", "true")
	h := newClusterHarness(t)
	a := h.start("node-a")
	b := h.start("node-b")
	sid := h.harnessPollStream()
	owner, other := h.pollOwner(a, b, sid)
	require.False(t, holdsQueue(other, sid), "the non-owner holds no queue before the event")

	ev, err := owner.app.EventRouter.GenerateVerifyEvent(sid, "watched")
	require.NoError(t, err)
	require.Eventually(t, func() bool { return other.dao.watchedFor(sid) > 0 }, 20*time.Second, 50*time.Millisecond,
		"the non-owner's WatchPending callback fires for the stream")
	assert.Never(t, func() bool { return holdsQueue(other, sid) }, time.Second, 50*time.Millisecond,
		"the non-owner's callback drops the reference and creates no queue")

	want := goSet.DeriveCopyJti(sid, ev.Jti)
	require.Eventually(t, func() bool {
		sets, _, status := owner.app.EventRouter.PollStreamHandler(context.Background(), sid, model.PollParameters{MaxEvents: 10, ReturnImmediately: true})
		_, ok := sets[want]
		return status == http.StatusOK && ok
	}, 10*time.Second, 100*time.Millisecond, "the owner serves the SET")
	assert.False(t, holdsQueue(other, sid))
}

// A receiver that disconnects from a non-owner cancels the peer Claim (#365):
// the owner's HandleClaim returns within a second with no references and the
// non-owner has no Claim to that owner in flight.
func TestClusterHarness_DisconnectCancelsClaim(t *testing.T) {
	h := newClusterHarness(t)
	a := h.start("node-a")
	b := h.start("node-b")
	sid := h.harnessPollStream()
	owner, other := h.pollOwner(a, b, sid)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	go func() {
		_, _, status := other.app.EventRouter.PollStreamHandler(ctx, sid, model.PollParameters{MaxEvents: 10, TimeoutSecs: 20})
		done <- status
	}()
	require.Eventually(t, func() bool { return h.inflight(other.id, owner.id) == 1 }, 10*time.Second, 10*time.Millisecond,
		"the non-owner's long poll waits in one Claim on the owner")
	before := len(h.claimEnds(other.id, owner.id))

	cancelled := time.Now()
	cancel()
	require.Eventually(t, func() bool { return len(h.claimEnds(other.id, owner.id)) > before }, time.Second, 10*time.Millisecond,
		"the owner's HandleClaim returns within 1s of the disconnect")
	end := h.claimEnds(other.id, owner.id)[before]
	assert.Less(t, end.at.Sub(cancelled), time.Second)
	assert.Zero(t, end.refs, "the cancelled Claim hands out no references")
	assert.Zero(t, h.inflight(other.id, owner.id), "no Claim to the owner is in flight")
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the poll handler did not return after the disconnect")
	}
}

// A stopped owner gives empty batches until its lease lapses; then the other
// node acquires the lease and serves every unacknowledged SET once more with
// the same JTI (#365). The lease clock of the surviving node is injected, so
// the lapse takes no wall time.
func TestClusterHarness_StoppedOwnerFailover(t *testing.T) {
	// A claim outlives the test, so a SET served again is the new owner's.
	t.Setenv("I2SIG_POLL_CLAIM_TTL", "10m")
	h := newClusterHarness(t)
	a := h.start("node-a")
	b := h.start("node-b")
	sid := h.harnessPollStream()
	owner, other := h.pollOwner(a, b, sid)

	var skew atomic.Int64
	clock, ok := other.persistence.Coordinator.(interface{ SetClock(func() time.Time) })
	require.True(t, ok, "the Mongo coordinator takes an injected clock")
	clock.SetClock(func() time.Time { return time.Now().Add(time.Duration(skew.Load())) })

	const n = 5
	want := map[string]bool{}
	for i := 0; i < n; i++ {
		ev, err := owner.app.EventRouter.GenerateVerifyEvent(sid, fmt.Sprintf("failover-%d", i))
		require.NoError(t, err)
		want[goSet.DeriveCopyJti(sid, ev.Jti)] = true
	}
	poll := func() map[string]string {
		sets, _, status := other.app.EventRouter.PollStreamHandler(context.Background(), sid, model.PollParameters{MaxEvents: 10, ReturnImmediately: true})
		require.Equal(t, http.StatusOK, status)
		return sets
	}
	first := map[string]bool{}
	require.Eventually(t, func() bool {
		for jti := range poll() {
			first[jti] = true
		}
		return len(first) == n
	}, 20*time.Second, 100*time.Millisecond, "the non-owner serves every SET through the owner")
	assert.Equal(t, want, first)

	// The owner stops answering: its peers cannot reach it, and it no longer
	// renews in the survivor's view of time once the clock moves.
	h.inproc.Unregister(owner.id)
	for i := 0; i < 3; i++ {
		assert.Empty(t, poll(), "an unreachable owner whose lease is live gives an empty batch")
	}

	skew.Store(int64(31 * time.Second)) // past the 30s lease TTL
	again := map[string]int{}
	require.Eventually(t, func() bool {
		for jti := range poll() {
			again[jti]++
		}
		return len(again) == n
	}, 20*time.Second, 100*time.Millisecond, "the survivor acquires the lapsed lease and serves the unacknowledged SETs")
	for jti := range want {
		assert.Equalf(t, 1, again[jti], "SET %s is served once more with the same JTI", jti)
	}
	o, _, _, err := other.persistence.Coordinator.GetLeaseOwner(cluster.PollTransmitter.Resource(sid))
	require.NoError(t, err)
	assert.Equal(t, other.id, o, "the survivor holds the poll-transmitter lease")

	acks := make([]string, 0, n)
	for jti := range again {
		acks = append(acks, jti)
	}
	_, _, status := other.app.EventRouter.PollStreamHandler(context.Background(), sid, model.PollParameters{AckOnly: true, Acks: acks})
	require.Equal(t, http.StatusOK, status)
	require.Eventually(t, func() bool { return len(h.pendingFor(sid)) == 0 }, 10*time.Second, 100*time.Millisecond,
		"the new owner applies the acknowledgements")
}

// A non-owner serves a poll request with one Claim call and no store write:
// it reads the bodies, signs and answers, and an acknowledgement it receives
// is applied by the owner (#365).
func TestClusterHarness_NonOwnerPollOneClaimNoWrite(t *testing.T) {
	h := newClusterHarness(t)
	a := h.start("node-a")
	b := h.start("node-b")
	sid := h.harnessPollStream()
	owner, other := h.pollOwner(a, b, sid)

	const n = 3
	want := map[string]bool{}
	for i := 0; i < n; i++ {
		ev, err := owner.app.EventRouter.GenerateVerifyEvent(sid, fmt.Sprintf("one-claim-%d", i))
		require.NoError(t, err)
		want[goSet.DeriveCopyJti(sid, ev.Jti)] = true
	}

	seen := map[string]bool{}
	writes, reads := other.dao.writes.Load(), other.dao.bodyReads.Load()
	require.Eventually(t, func() bool {
		calls := h.claimsBy(other.id)
		sets, _, status := other.app.EventRouter.PollStreamHandler(context.Background(), sid, model.PollParameters{MaxEvents: 10, ReturnImmediately: true})
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, calls+1, h.claimsBy(other.id), "one Claim call per poll request")
		for jti := range sets {
			seen[jti] = true
		}
		return len(seen) == n
	}, 20*time.Second, 100*time.Millisecond)
	assert.Equal(t, want, seen)
	assert.Equal(t, writes, other.dao.writes.Load(), "the non-owner writes nothing to the store")
	assert.Greater(t, other.dao.bodyReads.Load(), reads, "the non-owner reads the SET bodies")

	acks := make([]string, 0, n)
	for jti := range seen {
		acks = append(acks, jti)
	}
	calls := h.claimsBy(other.id)
	_, _, status := other.app.EventRouter.PollStreamHandler(context.Background(), sid, model.PollParameters{MaxEvents: 10, ReturnImmediately: true, Acks: acks})
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, calls+1, h.claimsBy(other.id), "the acknowledgements travel in the request's one Claim")
	require.Eventually(t, func() bool { return len(h.pendingFor(sid)) == 0 }, 10*time.Second, 100*time.Millisecond,
		"the owner applies the acknowledgements")
	assert.Equal(t, writes, other.dao.writes.Load(), "the non-owner writes nothing to the store")
}

// A non-owner serves an accepted SSTP request with one Claim call and no
// store write, and the owner applies the acknowledgements it carries (#365).
func TestClusterHarness_NonOwnerSstpOneClaimNoWrite(t *testing.T) {
	t.Setenv("I2SIG_POLL_DEFAULT_TIMEOUT", "2")
	h := newClusterHarness(t)
	a := h.start("node-a")

	boot := symmetricBootstrap("", "https://e2e.example.com", []string{"https://aud.example.com"})
	body, err := json.Marshal(boot)
	require.NoError(t, err)
	status, respBody := a.httpDo(t, http.MethodPost, "/stream", a.adminBearer(t), body)
	require.Equalf(t, http.StatusCreated, status, "pair create: %s", respBody)
	var rec model.StreamStateRecord
	require.NoError(t, json.Unmarshal(respBody, &rec))
	txSid := rec.StreamConfiguration.Id
	_, err = h.admin.KeyService.CreateKeyPair(context.Background(), rec.StreamConfiguration.Iss, "sig", harnessProject)
	require.NoError(t, err)
	b := h.start("node-b")

	cycle := func(n *harnessNode, acks []string) map[string]string {
		ret := true
		raw, err := json.Marshal(goSetSstp.Message{Sets: map[string]string{}, Ack: acks, ReturnImmediately: &ret})
		require.NoError(t, err)
		st, out := n.sstpPostRaw(t, "/sstp/"+rec.PairId, rec.SstpMethod.AuthorizationHeader, raw)
		require.Equalf(t, http.StatusOK, st, "SSTP cycle on %s: %s", n.id, out)
		var resp goSetSstp.Message
		require.NoError(t, json.Unmarshal(out, &resp))
		return resp.Sets
	}
	// node-a's first request takes the acceptor lease when no node holds it.
	_ = cycle(a, nil)
	owner, other := a, b
	if h.leaseOwner(cluster.SstpServer.Resource(txSid), 20*time.Second) == b.id {
		owner, other = b, a
	}

	const n = 3
	want := map[string]bool{}
	for i := 0; i < n; i++ {
		ev, err := owner.app.EventRouter.GenerateVerifyEvent(txSid, fmt.Sprintf("sstp-one-claim-%d", i))
		require.NoError(t, err)
		want[rec.AckJti(ev.Jti)] = true
	}

	seen := map[string]bool{}
	writes, reads := other.dao.writes.Load(), other.dao.bodyReads.Load()
	require.Eventually(t, func() bool {
		calls := h.claimsBy(other.id)
		sets := cycle(other, nil)
		require.Equal(t, calls+1, h.claimsBy(other.id), "one Claim call per accepted SSTP request")
		for jti := range sets {
			seen[jti] = true
		}
		return len(seen) == n
	}, 20*time.Second, 100*time.Millisecond)
	assert.Equal(t, want, seen)
	assert.Equal(t, writes, other.dao.writes.Load(), "the non-owner writes nothing to the store")
	assert.Greater(t, other.dao.bodyReads.Load(), reads, "the non-owner reads the SET bodies")

	acks := make([]string, 0, n)
	for jti := range seen {
		acks = append(acks, jti)
	}
	calls := h.claimsBy(other.id)
	_ = cycle(other, acks)
	assert.Equal(t, calls+1, h.claimsBy(other.id), "the acknowledgements travel in the request's one Claim")
	require.Eventually(t, func() bool { return len(h.pendingFor(txSid)) == 0 }, 10*time.Second, 100*time.Millisecond,
		"the owner applies the acknowledgements")
	assert.Equal(t, writes, other.dao.writes.Load(), "the non-owner writes nothing to the store")
}
