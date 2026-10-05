package eventRouter

import (
	"bytes"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// The fan-out modes of a routing entry. They label logs and select the wake
// action of a fanoutTarget.
const (
	routeModePush       = "PUSH"
	routeModePoll       = "POLL"
	routeModeSstpClient = "SSTP-CLIENT"
	routeModeSstpServer = "SSTP-SERVER"
)

// routeEntry is one outbound stream in a routingTable: the stream record the
// match step tests a SET against, the key its buffers are held under, and the
// lease resource that names the stream's owner.
type routeEntry struct {
	mode     string
	key      string // buffer-map key: the SID for push/poll, the PairId for sstp-client, the tx SID for sstp-server
	resource string // the stream's lease resource (streamLeaseResource)
	stream   model.StreamStateRecord
}

// routingTable is an immutable snapshot of the outbound streams this router
// fans inbound SETs out to (#362). It is rebuilt, under the write lock, every
// time a stream is added, removed or updated (status and route mode live in
// the record), and published through router.routes. The match step reads it
// with no router lock and no store or coordinator read. Entries are in a
// fixed order: push, poll, SSTP-client, SSTP-server.
type routingTable struct {
	entries []routeEntry
}

// streamLeaseResource returns the lease resource that names the owner of a
// stream of the given kind. Every kind a stream can be has one:
// push-transmitter, poll-transmitter, sstp-client and sstp-server for the
// routed (outbound) kinds, and poll-receiver for a poll receiver, which is
// inbound and never appears in a routingTable. Every one of them is taken
// (the poll-transmitter and sstp-server leases since #365).
func streamLeaseResource(mode, key string) string {
	switch mode {
	case routeModePush:
		return cluster.PushTransmitter.Resource(key)
	case routeModePoll:
		return cluster.PollTransmitter.Resource(key)
	case routeModeSstpClient:
		return cluster.SstpClient.Resource(key)
	case routeModeSstpServer:
		return cluster.SstpServer.Resource(key)
	case model.ReceivePoll:
		return cluster.PollReceiver.Resource(key)
	}
	return ""
}

// rebuildRoutingLocked rebuilds the routing snapshot from the stream maps and
// publishes it. Every write to pushStreams, pollStreams, sstpClientStreams or
// sstpServerStreams is followed by a call. The caller must hold r.mu for
// writing, which also orders concurrent rebuilds.
func (r *router) rebuildRoutingLocked() {
	t := &routingTable{entries: make([]routeEntry, 0,
		len(r.pushStreams)+len(r.pollStreams)+len(r.sstpClientStreams)+len(r.sstpServerStreams))}
	add := func(mode string, m map[string]model.StreamStateRecord) {
		for key, stream := range m {
			t.entries = append(t.entries, routeEntry{mode: mode, key: key, resource: streamLeaseResource(mode, key), stream: stream})
		}
	}
	add(routeModePush, r.pushStreams)
	add(routeModePoll, r.pollStreams)
	add(routeModeSstpClient, r.sstpClientStreams)
	add(routeModeSstpServer, r.sstpServerStreams)
	r.routes.Store(t)
}

// routing returns the current routing snapshot. It takes no lock.
func (r *router) routing() *routingTable {
	if t := r.routes.Load(); t != nil {
		return t
	}
	return &routingTable{}
}

// readsUnderLockCounter counts store and coordinator calls made while the
// calling goroutine holds the router lock on the fan-out path. The design
// value is zero (#362): routing reads the snapshot with no lock, and lease
// owners are resolved before the lock is taken for the wake.
var readsUnderLockCounter = prometheus.NewCounter(prometheus.CounterOpts{
	Namespace: "goSignals",
	Subsystem: "router",
	Name:      "reads_under_lock_total",
	Help:      "Store or coordinator calls made while the router lock was held on the fan-out path (design value 0).",
})

// RoutingCollectors returns the routing Prometheus collectors for the
// server's registry.
func RoutingCollectors() []prometheus.Collector {
	return []prometheus.Collector{readsUnderLockCounter}
}

// regionTracker records which goroutines are inside a code region, so a
// store or coordinator call made by one of them can be counted. The goroutine
// id is read only while some goroutine is inside, so a check made with none
// inside costs one atomic load.
type regionTracker struct {
	held    atomic.Int64
	holders sync.Map // goroutine id -> *atomic.Int64 depth
	onRead  func()   // test hook, called for each read counted
}

// enter records the caller as inside the region. Regions nest.
func (t *regionTracker) enter() {
	t.held.Add(1)
	d, _ := t.holders.LoadOrStore(goroutineID(), new(atomic.Int64))
	d.(*atomic.Int64).Add(1)
}

// exit ends an enter.
func (t *regionTracker) exit() {
	gid := goroutineID()
	if d, ok := t.holders.Load(gid); ok && d.(*atomic.Int64).Add(-1) <= 0 {
		t.holders.Delete(gid)
	}
	t.held.Add(-1)
}

// heldByCaller reports whether the calling goroutine is inside the region.
func (t *regionTracker) heldByCaller() bool {
	if t.held.Load() == 0 {
		return false
	}
	_, ok := t.holders.Load(goroutineID())
	return ok
}

// noteRead counts a read in counter, and calls the test hook, if the caller
// is inside the region.
func (t *regionTracker) noteRead(counter prometheus.Counter) {
	if !t.heldByCaller() {
		return
	}
	counter.Inc()
	if t.onRead != nil {
		t.onRead()
	}
}

// lockTracker holds the router's two tracked regions. A store or coordinator
// call made inside the fan-out region (the router lock in the fan-out path)
// is counted in goSignals_router_reads_under_lock_total. One made inside the
// acknowledgement region (#364: from a DeliveryQueue's write entry to its
// AckBatch call) is counted in goSignals_router_reads_before_ack_total; the
// design value of both is zero, since ownership is answered by the
// leaseManager from memory.
type lockTracker struct {
	fanout regionTracker
	ack    regionTracker
}

// fanoutRLock takes r.mu for reading and records the caller as a holder.
func (r *router) fanoutRLock() {
	r.mu.RLock()
	r.locks.enter()
}

// fanoutRUnlock releases a fanoutRLock.
func (r *router) fanoutRUnlock() {
	r.locks.exit()
	r.mu.RUnlock()
}

func (l *lockTracker) enter() { l.fanout.enter() }

func (l *lockTracker) exit() { l.fanout.exit() }

// heldByCaller reports whether the calling goroutine holds a fan-out region.
func (l *lockTracker) heldByCaller() bool { return l.fanout.heldByCaller() }

// noteRead counts a store or coordinator call if the caller is inside an
// acknowledgement region, and separately if it holds the fan-out lock.
func (l *lockTracker) noteRead() {
	l.ack.noteRead(readsBeforeAckTotal)
	l.fanout.noteRead(readsUnderLockCounter)
}

// enterAck records the caller as inside an acknowledgement region.
func (l *lockTracker) enterAck() { l.ack.enter() }

// exitAck ends an enterAck.
func (l *lockTracker) exitAck() { l.ack.exit() }

// inAckByCaller reports whether the calling goroutine is inside an
// acknowledgement region. With none open it costs one atomic load.
func (l *lockTracker) inAckByCaller() bool { return l.ack.heldByCaller() }

// goroutineID returns the calling goroutine's id, parsed from the header line
// of its stack ("goroutine 123 [...").
func goroutineID() uint64 {
	var buf [64]byte
	b := buf[:runtime.Stack(buf[:], false)]
	b = bytes.TrimPrefix(b, []byte("goroutine "))
	if i := bytes.IndexByte(b, ' '); i > 0 {
		b = b[:i]
	}
	id, _ := strconv.ParseUint(string(b), 10, 64)
	return id
}

// trackedCoordinator is the router's view of its ClusterCoordinator: every
// call is checked against the fan-out lock regions (lockTracker.noteRead).
type trackedCoordinator struct {
	cluster.ClusterCoordinator
	locks *lockTracker
}

func (c *trackedCoordinator) TryAcquireOrRenewLease(resource string, nodeId string, leaseDuration time.Duration) (bool, int64, time.Time, error) {
	c.locks.noteRead()
	return c.ClusterCoordinator.TryAcquireOrRenewLease(resource, nodeId, leaseDuration)
}

func (c *trackedCoordinator) ReleaseLeaseIfOwned(resource string, nodeId string) error {
	c.locks.noteRead()
	return c.ClusterCoordinator.ReleaseLeaseIfOwned(resource, nodeId)
}

func (c *trackedCoordinator) GetLeaseOwner(resource string) (string, time.Time, int64, error) {
	c.locks.noteRead()
	return c.ClusterCoordinator.GetLeaseOwner(resource)
}

func (c *trackedCoordinator) RegisterNode(node model.ClusterNode) error {
	c.locks.noteRead()
	return c.ClusterCoordinator.RegisterNode(node)
}

func (c *trackedCoordinator) GetActiveNodeCount() (int64, error) {
	c.locks.noteRead()
	return c.ClusterCoordinator.GetActiveNodeCount()
}

func (c *trackedCoordinator) GetActiveNodes() ([]model.ClusterNode, error) {
	c.locks.noteRead()
	return c.ClusterCoordinator.GetActiveNodes()
}

func (c *trackedCoordinator) GetNode(nodeId string) (*model.ClusterNode, error) {
	c.locks.noteRead()
	return c.ClusterCoordinator.GetNode(nodeId)
}

// Unwrap returns the coordinator the router was built with.
func (c *trackedCoordinator) Unwrap() cluster.ClusterCoordinator {
	return c.ClusterCoordinator
}
