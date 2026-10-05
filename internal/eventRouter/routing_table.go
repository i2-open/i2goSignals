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
// inbound and never appears in a routingTable. Only the push-transmitter,
// poll-receiver and sstp-client leases are taken today; the poll-transmitter
// and sstp-server leases follow in #365.
func streamLeaseResource(mode, key string) string {
	switch mode {
	case routeModePush:
		return cluster.PushTransmitterResource(key)
	case routeModePoll:
		return cluster.PollTransmitterResource(key)
	case routeModeSstpClient:
		return cluster.SstpClientResource(key)
	case routeModeSstpServer:
		return cluster.SstpServerResource(key)
	case model.ReceivePoll:
		return cluster.PollReceiverResource(key)
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

// lockTracker records which goroutines hold the router lock in the fan-out
// path, so a store or coordinator call made by one of them is counted in
// goSignals_router_reads_under_lock_total. The goroutine id is read only while
// some fan-out region is held, so a call made with none held costs one atomic
// load.
type lockTracker struct {
	held    atomic.Int64
	holders sync.Map // goroutine id -> *atomic.Int64 depth
	onRead  func()   // test hook, called for each read counted
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

func (l *lockTracker) enter() {
	l.held.Add(1)
	d, _ := l.holders.LoadOrStore(goroutineID(), new(atomic.Int64))
	d.(*atomic.Int64).Add(1)
}

func (l *lockTracker) exit() {
	gid := goroutineID()
	if d, ok := l.holders.Load(gid); ok && d.(*atomic.Int64).Add(-1) <= 0 {
		l.holders.Delete(gid)
	}
	l.held.Add(-1)
}

// heldByCaller reports whether the calling goroutine holds a fan-out region.
func (l *lockTracker) heldByCaller() bool {
	if l.held.Load() == 0 {
		return false
	}
	_, ok := l.holders.Load(goroutineID())
	return ok
}

// noteRead counts a store or coordinator call if the caller holds the lock.
func (l *lockTracker) noteRead() {
	if !l.heldByCaller() {
		return
	}
	readsUnderLockCounter.Inc()
	if l.onRead != nil {
		l.onRead()
	}
}

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

func (c *trackedCoordinator) TryAcquireOrRenewLease(resource string, nodeId string, leaseDuration time.Duration) (bool, int64, error) {
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
