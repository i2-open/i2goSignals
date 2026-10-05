// Package cluster defines the seam used by goSignals nodes to coordinate
// per-resource ownership (push transmitters, poll receivers) and to publish
// node liveness for cluster-aware routing.
//
// Implementations live alongside the persistence adapters that own them:
//   - mongo_provider/cluster_coordinator.go (MongoCoordinator)
//   - memory_provider/cluster_coordinator.go (MemoryCoordinator)
package cluster

import (
	"slices"
	"strings"
	"time"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// ClusterCoordinator owns lease and node-registry semantics. It is the only
// way the rest of the system observes "who owns what" and "which peers are
// alive". Implementations must guarantee:
//
//   - TryAcquireOrRenewLease is atomic across concurrent callers competing
//     for the same resource. Exactly one acquires when the lease is free.
//   - FencingToken is strictly monotonic per resource and identifies one
//     tenure: every acquisition of an expired or unowned lease (by any node,
//     including its former owner) increments it, while the holder's renewal
//     of its own live lease keeps it. Acks are fenced on it, so the holder's
//     acks stay valid across heartbeats and a superseded holder's are
//     rejected (#334).
//   - ReleaseLeaseIfOwned is a no-op unless the caller currently owns the
//     lease (compare-and-release semantics).
//   - GetActiveNodes/GetActiveNodeCount filter to nodes whose LastSeenAt is
//     within the active-window (60s by convention).
type ClusterCoordinator interface {
	// TryAcquireOrRenewLease atomically acquires the lease if it is
	// expired/unowned, or renews it if already owned by nodeId. Returns
	// (acquired=true, fencingToken, leaseUntil) only when this node is (or
	// remains) owner; leaseUntil is the expiry the call stored on the lease
	// row, and the zero time when the lease was not acquired. The event
	// router's LeaseManager keeps it to answer "do I still own this stream"
	// from memory (#364).
	TryAcquireOrRenewLease(resource string, nodeId string, leaseDuration time.Duration) (acquired bool, fencingToken int64, leaseUntil time.Time, err error)

	// ReleaseLeaseIfOwned clears the lease iff it is owned by nodeId.
	ReleaseLeaseIfOwned(resource string, nodeId string) error

	// GetLeaseOwner returns the current owner, expiry, and fencing token for
	// a resource. Returns ("", zeroTime, 0, nil) when no lease exists, and
	// likewise when the lease has expired or been released: an elapsed lease
	// has no owner.
	GetLeaseOwner(resource string) (ownerNodeId string, leaseUntil time.Time, fencingToken int64, err error)

	// RegisterNode upserts the calling node's heartbeat and metadata.
	RegisterNode(node model.ClusterNode) error

	// GetActiveNodeCount returns the count of nodes heartbeated within the
	// active window.
	GetActiveNodeCount() (int64, error)

	// GetActiveNodes returns nodes heartbeated within the active window.
	GetActiveNodes() ([]model.ClusterNode, error)

	// GetNode returns the node with the given id. Returns (nil, nil) when
	// not found.
	GetNode(nodeId string) (*model.ClusterNode, error)
}

// LeaseKind is the kind prefix of a lease resource: a resource is
// "<kind>:<stream or pair id>".
type LeaseKind string

// The lease kinds. A push transmitter's runner holds PushTransmitter and a
// poll receiver PollReceiver for their stream; an SSTP client (dialer) holds
// SstpClient for its pair. The PollTransmitter holder keeps a poll stream's
// one queue and serves every poll request for it, others through a peer
// Claim; the SstpServer holder (the accepting side, keyed by the pair's tx
// stream id) keeps the pair's one outbound queue (#365).
const (
	PushTransmitter LeaseKind = "push-transmitter"
	PollReceiver    LeaseKind = "poll-receiver"
	SstpClient      LeaseKind = "sstp-client"
	PollTransmitter LeaseKind = "poll-transmitter"
	SstpServer      LeaseKind = "sstp-server"
)

// leaseKinds lists every lease kind; known checks against it.
var leaseKinds = []LeaseKind{PushTransmitter, PollReceiver, SstpClient, PollTransmitter, SstpServer}

// Resource is the lease resource of kind k for stream or pair id.
func (k LeaseKind) Resource(id string) string {
	return string(k) + ":" + id
}

// known reports whether k is one of leaseKinds.
func (k LeaseKind) known() bool {
	return slices.Contains(leaseKinds, k)
}

// ParseResource splits resource at its first ':' into its kind and id. ok
// reports whether the kind is a known LeaseKind and the id is non-empty; the
// kind and id are returned as split either way.
func ParseResource(resource string) (kind LeaseKind, id string, ok bool) {
	k, id, found := strings.Cut(resource, ":")
	kind = LeaseKind(k)
	return kind, id, found && id != "" && kind.known()
}

// Reaper is the optional garbage-collection half of a coordinator (#350).
// Nodes that stopped heartbeating and leases whose stream was deleted leave
// rows behind; a node that implements Reaper lets the periodic stream-table
// sync remove them. It is a separate interface so test coordinators need not
// implement it.
//
// A lease row carries its resource's fencing history, and deleting it restarts
// the next tenure at token 1. So a lease is purged only once it has been
// expired since before the cutoff AND keep reports its resource unwanted —
// that is, its stream is gone from the store.
type Reaper interface {
	// PurgeStaleNodes deletes the nodes last seen before the cutoff and
	// returns how many it deleted.
	PurgeStaleNodes(before time.Time) (int, error)
	// PurgeExpiredLeases deletes the lease rows that expired before the cutoff
	// and whose resource keep rejects, and returns how many it deleted. A
	// lease renewed between the scan and the delete is not deleted.
	PurgeExpiredLeases(before time.Time, keep func(resource string) bool) (int, error)
}
