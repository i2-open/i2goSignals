// Package cluster defines the seam used by goSignals nodes to coordinate
// per-resource ownership (push transmitters, poll receivers) and to publish
// node liveness for cluster-aware routing.
//
// Implementations live alongside the persistence adapters that own them:
//   - mongo_provider/cluster_coordinator.go (MongoCoordinator)
//   - memory_provider/cluster_coordinator.go (MemoryCoordinator)
package cluster

import (
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
	// (acquired=true, fencingToken) only when this node is (or remains) owner.
	TryAcquireOrRenewLease(resource string, nodeId string, leaseDuration time.Duration) (acquired bool, fencingToken int64, err error)

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

// The kind prefixes of the lease resources, shared by the resource builders
// below and ResourceId.
const (
	pushTransmitterKind = "push-transmitter"
	pollReceiverKind    = "poll-receiver"
	sstpClientKind      = "sstp-client"
	pollTransmitterKind = "poll-transmitter"
	sstpServerKind      = "sstp-server"
)

// PushTransmitterResource is the lease resource a push transmitter's runner
// holds for stream sid.
func PushTransmitterResource(sid string) string {
	return pushTransmitterKind + ":" + sid
}

// PollReceiverResource is the lease resource a poll receiver holds for
// stream sid.
func PollReceiverResource(sid string) string {
	return pollReceiverKind + ":" + sid
}

// SstpClientResource is the lease resource an SSTP client (dialer) holds for
// pair pairId.
func SstpClientResource(pairId string) string {
	return sstpClientKind + ":" + pairId
}

// PollTransmitterResource is the lease resource a poll transmitter holds for
// sid. It names the resource only: no lease is taken on it yet (#365).
func PollTransmitterResource(sid string) string {
	return pollTransmitterKind + ":" + sid
}

// SstpServerResource is the lease resource the accepting (responder) side of
// an SSTP pair holds for the pair. It is called with the pair's tx stream id,
// the key the router tracks responder pairs by. It names the resource only: no
// lease is taken on it yet (#365).
func SstpServerResource(pairId string) string {
	return sstpServerKind + ":" + pairId
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

// ResourceId splits a lease resource into its kind prefix and the stream or
// pair id it guards. ok is false for a resource that is not one of the known
// kinds (push-transmitter, poll-receiver, sstp-client).
func ResourceId(resource string) (kind, id string, ok bool) {
	kind, id, found := strings.Cut(resource, ":")
	if !found || id == "" {
		return "", "", false
	}
	switch kind {
	case pushTransmitterKind, pollReceiverKind, sstpClientKind:
		return kind, id, true
	}
	return "", "", false
}
