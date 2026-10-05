package eventRouter

import (
	"errors"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/cluster"
)

// errNotLeaseOwner is returned by an acknowledgement write the router's
// leaseManager refused: this node's recorded tenure on the stream's lease has
// run out, so it may no longer record deliveries for it (#364). Nothing was
// read or written; the SETs stay pending, and the batch is retried once a
// heartbeat renews the lease, or redelivered by the next owner.
var errNotLeaseOwner = errors.New("not the lease owner")

// ackResource names the lease that guards acknowledgements for stream sid:
// the push-transmitter lease of a push stream, or the sstp-client lease of an
// SSTP pair whose client side this node runs. Any other stream (a poll
// transmitter, or the SSTP server side) returns "" and its acknowledgements
// are not checked in this slice; #365 leases those kinds too. It reads only
// the router's own maps, never the store or the coordinator.
func (r *router) ackResource(sid string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if _, ok := r.pushStreams[sid]; ok {
		return cluster.PushTransmitterResource(sid)
	}
	if _, ok := r.sstpClientStreams[sid]; ok {
		return cluster.SstpClientResource(sid)
	}
	for pairId, rec := range r.sstpClientStreams {
		if rec.StreamConfiguration.Id == sid {
			return cluster.SstpClientResource(pairId)
		}
	}
	return ""
}

// stillOwnsAck reports whether this node may write an acknowledgement for
// stream sid, answered from the leaseManager's memory: no store or
// coordinator call is made.
func (r *router) stillOwnsAck(sid string) bool {
	resource := r.ackResource(sid)
	if resource == "" {
		return true
	}
	return r.leases.StillOwner(resource)
}

// tryLease makes one acquire-or-renew call for resource, through the router's
// leaseManager so the tenure it records is what StillOwner answers from. A
// router built without a manager (a test literal) calls the coordinator
// directly.
func (r *router) tryLease(resource string, leaseDuration time.Duration) (bool, int64, error) {
	if r.leases != nil && r.leases.coord != nil {
		return r.leases.acquire(resource, r.nodeId, leaseDuration)
	}
	held, token, _, err := r.coordinator.TryAcquireOrRenewLease(resource, r.nodeId, leaseDuration)
	return held, token, err
}

// leaseRenewer returns the manager a lease heartbeat renews through, or nil
// when the router has none.
func (r *router) leaseRenewer() *leaseManager {
	if r.leases != nil && r.leases.coord != nil {
		return r.leases
	}
	return nil
}

// releaseLease gives up this node's lease on resource if it still holds it.
// A failure is logged and otherwise harmless: the lease then expires on its
// own. At shutdown the coordinator's context is already gone, so the failure
// is expected and logged quietly.
func (r *router) releaseLease(resource, sid string) {
	r.leases.forget(resource)
	if r.coordinator == nil {
		return
	}
	if err := r.coordinator.ReleaseLeaseIfOwned(resource, r.nodeId); err != nil {
		if r.ctx.Err() != nil {
			eventLogger.Debug("ROUTER: lease release at shutdown failed; it will expire", "sid", sid, "resource", resource, "error", err)
			return
		}
		eventLogger.Warn("ROUTER: lease release failed; it will expire", "sid", sid, "resource", resource, "error", err)
	}
}
