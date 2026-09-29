package eventRouter

import (
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/pkg/services"
)

// Compile-time check: the router fences EventService acks (#334).
var _ services.FenceChecker = (*router)(nil)

// CurrentFence reports the lease that fences acks for stream sid: the
// push-transmitter lease of a push stream, or the sstp-client lease of an SSTP
// pair whose client side this node runs. Any other stream (a poll transmitter,
// ADR 0014, or the SSTP server side) holds no lease and is not fenced. The
// token is the lease's current one, 0 once it has expired or been released,
// read straight from the coordinator: a fence is never answered from a cache.
func (r *router) CurrentFence(sid string) (string, int64, bool, error) {
	resource := ""
	r.mu.RLock()
	if _, ok := r.pushStreams[sid]; ok {
		resource = cluster.PushTransmitterResource(sid)
	} else if _, ok := r.sstpClientStreams[sid]; ok {
		resource = cluster.SstpClientResource(sid)
	} else {
		for pairId, rec := range r.sstpClientStreams {
			if rec.StreamConfiguration.Id == sid {
				resource = cluster.SstpClientResource(pairId)
				break
			}
		}
	}
	r.mu.RUnlock()
	if resource == "" || r.coordinator == nil {
		return "", 0, false, nil
	}
	_, _, token, err := r.coordinator.GetLeaseOwner(resource)
	if err != nil {
		return resource, 0, true, err
	}
	return resource, token, true, nil
}

// releaseLease gives up this node's lease on resource if it still holds it.
// A failure is logged and otherwise harmless: the lease then expires on its
// own. At shutdown the coordinator's context is already gone, so the failure
// is expected and logged quietly.
func (r *router) releaseLease(resource, sid string) {
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
