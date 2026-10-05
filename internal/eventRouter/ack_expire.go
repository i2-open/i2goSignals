package eventRouter

import (
	"context"
	"fmt"
	"time"

	"github.com/i2-open/i2goSignals/pkg/services"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// ackEvents acknowledges SETs the receiver accepted, by inbound JTI, for
// stream sid. It goes through the stream's DeliveryQueue (#363), the one
// caller of AckBatch: one Ack per batch, under each reference's
// acknowledgement JTI, with the outbound copies this node served and the
// retention expiry of #360. An empty jtis is a no-op.
func (r *router) ackEvents(ctx context.Context, jtis []string, sid string, fencingToken int64) error {
	_, err := r.queueFor(sid).AckInbound(ctx, jtis, true, fencingToken)
	return err
}

// ackExpireAt returns ackDate + the stream's finite window, or nil (keep
// forever) when there is no resolver, no stream record, or the window is nil
// or <= 0.
func ackExpireAt(window services.EffectiveWindowFunc, rec *model.StreamStateRecord, ackDate time.Time) *time.Time {
	if window == nil || rec == nil {
		return nil
	}
	days := window(rec)
	if days == nil || *days <= 0 {
		return nil
	}
	expireAt := ackDate.Add(time.Duration(*days) * 24 * time.Hour)
	return &expireAt
}

// streamRecord returns a copy of the in-memory stream record of sid across the
// router's delivery maps, or nil when this router does not hold the stream.
func (r *router) streamRecord(sid string) *model.StreamStateRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.streamRecordLocked(sid)
}

// streamRecordLocked is streamRecord for a caller that holds r.mu (at least
// RLock): r.mu is a sync.RWMutex, so a nested RLock deadlocks once a writer
// is waiting.
func (r *router) streamRecordLocked(sid string) *model.StreamStateRecord {
	for _, m := range []map[string]model.StreamStateRecord{r.pushStreams, r.pollStreams, r.sstpServerStreams, r.sstpClientStreams} {
		if rec, ok := m[sid]; ok {
			return &rec
		}
	}
	for _, rec := range r.sstpClientStreams {
		if rec.StreamConfiguration.Id == sid {
			return &rec
		}
	}
	return nil
}

// checkAckFence applies the EventService ack fence (#334) to an ack the
// router writes through EventService.AckBatch: a leased stream's ack must
// carry the lease's current token.
func (r *router) checkAckFence(sid string, fencingToken int64) error {
	resource, current, leased, err := r.CurrentFence(sid)
	if err != nil {
		eventLogger.Error("ROUTER: fence check failed, ack not written", "sid", sid, "error", err)
		return err
	}
	if !leased {
		return nil
	}
	if fencingToken != services.NoFencingToken && fencingToken == current {
		return nil
	}
	eventLogger.Warn("ROUTER: rejected ack with stale fencing token", "sid", sid, "resource", resource, "token", fencingToken, "current", current)
	return fmt.Errorf("%w: stream %s resource %s token %d current %d", services.ErrStaleFencingToken, sid, resource, fencingToken, current)
}
