package eventRouter

import (
	"context"
	"fmt"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/services"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// ackEvents acknowledges jtis for stream sid, stamping the delivered
// references with expireAt = ackDate + the stream's retention window (#360,
// seam S1). The window is resolved through RouterDeps.RetentionWindow from the
// stream record the router already holds, so no store read is added. With no
// resolver, or a keep-forever window, the ack takes the EventService path
// unchanged and writes no expireAt. An empty jtis is a no-op.
func (r *router) ackEvents(ctx context.Context, jtis []string, sid string, fencingToken int64) error {
	if len(jtis) == 0 {
		return nil
	}
	if r.retentionWindow == nil {
		return r.eventService.AckEvents(ctx, jtis, sid, fencingToken)
	}
	ackDate := time.Now()
	expireAt := ackExpireAt(r.retentionWindow, r.streamRecord(sid), ackDate)
	if expireAt == nil {
		return r.eventService.AckEvents(ctx, jtis, sid, fencingToken)
	}
	if err := r.checkAckFence(sid, fencingToken); err != nil {
		return err
	}
	_, err := r.eventService.AckBatch(ctx, interfaces.AckBatch{StreamID: sid, Jtis: jtis, AckDate: ackDate, ExpireAt: expireAt})
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
