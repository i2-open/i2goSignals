package services

import (
	"context"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

var retLog = logger.Sub("RETENTION")

// EffectiveWindowFunc resolves the effective retention window (in days) for a
// stream. A nil result — or a non-positive value — means keep-forever, so the
// purge engine skips the stream entirely. The community default resolver
// (DefaultEffectiveWindow) returns the per-stream RetentionWindowDays override
// only, which is nil unless an operator set it: that is why the engine ships
// DORMANT (ADR 0055 decision 3). The enterprise superset supplies its own
// resolver that folds in the enrollment-bundle default and cap.
type EffectiveWindowFunc func(stream *model.StreamStateRecord) *int

// DefaultEffectiveWindow is community's dormant-by-default window resolver: it
// honors only the per-stream override, treating an unset (nil) override as
// keep-forever. Without a finite window from this or an enterprise-supplied
// resolver, nothing ever expires.
func DefaultEffectiveWindow(stream *model.StreamStateRecord) *int {
	return stream.RetentionWindowDays
}

// OccupancySample is one daily per-stream retained-occupancy observation — the
// community→enterprise contract feeding ADR 0055's Mean Retained Events (MRE)
// aggregation. The idempotency key is (ServerURN, StreamURN, SampleDate); every
// HA replica emits an identical sample because the event store is shared, and
// tenancy dedups on that key. RetainedCount counts post-ack-retained (delivered,
// not-yet-purged) JTIs only — pending is excluded.
type OccupancySample struct {
	ServerURN     string
	StreamURN     string
	SampleDate    string // UTC calendar date, "YYYY-MM-DD"
	RetainedCount int64
}

// OccupancySink receives the daily per-stream occupancy samples. Community
// registers none (the sampler is inert without a sink); the enterprise superset
// registers one to forward samples to the tenancy MRE aggregator — mirroring the
// event-router MeteringObserver seam.
type OccupancySink interface {
	ObserveOccupancy(sample OccupancySample)
}

// RetentionEngine owns the ack-anchored refcount purge and the daily occupancy
// sampler. It holds no scheduler of its own: PurgeExpired and SampleOccupancy
// are driven by the server's periodic tick (or a test clock), each handed the
// current stream set so the engine stays decoupled from the StreamDAO.
type RetentionEngine struct {
	eventDAO interfaces.EventDAO
}

// NewRetentionEngine constructs a RetentionEngine over the given event store.
func NewRetentionEngine(eventDAO interfaces.EventDAO) *RetentionEngine {
	return &RetentionEngine{eventDAO: eventDAO}
}

// PurgeExpired runs one ack-anchored purge pass over streams at time now,
// resolving each stream's effective window via window. The clock is per (stream,
// JTI): a delivered entry expires when AckDate + window <= now. On expiry the
// stream's delivered entry is dropped; the global body is deleted ONLY when no
// stream (pending or delivered) still references the JTI — so a body referenced
// by two streams survives until BOTH windows expire (refcount → 0). Pending is
// never touched. Streams whose effective window is keep-forever (nil or
// non-positive) are skipped, which is why the engine is inert until a finite
// window is set. It returns the number of global bodies deleted.
func (e *RetentionEngine) PurgeExpired(ctx context.Context, now time.Time, streams []model.StreamStateRecord, window EffectiveWindowFunc) (int, error) {
	if window == nil {
		window = DefaultEffectiveWindow
	}

	// Candidate JTIs whose per-stream entry expired this pass; each is re-checked
	// for refcount 0 after all per-stream removals so a body shared across streams
	// with different windows is only deleted once the last reference is gone.
	candidates := make(map[string]struct{})

	for i := range streams {
		stream := &streams[i]
		days := window(stream)
		if days == nil || *days <= 0 {
			continue // keep-forever — engine stays dormant for this stream
		}
		streamID := stream.Id.Hex()
		cutoff := now.Add(-time.Duration(*days) * 24 * time.Hour)

		delivered, err := e.eventDAO.ListDeliveredForStream(ctx, streamID)
		if err != nil {
			return 0, err
		}
		for _, evt := range delivered {
			// Not yet expired when AckDate is at/after the cutoff.
			if evt.AckDate.After(cutoff) || evt.AckDate.Equal(cutoff) {
				continue
			}
			if err := e.eventDAO.RemoveDelivered(ctx, evt.Jti, streamID); err != nil {
				return 0, err
			}
			candidates[evt.Jti] = struct{}{}
		}
	}

	purged := 0
	for jti := range candidates {
		deleted, err := e.eventDAO.DeleteBodyIfUnreferenced(ctx, jti)
		if err != nil {
			return purged, err
		}
		if deleted {
			purged++
		}
	}
	if purged > 0 {
		retLog.Debug("Retention purge deleted event bodies", "count", purged)
	}
	return purged, nil
}

// SampleOccupancy emits one OccupancySample per stream to sink at time now,
// stamped with serverURN. RetainedCount is the stream's delivered
// (post-ack-retained) JTI count read from the shared store, so every HA replica
// produces an identical sample; SampleDate is now's UTC calendar date, making
// (serverURN, streamURN, sampleDate) the idempotency key tenancy dedups on. A
// nil sink is a no-op (the sampler is inert until the enterprise superset
// registers one).
func (e *RetentionEngine) SampleOccupancy(ctx context.Context, now time.Time, serverURN string, streams []model.StreamStateRecord, sink OccupancySink) error {
	if sink == nil {
		return nil
	}
	sampleDate := now.UTC().Format("2006-01-02")
	for i := range streams {
		streamID := streams[i].Id.Hex()
		count, err := e.eventDAO.CountRetainedForStream(ctx, streamID)
		if err != nil {
			return err
		}
		sink.ObserveOccupancy(OccupancySample{
			ServerURN:     serverURN,
			StreamURN:     streamID,
			SampleDate:    sampleDate,
			RetainedCount: count,
		})
	}
	return nil
}
