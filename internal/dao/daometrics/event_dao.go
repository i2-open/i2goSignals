// Package daometrics instruments the EventDAO seam with per-operation latency
// and batch-size histograms (community #328, planning spec #111 Stage 0).
//
// It is a pure decorator: every call is forwarded verbatim to the wrapped
// EventDAO and its results and errors are returned unchanged. Both persistence
// providers wrap their live EventDAO with Wrap, so services.NewEventService and
// Persistence.EventDAO see the instrumented instance without either raw DAO
// being modified.
package daometrics

import (
	"context"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	outcomeOK    = "ok"
	outcomeError = "error"
)

// Metrics holds the two DAO histograms. Label cardinality is closed: op is an
// EventDAO Go method name, outcome is ok/error — no stream_id.
type Metrics struct {
	// OpDuration is goSignals_dao_op_duration_seconds{op, outcome}.
	OpDuration *prometheus.HistogramVec
	// BatchSize is goSignals_dao_batch_size{op}, observed for the batch-taking
	// methods only.
	BatchSize *prometheus.HistogramVec
}

// OpDurationBuckets resolve 0.5 ms .. 5 s: the interesting range for a
// majority-acked, journaled Mongo write is sub-millisecond to ~100 ms.
var OpDurationBuckets = []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5}

// BatchSizeBuckets cover single-document calls up to the largest ingest and
// delivery batches.
var BatchSizeBuckets = []float64{1, 2, 5, 10, 25, 50, 100, 250, 500, 1000}

// NewMetrics builds an unregistered Metrics. Tests use it with a private
// registry; production uses Default.
func NewMetrics() *Metrics {
	return &Metrics{
		OpDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "goSignals",
				Subsystem: "dao",
				Name:      "op_duration_seconds",
				Help:      "Wall-time of each EventDAO call, labeled by method name and outcome (ok/error).",
				Buckets:   OpDurationBuckets,
			},
			[]string{"op", "outcome"},
		),
		BatchSize: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "goSignals",
				Subsystem: "dao",
				Name:      "batch_size",
				Help:      "Number of items passed to each batch-taking EventDAO call, labeled by method name.",
				Buckets:   BatchSizeBuckets,
			},
			[]string{"op"},
		),
	}
}

// Collectors returns the collectors to register.
func (m *Metrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{m.OpDuration, m.BatchSize}
}

// Default is the process-wide Metrics both providers wrap with and the server
// registers alongside its other router histograms.
var Default = NewMetrics()

// Wrap returns inner instrumented with m (Default when m is nil).
func Wrap(inner interfaces.EventDAO, m *Metrics) interfaces.EventDAO {
	if m == nil {
		m = Default
	}
	return &eventDAO{inner: inner, m: m}
}

type eventDAO struct {
	inner interfaces.EventDAO
	m     *Metrics
}

// observe records the latency of op since start with the outcome of err.
func (d *eventDAO) observe(op string, start time.Time, err error) {
	outcome := outcomeOK
	if err != nil {
		outcome = outcomeError
	}
	d.m.OpDuration.WithLabelValues(op, outcome).Observe(time.Since(start).Seconds())
}

func (d *eventDAO) batch(op string, n int) {
	d.m.BatchSize.WithLabelValues(op).Observe(float64(n))
}

func (d *eventDAO) Insert(ctx context.Context, record *model.EventRecord) error {
	start := time.Now()
	err := d.inner.Insert(ctx, record)
	d.observe("Insert", start, err)
	return err
}

// InsertMany's outcome reflects the batch-level error only; per-record
// results (e.g. ErrDuplicateJTI) are data, not a failed call.
func (d *eventDAO) InsertMany(ctx context.Context, records []*model.EventRecord) ([]error, error) {
	d.batch("InsertMany", len(records))
	start := time.Now()
	results, err := d.inner.InsertMany(ctx, records)
	d.observe("InsertMany", start, err)
	return results, err
}

func (d *eventDAO) InsertWithPending(ctx context.Context, records []*model.EventRecord, pending map[string][]interfaces.PendingRef) ([]error, error) {
	d.batch("InsertWithPending", len(records))
	start := time.Now()
	errs, err := d.inner.InsertWithPending(ctx, records, pending)
	d.observe("InsertWithPending", start, err)
	return errs, err
}

func (d *eventDAO) FindByJTI(ctx context.Context, jti string) (*model.EventRecord, error) {
	start := time.Now()
	rec, err := d.inner.FindByJTI(ctx, jti)
	d.observe("FindByJTI", start, err)
	return rec, err
}

func (d *eventDAO) FindByJTIs(ctx context.Context, jtis []string) ([]*model.EventRecord, error) {
	d.batch("FindByJTIs", len(jtis))
	start := time.Now()
	recs, err := d.inner.FindByJTIs(ctx, jtis)
	d.observe("FindByJTIs", start, err)
	return recs, err
}

func (d *eventDAO) FindByTimeRange(ctx context.Context, from time.Time, to *time.Time, filter func(*model.EventRecord) bool) ([]*model.EventRecord, error) {
	start := time.Now()
	recs, err := d.inner.FindByTimeRange(ctx, from, to, filter)
	d.observe("FindByTimeRange", start, err)
	return recs, err
}

func (d *eventDAO) AddPending(ctx context.Context, ref interfaces.PendingRef, streamID string) error {
	start := time.Now()
	err := d.inner.AddPending(ctx, ref, streamID)
	d.observe("AddPending", start, err)
	return err
}

func (d *eventDAO) AddPendingMany(ctx context.Context, refs []interfaces.PendingRef, streamID string) error {
	d.batch("AddPendingMany", len(refs))
	start := time.Now()
	err := d.inner.AddPendingMany(ctx, refs, streamID)
	d.observe("AddPendingMany", start, err)
	return err
}

func (d *eventDAO) EnsurePending(ctx context.Context, jti string, ackJtis map[string]string) ([]string, error) {
	start := time.Now()
	queued, err := d.inner.EnsurePending(ctx, jti, ackJtis)
	d.observe("EnsurePending", start, err)
	return queued, err
}

func (d *eventDAO) GetPendingForStream(ctx context.Context, streamID string, limit int32) (interfaces.PendingPage, error) {
	start := time.Now()
	page, err := d.inner.GetPendingForStream(ctx, streamID, limit)
	d.observe("GetPendingForStream", start, err)
	return page, err
}

func (d *eventDAO) RemovePendingMany(ctx context.Context, jtis []string, streamID string) ([]interfaces.DeliverableEvent, error) {
	d.batch("RemovePendingMany", len(jtis))
	start := time.Now()
	evs, err := d.inner.RemovePendingMany(ctx, jtis, streamID)
	d.observe("RemovePendingMany", start, err)
	return evs, err
}

func (d *eventDAO) ClearPendingForStream(ctx context.Context, streamID string) (int64, error) {
	start := time.Now()
	n, err := d.inner.ClearPendingForStream(ctx, streamID)
	d.observe("ClearPendingForStream", start, err)
	return n, err
}

func (d *eventDAO) Ack(ctx context.Context, batch interfaces.AckBatch) (int64, error) {
	d.batch("Ack", len(batch.Jtis))
	start := time.Now()
	n, err := d.inner.Ack(ctx, batch)
	d.observe("Ack", start, err)
	return n, err
}

func (d *eventDAO) ResetPendingAckJti(ctx context.Context, streamID string) (int64, error) {
	start := time.Now()
	n, err := d.inner.ResetPendingAckJti(ctx, streamID)
	d.observe("ResetPendingAckJti", start, err)
	return n, err
}

func (d *eventDAO) SweepExpired(ctx context.Context, now time.Time, bodyCutoff time.Time, maxBodies int) (interfaces.SweepResult, error) {
	start := time.Now()
	res, err := d.inner.SweepExpired(ctx, now, bodyCutoff, maxBodies)
	d.observe("SweepExpired", start, err)
	return res, err
}

func (d *eventDAO) MigrateLegacyDeliveries(ctx context.Context, expireAt func(streamID string, ackDate time.Time) *time.Time) (interfaces.MigrationResult, error) {
	start := time.Now()
	res, err := d.inner.MigrateLegacyDeliveries(ctx, expireAt)
	d.observe("MigrateLegacyDeliveries", start, err)
	return res, err
}

func (d *eventDAO) ListDeliveredForStream(ctx context.Context, streamID string) ([]interfaces.DeliveredEvent, error) {
	start := time.Now()
	evs, err := d.inner.ListDeliveredForStream(ctx, streamID)
	d.observe("ListDeliveredForStream", start, err)
	return evs, err
}

func (d *eventDAO) RemoveDelivered(ctx context.Context, jti string, streamID string) error {
	start := time.Now()
	err := d.inner.RemoveDelivered(ctx, jti, streamID)
	d.observe("RemoveDelivered", start, err)
	return err
}

func (d *eventDAO) DeleteBodyIfUnreferenced(ctx context.Context, jti string) (bool, error) {
	start := time.Now()
	deleted, err := d.inner.DeleteBodyIfUnreferenced(ctx, jti)
	d.observe("DeleteBodyIfUnreferenced", start, err)
	return deleted, err
}

func (d *eventDAO) CountRetainedForStream(ctx context.Context, streamID string) (int64, error) {
	start := time.Now()
	n, err := d.inner.CountRetainedForStream(ctx, streamID)
	d.observe("CountRetainedForStream", start, err)
	return n, err
}

// WatchPending's latency is the setup time of the watch (Mongo returns once the
// change stream is open); the memory store blocks until ctx ends, so there it
// measures the watch's lifetime.
func (d *eventDAO) WatchPending(ctx context.Context, callback func(ref interfaces.PendingRef, streamID string)) error {
	start := time.Now()
	err := d.inner.WatchPending(ctx, callback)
	d.observe("WatchPending", start, err)
	return err
}
