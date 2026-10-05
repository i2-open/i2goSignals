package eventRouter

import (
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	deliveryInFlightGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "goSignals",
		Subsystem: "router",
		Name:      "delivery_inflight",
		Help:      "JTIs a delivery runner has taken for sending and not yet acked or handed back.",
	}, []string{"stream_id", "transport"})
	ackBatchSizeHist = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "goSignals",
		Subsystem: "router",
		Name:      "delivery_ack_batch_size",
		Help:      "JTIs applied per coalesced delivery ack write.",
		Buckets:   []float64{1, 2, 4, 8, 16, 32, 64, 128, 256, 512},
	}, []string{"transport"})
	pollClaimedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "goSignals",
		Subsystem: "router",
		Name:      "poll_claimed_inflight",
		Help:      "JTIs an RFC 8936 poll stream has returned under an unexpired claim and not yet had acked (#337).",
	}, []string{"stream_id"})
)

// DeliveryCollectors returns the acker's Prometheus collectors for the
// server's registry.
func DeliveryCollectors() []prometheus.Collector {
	return []prometheus.Collector{deliveryInFlightGauge, ackBatchSizeHist, pollClaimedGauge, ackWritesTotal, ackBatchesTotal, readsBeforeAckTotal, queueTimeHist, ackTimeHist}
}

var (
	ackWritesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "goSignals",
		Subsystem: "router",
		Name:      "ack_writes_total",
		Help:      "Acknowledgement writes (EventService.AckBatch calls) made by the delivery queues.",
	})
	ackBatchesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "goSignals",
		Subsystem: "router",
		Name:      "ack_batches_total",
		Help:      "Acknowledgement batches the delivery queues accepted for writing while holding the stream's lease: one per push batch, poll request or SSTP frame that acknowledged anything. A batch skipped for lease tenure is not counted; its retry is.",
	})
	// readsBeforeAckTotal counts coordinator calls made on the acknowledgement
	// path before its AckBatch (#364). The design value is zero: the
	// leaseManager answers ownership from memory.
	readsBeforeAckTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "goSignals",
		Subsystem: "router",
		Name:      "reads_before_ack_total",
		Help:      "Store or coordinator calls made on the acknowledgement path before its write (design value 0).",
	})

	// Transmitter-side waiting (#352). Both are labelled by tfr only, never
	// by stream (community ADR 0047), and observed once per SET at its
	// receiver acknowledgement, for SETs this node handed out.
	queueTimeHist = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "goSignals",
		Subsystem: "router",
		Name:      "queue_time_seconds",
		Help:      "Enqueue time to first hand-out (push request sent, poll response written, SSTP frame sent), by transfer method.",
		Buckets:   waitBuckets,
	}, []string{"tfr"})
	ackTimeHist = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "goSignals",
		Subsystem: "router",
		Name:      "ack_time_seconds",
		Help:      "First hand-out to acknowledgement, by transfer method. Retries and redeliveries count here.",
		Buckets:   waitBuckets,
	}, []string{"tfr"})
)

// waitBuckets spans 5 ms to 60 s for the queue and acknowledgement time
// histograms (#352). The top bound is pinned to exactly 60: the exponential
// series lands a rounding error below it.
var waitBuckets = func() []float64 {
	b := prometheus.ExponentialBucketsRange(0.005, 60, 15)
	b[len(b)-1] = 60
	return b
}()

func init() {
	// Every transfer method has a series from the first scrape, so a
	// dashboard or alert sees zero rather than an absent metric.
	for _, tfr := range []string{tfrPush, tfrPoll, tfrSstp} {
		queueTimeHist.WithLabelValues(tfr)
		ackTimeHist.WithLabelValues(tfr)
	}
}

// tfr label values, as goSignals_router_events_out_total uses them.
const (
	tfrPush = "PUSH"
	tfrPoll = "POLL"
	tfrSstp = "SSTP"
)

// tfrOf is the tfr label of a target stream.
func tfrOf(stream *model.StreamStateRecord) string {
	switch stream.GetType() {
	case model.DeliveryPoll, model.ReceivePoll:
		return tfrPoll
	case model.DeliverySstpPair:
		return tfrSstp
	}
	return tfrPush
}
