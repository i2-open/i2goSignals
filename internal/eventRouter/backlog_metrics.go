package eventRouter

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Per-stream backlog gauges (#352).
//
// Each target stream's backlog is reported by the node that owns it, from that
// node's deliveryQueue: depth and oldest enqueue time are kept in memory
// (Backlog), so a scrape makes no store or coordinator call. Every stream kind
// is leased (#365), so exactly one node reports a stream. A queue this node
// holds for a stream it does not own (a fan-out wake built it, or the lease
// moved) is skipped, and a removed stream's queue is gone, so its series stop
// on the next scrape.

var (
	backlogDepthDesc = prometheus.NewDesc(
		"goSignals_router_stream_backlog_depth",
		"SETs enqueued for the stream and not yet acknowledged, handed out or not. Reported by the stream's owning node.",
		[]string{"stream_id"}, nil)
	backlogOldestAgeDesc = prometheus.NewDesc(
		"goSignals_router_stream_backlog_oldest_age_seconds",
		"Age of the oldest SET in the stream's backlog at scrape time; 0 when the backlog is empty. Reported by the stream's owning node.",
		[]string{"stream_id"}, nil)
)

// backlogCollector reports the backlog gauges of the streams r owns.
type backlogCollector struct {
	r   *router
	now func() time.Time
}

// BacklogCollector returns the Prometheus collector for the per-stream backlog
// gauges of the streams this router owns.
func (r *router) BacklogCollector() prometheus.Collector {
	return &backlogCollector{r: r, now: time.Now}
}

func (c *backlogCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- backlogDepthDesc
	ch <- backlogOldestAgeDesc
}

func (c *backlogCollector) Collect(ch chan<- prometheus.Metric) {
	now := c.now()
	c.r.queues.Range(func(key, value any) bool {
		sid := key.(string)
		resource := c.r.ackResource(sid)
		if resource == "" || !c.r.leases.StillOwner(resource) {
			return true
		}
		depth, oldest := value.(*deliveryQueue).Backlog()
		age := 0.0
		if depth > 0 && !oldest.IsZero() {
			age = max(0, now.Sub(oldest).Seconds())
		}
		ch <- prometheus.MustNewConstMetric(backlogDepthDesc, prometheus.GaugeValue, float64(depth), sid)
		ch <- prometheus.MustNewConstMetric(backlogOldestAgeDesc, prometheus.GaugeValue, age, sid)
		return true
	})
}
