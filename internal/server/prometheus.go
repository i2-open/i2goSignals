package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var pLog = logger.Sub("PROMTH")

type PrometheusHandler struct {
	App                    *SignalsApplication
	EventsIn, EventsOut    *prometheus.CounterVec
	PubPushCnt, PubPollCnt prometheus.GaugeFunc
	RcvPushCnt, RcvPollCnt prometheus.GaugeFunc
	ClusterLeasesHeld      prometheus.Gauge
	ClusterLeaseAcq        *prometheus.CounterVec
	ClusterNodes           prometheus.GaugeFunc

	// Push state-machine instrumentation (PRD #28). Labels are intentionally low-cardinality:
	// stream_id is bounded by the number of configured streams, errClass / from / to / outcome
	// are bounded by enum values defined in goSetPush + push state names + idle outcomes.
	PushFailures           *prometheus.CounterVec
	PushStateTransitions   *prometheus.CounterVec
	PushRecoveryDuration   *prometheus.HistogramVec
	PushIdleVerifyOutcomes *prometheus.CounterVec
}

type streamCollector struct {
	sa           *SignalsApplication
	statusDesc   *prometheus.Desc
	errorDesc    *prometheus.Desc
	createdDesc  *prometheus.Desc
	startDesc    *prometheus.Desc
	modifiedDesc *prometheus.Desc
}

func newStreamCollector(sa *SignalsApplication) *streamCollector {
	return &streamCollector{
		sa: sa,
		statusDesc: prometheus.NewDesc(
			"goSignals_router_stream_status_info",
			"Information about the stream status.",
			[]string{"stream_id", "status"},
			nil,
		),
		errorDesc: prometheus.NewDesc(
			"goSignals_router_stream_error_info",
			"Information about the stream error message.",
			[]string{"stream_id", "error_msg"},
			nil,
		),
		createdDesc: prometheus.NewDesc(
			"goSignals_router_stream_created_at_seconds",
			"Stream creation date in unix seconds.",
			[]string{"stream_id"},
			nil,
		),
		startDesc: prometheus.NewDesc(
			"goSignals_router_stream_start_date_seconds",
			"Stream start date in unix seconds.",
			[]string{"stream_id"},
			nil,
		),
		modifiedDesc: prometheus.NewDesc(
			"goSignals_router_stream_modified_at_seconds",
			"Stream last modification date in unix seconds.",
			[]string{"stream_id"},
			nil,
		),
	}
}

func (c *streamCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.statusDesc
	ch <- c.errorDesc
	ch <- c.createdDesc
	ch <- c.startDesc
	ch <- c.modifiedDesc
}

func (c *streamCollector) Collect(ch chan<- prometheus.Metric) {
	states := c.sa.StreamService.GetStateMap(context.Background())
	for _, state := range states {
		streamID := state.StreamConfiguration.Id
		ch <- prometheus.MustNewConstMetric(c.statusDesc, prometheus.GaugeValue, 1, streamID, state.Status)
		ch <- prometheus.MustNewConstMetric(c.errorDesc, prometheus.GaugeValue, 1, streamID, state.ErrorMsg)
		ch <- prometheus.MustNewConstMetric(c.createdDesc, prometheus.GaugeValue, float64(state.CreatedAt.Unix()), streamID)
		ch <- prometheus.MustNewConstMetric(c.startDesc, prometheus.GaugeValue, float64(state.StartDate.Unix()), streamID)
		ch <- prometheus.MustNewConstMetric(c.modifiedDesc, prometheus.GaugeValue, float64(state.ModifiedAt.Unix()), streamID)
	}
}

type clusterCollector struct {
	sa           *SignalsApplication
	nodeInfoDesc *prometheus.Desc
	uptimeDesc   *prometheus.Desc
	lastSeenDesc *prometheus.Desc
}

func newClusterCollector(sa *SignalsApplication) *clusterCollector {
	return &clusterCollector{
		sa: sa,
		nodeInfoDesc: prometheus.NewDesc(
			"goSignals_cluster_node_info",
			"Information about the cluster nodes.",
			[]string{"node_id", "address", "version"},
			nil,
		),
		uptimeDesc: prometheus.NewDesc(
			"goSignals_cluster_node_uptime_seconds",
			"Node uptime in seconds.",
			[]string{"node_id"},
			nil,
		),
		lastSeenDesc: prometheus.NewDesc(
			"goSignals_cluster_node_last_seen_seconds",
			"Node last seen in unix seconds.",
			[]string{"node_id"},
			nil,
		),
	}
}

func (c *clusterCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.nodeInfoDesc
	ch <- c.uptimeDesc
	ch <- c.lastSeenDesc
}

func (c *clusterCollector) Collect(ch chan<- prometheus.Metric) {
	nodes, err := c.sa.Coordinator.GetActiveNodes()
	if err != nil {
		pLog.Error("Failed to get active nodes", "error", err)
		return
	}
	now := time.Now().UTC()
	for _, node := range nodes {
		ch <- prometheus.MustNewConstMetric(c.nodeInfoDesc, prometheus.GaugeValue, 1, node.Id, node.Address, node.Version)
		uptime := now.Sub(node.StartedAt).Seconds()
		ch <- prometheus.MustNewConstMetric(c.uptimeDesc, prometheus.GaugeValue, uptime, node.Id)
		ch <- prometheus.MustNewConstMetric(c.lastSeenDesc, prometheus.GaugeValue, float64(node.LastSeenAt.Unix()), node.Id)
	}
}

var (
	httpDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "goSignals_http_duration_seconds",
		Help: "Duration of HTTP requests.",
	}, []string{"path"})
)

func PrometheusHttpMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// log.Println("*** GoSignals Prometheus handler called!!")
		route := mux.CurrentRoute(r)
		path, _ := route.GetPathTemplate()
		timer := prometheus.NewTimer(httpDuration.WithLabelValues(path))
		next.ServeHTTP(w, r)
		timer.ObserveDuration()
	})
}

func (h *PrometheusHandler) TrackLeaseAcquisition(resource string, success bool) {
	if h != nil && h.ClusterLeaseAcq != nil {
		status := "failure"
		if success {
			status = "success"
		}
		h.ClusterLeaseAcq.WithLabelValues(resource, status).Inc()
	}
}

func (h *PrometheusHandler) IncLeasesHeld() {
	if h != nil && h.ClusterLeasesHeld != nil {
		h.ClusterLeasesHeld.Inc()
	}
}

func (h *PrometheusHandler) DecLeasesHeld() {
	if h != nil && h.ClusterLeasesHeld != nil {
		h.ClusterLeasesHeld.Dec()
	}
}

// RecordPushFailure satisfies the eventRouter statsTracker contract for push delivery failures.
// errClass is the FailureClass.String() label from goSetPush (e.g. "Forbidden", "Transport").
func (h *PrometheusHandler) RecordPushFailure(sid, errClass string) {
	if h != nil && h.PushFailures != nil {
		h.PushFailures.WithLabelValues(sid, errClass).Inc()
	}
}

// RecordStateTransition is called once per actual stream state change (no-op transitions are
// suppressed at the call site in updateStream). Mirrors the audit log line emitted there.
func (h *PrometheusHandler) RecordStateTransition(sid, from, to string) {
	if h != nil && h.PushStateTransitions != nil {
		h.PushStateTransitions.WithLabelValues(sid, from, to).Inc()
	}
}

// ObservePushRecoveryDuration records the wall-time elapsed between recovery entry and exit
// (any outcome). Bucket boundaries lean toward the long tail because the most actionable
// signal is "this stream sat in recovery for hours" rather than sub-second flicker.
func (h *PrometheusHandler) ObservePushRecoveryDuration(sid string, seconds float64) {
	if h != nil && h.PushRecoveryDuration != nil {
		h.PushRecoveryDuration.WithLabelValues(sid).Observe(seconds)
	}
}

// RecordIdleVerifyOutcome counts verify-event push outcomes. Outcome is "acked" or "failed".
// In production this counter is dominated by T3 idle keepalives; operator-triggered verifies
// also pass through and contribute (rare).
func (h *PrometheusHandler) RecordIdleVerifyOutcome(sid, outcome string) {
	if h != nil && h.PushIdleVerifyOutcomes != nil {
		h.PushIdleVerifyOutcomes.WithLabelValues(sid, outcome).Inc()
	}
}

func (sa *SignalsApplication) InitializePrometheus() {
	sa.InitializePrometheusWithRegisterer(prometheus.DefaultRegisterer)
}

func (sa *SignalsApplication) InitializePrometheusWithRegisterer(reg prometheus.Registerer) {
	prometheusHandler := PrometheusHandler{
		App: sa,
		EventsIn: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "goSignals",
				Subsystem: "router",
				Name:      "events_in_total",
				Help:      "Events received",
			},
			[]string{"type", "iss", "tfr", "stream_id"},
		),
		EventsOut: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "goSignals",
				Subsystem: "router",
				Name:      "events_out_total",
				Help:      "Events delivered",
			},
			[]string{"type", "iss", "tfr", "stream_id"},
		),
		PubPollCnt: prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Namespace: "goSignals",
				Subsystem: "router",
				Name:      "stream_pub_polling_cnt",
				Help:      "Number of SET polling publishers streams",
			},
			func() float64 {
				return sa.EventRouter.GetPollStreamCnt()
			}),
		PubPushCnt: prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Namespace: "goSignals",
				Subsystem: "router",
				Name:      "stream_pub_push_cnt",
				Help:      "Number of SET push publisher streams",
			},
			func() float64 {
				return sa.EventRouter.GetPushStreamCnt()
			}),
		RcvPollCnt: prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Namespace: "goSignals",
				Subsystem: "router",
				Name:      "stream_rcv_poll_cnt",
				Help:      "Number of SET polling receivers",
			},
			func() float64 {
				return sa.GetPollReceiverCnt()
			}),
		RcvPushCnt: prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Namespace: "goSignals",
				Subsystem: "router",
				Name:      "stream_rcv_push_cnt",
				Help:      "Number of SET push receivers",
			},
			func() float64 {
				return sa.GetPushReceiverCnt()
			}),
		ClusterLeasesHeld: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "goSignals",
				Subsystem: "cluster",
				Name:      "leases_held_total",
				Help:      "Number of leases currently held by this node",
			}),
		ClusterLeaseAcq: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "goSignals",
				Subsystem: "cluster",
				Name:      "lease_acquisition_total",
				Help:      "Total lease acquisition attempts",
			},
			[]string{"resource", "status"},
		),
		ClusterNodes: prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Namespace: "goSignals",
				Subsystem: "cluster",
				Name:      "nodes_count",
				Help:      "Number of active nodes in the cluster",
			},
			func() float64 {
				if sa.Coordinator == nil {
					return 0
				}
				count, _ := sa.Coordinator.GetActiveNodeCount()
				return float64(count)
			}),
		PushFailures: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "goSignals",
				Subsystem: "router",
				Name:      "push_failures_total",
				Help:      "Push delivery failures, labeled by stream and FailureClass.",
			},
			[]string{"stream_id", "err_class"},
		),
		PushStateTransitions: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "goSignals",
				Subsystem: "router",
				Name:      "push_state_transitions_total",
				Help:      "Push stream state transitions, mirroring the audit log.",
			},
			[]string{"stream_id", "from", "to"},
		),
		PushRecoveryDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "goSignals",
				Subsystem: "router",
				Name:      "push_recovery_duration_seconds",
				Help:      "Wall-time elapsed inside recoveryLoop, from entry to exit (any outcome).",
				// Long-tail buckets — the operationally interesting question is "how long did
				// this stream sit in recovery", not sub-second flicker. Boundaries cover the
				// 6h transport cap and the 10×15s auth cap with reasonable resolution between.
				Buckets: []float64{1, 5, 30, 60, 300, 900, 3600, 21600},
			},
			[]string{"stream_id"},
		),
		PushIdleVerifyOutcomes: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "goSignals",
				Subsystem: "router",
				Name:      "push_idle_verify_total",
				Help:      "Verify-event push outcomes (T3 idle keepalive + operator-triggered).",
			},
			[]string{"stream_id", "outcome"},
		),
	}

	sa.EventRouter.SetEventCounter(prometheusHandler.EventsIn, prometheusHandler.EventsOut)

	registerTo(reg, prometheusHandler.EventsIn)
	registerTo(reg, prometheusHandler.EventsOut)

	registerTo(reg, prometheusHandler.RcvPollCnt)
	registerTo(reg, prometheusHandler.RcvPushCnt)
	registerTo(reg, prometheusHandler.PubPollCnt)
	registerTo(reg, prometheusHandler.PubPushCnt)
	registerTo(reg, prometheusHandler.ClusterLeasesHeld)
	registerTo(reg, prometheusHandler.ClusterLeaseAcq)
	registerTo(reg, prometheusHandler.ClusterNodes)
	registerTo(reg, prometheusHandler.PushFailures)
	registerTo(reg, prometheusHandler.PushStateTransitions)
	registerTo(reg, prometheusHandler.PushRecoveryDuration)
	registerTo(reg, prometheusHandler.PushIdleVerifyOutcomes)
	registerTo(reg, newStreamCollector(sa))
	registerTo(reg, newClusterCollector(sa))

	// Pre-initialize counters for existing streams
	states := sa.StreamService.GetStateMap(context.Background())
	for _, state := range states {
		sa.EventRouter.PreInitializeCounter(&state)
	}

	sa.Stats = &prometheusHandler
	sa.EventRouter.SetStatsHandler(sa.Stats)
}

func registerTo(reg prometheus.Registerer, collector prometheus.Collector) {
	err := reg.Register(collector)
	if err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if errors.As(err, &alreadyRegisteredError) {
			// Already registered, this is fine (e.g. in tests)
			return
		}
		pLog.Error("instrumentation error", "error", err)
	}
}

func registerCollector(collector prometheus.Collector) {
	registerTo(prometheus.DefaultRegisterer, collector)
}
