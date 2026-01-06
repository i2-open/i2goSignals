package server

import (
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var pLog = log.New(os.Stdout, "PROMTH: ", log.Ldate|log.Ltime)

type PrometheusHandler struct {
	App                    *SignalsApplication
	EventsIn, EventsOut    *prometheus.CounterVec
	PubPushCnt, PubPollCnt prometheus.GaugeFunc
	RcvPushCnt, RcvPollCnt prometheus.GaugeFunc
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
	states := c.sa.Provider.GetStateMap()
	for _, state := range states {
		streamID := state.StreamConfiguration.Id
		ch <- prometheus.MustNewConstMetric(c.statusDesc, prometheus.GaugeValue, 1, streamID, state.Status)
		ch <- prometheus.MustNewConstMetric(c.errorDesc, prometheus.GaugeValue, 1, streamID, state.ErrorMsg)
		ch <- prometheus.MustNewConstMetric(c.createdDesc, prometheus.GaugeValue, float64(state.CreatedAt.Unix()), streamID)
		ch <- prometheus.MustNewConstMetric(c.startDesc, prometheus.GaugeValue, float64(state.StartDate.Unix()), streamID)
		ch <- prometheus.MustNewConstMetric(c.modifiedDesc, prometheus.GaugeValue, float64(state.ModifiedAt.Unix()), streamID)
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

func (sa *SignalsApplication) InitializePrometheus() {
	prometheusHandler := PrometheusHandler{
		App: sa,
		EventsIn: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "goSignals",
				Subsystem: "router",
				Name:      "events_in",
				Help:      "Events received",
			},
			[]string{"type", "iss", "tfr", "stream_id"},
		),
		EventsOut: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "goSignals",
				Subsystem: "router",
				Name:      "events_out",
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
	}
	registerCollector(prometheusHandler.EventsIn)

	registerCollector(prometheusHandler.EventsOut)
	// this is to handle poll
	sa.EventRouter.SetEventCounter(prometheusHandler.EventsIn, prometheusHandler.EventsOut) // this is to handle push
	registerCollector(prometheusHandler.RcvPollCnt)
	registerCollector(prometheusHandler.RcvPushCnt)
	registerCollector(prometheusHandler.PubPollCnt)
	registerCollector(prometheusHandler.PubPushCnt)
	registerCollector(newStreamCollector(sa))

	sa.Stats = &prometheusHandler
}

func registerCollector(collector prometheus.Collector) {

	err := prometheus.Register(collector)
	if err != nil {
		pLog.Println("WARNING: instrumentation error:" + err.Error())
	}

}
