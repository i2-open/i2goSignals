package server

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type PrometheusHandler struct {
	App                    *SignalsApplication
	EventsIn, EventsOut    *prometheus.CounterVec
	PubPushCnt, PubPollCnt prometheus.GaugeFunc
	RcvPushCnt, RcvPollCnt prometheus.GaugeFunc
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
			[]string{"type", "iss", "tfr"},
		),
		EventsOut: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "goSignals",
				Subsystem: "router",
				Name:      "events_out",
				Help:      "Events delivered",
			},
			[]string{"type", "iss", "tfr"},
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
				return sa.GetPollReceiverCnt()
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

	sa.Stats = &prometheusHandler
}

func registerCollector(collector prometheus.Collector) {
	err := prometheus.Register(collector)
	if err != nil {
		log.Println("WARNING: instrumentation error:" + err.Error())
	}
}
