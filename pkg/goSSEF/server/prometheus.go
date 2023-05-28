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
	OpsCounter             prometheus.Counter
	EventsIn, EventsOut    prometheus.Counter
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

func (sa *SignalsApplication) InitializePrometheus() *PrometheusHandler {
	prometheusHandler := PrometheusHandler{
		App: sa,
		OpsCounter: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: sa.Name(),
			Subsystem: "goSignals",
			Name:      "processed_ops_total",
			Help:      "The total number of processed events",
		}),
		EventsIn: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: sa.Name(),
			Subsystem: "goSignals",
			Name:      "events_in",
			Help:      "The total SETs received",
		}),
		EventsOut: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: sa.Name(),
			Subsystem: "goSignals",
			Name:      "events_out",
			Help:      "The total SETs delivered",
		}),
		PubPollCnt: prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Namespace: sa.Name(),
				Subsystem: "goSignals",
				Name:      "pub_polling_streams_cnt",
				Help:      "Number of SET polling publishers streams",
			},
			func() float64 {
				return sa.EventRouter.GetPollStreamCnt()
			}),
		PubPushCnt: prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Namespace: sa.Name(),
				Subsystem: "goSignals",
				Name:      "pub_push_streams_cnt",
				Help:      "Number of SET push publisher streams",
			},
			func() float64 {
				return sa.EventRouter.GetPushStreamCnt()
			}),
		RcvPollCnt: prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Namespace: sa.Name(),
				Subsystem: "goSignals",
				Name:      "rcv_poll_stream_cnt",
				Help:      "Number of SET polling receivers",
			},
			func() float64 {
				return sa.GetPollReceiverCnt()
			}),
		RcvPushCnt: prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Namespace: sa.Name(),
				Subsystem: "goSignals",
				Name:      "rcv_push_stream_cnt",
				Help:      "Number of SET push receivers",
			},
			func() float64 {
				return sa.GetPollReceiverCnt()
			}),
	}
	registerCollector(prometheusHandler.OpsCounter)
	sa.OpsCounter = prometheusHandler.OpsCounter
	registerCollector(prometheusHandler.EventsIn)
	sa.EventsIn = prometheusHandler.EventsIn
	registerCollector(prometheusHandler.EventsOut)
	sa.EventsOut = prometheusHandler.EventsOut                                              // this is to handle poll
	sa.EventRouter.SetEventCounter(prometheusHandler.EventsIn, prometheusHandler.EventsOut) // this is to handle push
	registerCollector(prometheusHandler.RcvPollCnt)
	registerCollector(prometheusHandler.RcvPushCnt)
	registerCollector(prometheusHandler.PubPollCnt)
	registerCollector(prometheusHandler.PubPushCnt)

	return &prometheusHandler
}

func registerCollector(collector prometheus.Collector) {
	err := prometheus.Register(collector)
	if err != nil {
		log.Println("WARNING: instrumentation error:" + err.Error())
	}
}
