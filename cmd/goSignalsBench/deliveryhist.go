package main

import (
	"io"
	"math"
	"sort"
)

// Per-event delivery latency (i2goSignals#325). The harness stamps toe on each
// SET just before its POST; goSignals2 observes receipt time minus toe into
// this histogram, labelled by the receiving transfer type. The harness scrapes
// it before and after the run and reports the quantiles of the difference.
const metricEventAge = "goSignals_router_event_age_at_receipt_seconds"

// scrapeEventAge fetches /metrics and parses the event-age histogram by tfr.
func (n *node) scrapeEventAge() (daoHistograms, error) {
	return n.scrapeHistograms(metricEventAge, "tfr")
}

func parseEventAgeHistograms(r io.Reader) (daoHistograms, error) {
	return parseHistograms(r, metricEventAge, "tfr")
}

// maxBound is the upper bound (seconds) of the highest bucket holding a
// sample: the histogram's best estimate of the maximum, never below it. When
// the highest sample is past the last finite bucket it returns that bucket's
// bound, which is then a floor.
func (h *opHistogram) maxBound() float64 {
	bounds := make([]float64, 0, len(h.Buckets))
	for le := range h.Buckets {
		bounds = append(bounds, le)
	}
	sort.Float64s(bounds)
	if len(bounds) == 0 {
		return 0
	}
	total := h.Buckets[bounds[len(bounds)-1]]
	prevBound := 0.0
	for _, le := range bounds {
		if h.Buckets[le] >= total {
			if math.IsInf(le, 1) {
				return prevBound
			}
			return le
		}
		prevBound = le
	}
	return prevBound
}

// summarizeDeliveryLatency turns a diffed event-age histogram set into
// per-tfr latency stats (milliseconds).
func summarizeDeliveryLatency(d daoHistograms) map[string]latencyStats {
	out := make(map[string]latencyStats, len(d))
	for tfr, h := range d {
		out[tfr] = latencyStats{
			P50Ms: h.quantile(0.50) * 1000,
			P95Ms: h.quantile(0.95) * 1000,
			P99Ms: h.quantile(0.99) * 1000,
			MaxMs: h.maxBound() * 1000,
		}
	}
	return out
}
