package main

import (
	"strings"
	"testing"
)

const ageBefore = `# TYPE goSignals_router_event_age_at_receipt_seconds histogram
goSignals_router_event_age_at_receipt_seconds_bucket{tfr="PUSH",le="0.001"} 3
goSignals_router_event_age_at_receipt_seconds_bucket{tfr="PUSH",le="0.01"} 5
goSignals_router_event_age_at_receipt_seconds_bucket{tfr="PUSH",le="0.1"} 5
goSignals_router_event_age_at_receipt_seconds_bucket{tfr="PUSH",le="+Inf"} 5
goSignals_router_event_age_at_receipt_seconds_sum{tfr="PUSH"} 0.02
goSignals_router_event_age_at_receipt_seconds_count{tfr="PUSH"} 5
goSignals_router_event_age_at_receipt_seconds_bucket{tfr="POLL",le="0.001"} 0
goSignals_router_event_age_at_receipt_seconds_bucket{tfr="POLL",le="0.01"} 7
goSignals_router_event_age_at_receipt_seconds_bucket{tfr="POLL",le="0.1"} 7
goSignals_router_event_age_at_receipt_seconds_bucket{tfr="POLL",le="+Inf"} 7
goSignals_router_event_age_at_receipt_seconds_sum{tfr="POLL"} 0.03
goSignals_router_event_age_at_receipt_seconds_count{tfr="POLL"} 7
goSignals_router_events_in_total{iss="x",stream_id="s",tfr="PUSH",type="t"} 5
`

// After: PUSH gained 100 SETs, 50 aged 1ms..10ms and 50 aged 10ms..100ms;
// POLL is unchanged; SSTP is new, with 9 SETs under 1ms and 1 beyond 100ms.
const ageAfter = `goSignals_router_event_age_at_receipt_seconds_bucket{tfr="PUSH",le="0.001"} 3
goSignals_router_event_age_at_receipt_seconds_bucket{tfr="PUSH",le="0.01"} 55
goSignals_router_event_age_at_receipt_seconds_bucket{tfr="PUSH",le="0.1"} 105
goSignals_router_event_age_at_receipt_seconds_bucket{tfr="PUSH",le="+Inf"} 105
goSignals_router_event_age_at_receipt_seconds_sum{tfr="PUSH"} 3.02
goSignals_router_event_age_at_receipt_seconds_count{tfr="PUSH"} 105
goSignals_router_event_age_at_receipt_seconds_bucket{tfr="POLL",le="0.001"} 0
goSignals_router_event_age_at_receipt_seconds_bucket{tfr="POLL",le="0.01"} 7
goSignals_router_event_age_at_receipt_seconds_bucket{tfr="POLL",le="0.1"} 7
goSignals_router_event_age_at_receipt_seconds_bucket{tfr="POLL",le="+Inf"} 7
goSignals_router_event_age_at_receipt_seconds_sum{tfr="POLL"} 0.03
goSignals_router_event_age_at_receipt_seconds_count{tfr="POLL"} 7
goSignals_router_event_age_at_receipt_seconds_bucket{tfr="SSTP",le="0.001"} 9
goSignals_router_event_age_at_receipt_seconds_bucket{tfr="SSTP",le="0.01"} 9
goSignals_router_event_age_at_receipt_seconds_bucket{tfr="SSTP",le="0.1"} 9
goSignals_router_event_age_at_receipt_seconds_bucket{tfr="SSTP",le="+Inf"} 10
goSignals_router_event_age_at_receipt_seconds_sum{tfr="SSTP"} 0.5
goSignals_router_event_age_at_receipt_seconds_count{tfr="SSTP"} 10
`

func mustParseAge(t *testing.T, text string) histograms {
	t.Helper()
	h, err := parseEventAgeHistograms(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// TestDeliveryLatency_PerLegFromHistogramDiff: the harness diffs the
// receiver's event-age histogram across the run and reports p50/p95/p99/max
// per transfer type, covering only the SETs this run delivered (#325).
func TestDeliveryLatency_PerLegFromHistogramDiff(t *testing.T) {
	got := summarizeDeliveryLatency(diffHistograms(mustParseAge(t, ageBefore), mustParseAge(t, ageAfter)))

	if _, ok := got["POLL"]; ok {
		t.Errorf("POLL delivered nothing during the run, want it absent: %+v", got["POLL"])
	}

	push, ok := got["PUSH"]
	if !ok {
		t.Fatalf("PUSH missing: %+v", got)
	}
	// 50 of 100 in (1ms,10ms], 50 in (10ms,100ms], interpolated linearly.
	want := latencyStats{P50Ms: 10, P95Ms: 91, P99Ms: 98.2, MaxMs: 100}
	if !near(push.P50Ms, want.P50Ms) || !near(push.P95Ms, want.P95Ms) || !near(push.P99Ms, want.P99Ms) || !near(push.MaxMs, want.MaxMs) {
		t.Errorf("PUSH = %+v, want %+v", push, want)
	}

	// Max is the upper bound of the highest bucket that gained a SET; past the
	// last finite bucket it is reported as that bound (a floor).
	sstp := got["SSTP"]
	if !near(sstp.MaxMs, 100) {
		t.Errorf("SSTP max = %v ms, want the 100ms floor of the +Inf bucket", sstp.MaxMs)
	}
	// Rank 5 of 10 falls in the [0, 1ms] bucket holding 9: 5/9 of 1ms.
	if !near(sstp.P50Ms, 5.0/9) {
		t.Errorf("SSTP p50 = %v ms, want 5/9", sstp.P50Ms)
	}
}
