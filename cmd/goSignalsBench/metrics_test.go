package main

import (
	"strings"
	"testing"
)

func TestParseCounters(t *testing.T) {
	text := `# HELP goSignals_router_events_in_total events received
# TYPE goSignals_router_events_in_total counter
goSignals_router_events_in_total{iss="a",stream_id="rx1",tfr="PUSH",type="urn:x"} 7
goSignals_router_events_in_total{iss="a",stream_id="rx1",tfr="PUSH",type="urn:y"} 3
goSignals_router_events_in_total{iss="a",stream_id="rx2",tfr="POLL",type="urn:x"} 2.5 1700000000
goSignals_router_events_out_total{iss="a",stream_id="tx1",tfr="PUSH",type="urn:x"} 9
goSignals_http_duration_seconds_bucket{path="/events",le="0.005"} 12
`
	c, err := parseCounters(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.In["rx1"]; got != 10 {
		t.Errorf("rx1 in = %v, want 10", got)
	}
	if got := c.In["rx2"]; got != 2.5 {
		t.Errorf("rx2 in = %v, want 2.5", got)
	}
	if got := c.Out["tx1"]; got != 9 {
		t.Errorf("tx1 out = %v, want 9", got)
	}
	if _, present := c.In["tx1"]; present {
		t.Errorf("tx1 should not appear in the in-counters")
	}
}

func TestParseSampleRejectsMalformed(t *testing.T) {
	for _, line := range []string{
		`goSignals_router_events_in_total 5`,
		`goSignals_router_events_in_total{stream_id="x"}`,
		`goSignals_router_events_in_total{tfr="PUSH"} 5`,
	} {
		if _, _, ok := parseSample(line); ok {
			t.Errorf("expected %q to be rejected", line)
		}
	}
}
