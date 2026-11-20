package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// Workers alternate between the cluster members: even -> gs1, odd -> gs1b.
func TestIngestTargetAlternates(t *testing.T) {
	for w := 0; w < 6; w++ {
		if got := ingestTarget(w, 1); got != 0 {
			t.Errorf("single node: worker %d -> %d, want 0", w, got)
		}
		want := w % 2
		if got := ingestTarget(w, 2); got != want {
			t.Errorf("two nodes: worker %d -> %d, want %d", w, got, want)
		}
	}
}

// gs1b has registered a stream once /metrics carries an events_in_total
// series for it, even at value 0 (outbound streams report type="NONE").
func TestMissingStreamsFromMetrics(t *testing.T) {
	body := `# HELP goSignals_router_events_in_total Events received by the router.
# TYPE goSignals_router_events_in_total counter
goSignals_router_events_in_total{iss="https://bench",stream_id="ingress1",tfr="PUSH",type="INBOUND"} 0
goSignals_router_events_in_total{iss="",stream_id="txpush1",tfr="",type="NONE"} 0
goSignals_router_events_in_total{iss="",stream_id="sstp1",tfr="",type="NONE"} 0
goSignals_router_events_out_total{iss="",stream_id="txpoll1",tfr="",type="NONE"} 0
`
	c, err := parseCounters(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if got := missingStreams(c, []string{"txpush1", "sstp1"}); len(got) != 0 {
		t.Errorf("registered streams reported missing: %v", got)
	}
	// txpoll1 only has an events_out series, which does not count as registered.
	got := missingStreams(c, []string{"txpush1", "txpoll1", "nope"})
	if len(got) != 2 || got[0] != "txpoll1" || got[1] != "nope" {
		t.Errorf("missing = %v, want [txpoll1 nope]", got)
	}
}

// A single-node run must serialize exactly as before: no gs1b fields at all.
func TestResultJSONOmitsGs1bWhenUnset(t *testing.T) {
	data, err := json.Marshal(&benchResult{Events: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"gs1b"`, `"ingest_split"`, `"dao_gs1b"`, `"gs1b_sync_seconds"`} {
		if strings.Contains(string(data), key) {
			t.Errorf("single-node result should not carry %s: %s", key, data)
		}
	}
	data, err = json.Marshal(&benchResult{Gs1b: "https://localhost:8887", IngestSplit: &ingestSplit{Gs1: 3, Gs1b: 2}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"gs1b":"https://localhost:8887"`, `"ingest_split":{"gs1":3,"gs1b":2}`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("cluster result missing %s: %s", want, data)
		}
	}
}
