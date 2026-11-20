package main

import (
	"strings"
	"testing"
)

const propertyExposition = `# TYPE goSignals_router_ack_writes_total counter
goSignals_router_ack_writes_total 40
goSignals_router_ack_batches_total 100
goSignals_router_reads_under_lock_total 0
goSignals_router_reads_before_ack_total 2
goSignals_router_peer_claims_total{mode="poll-transmitter",result="served"} 7
goSignals_router_peer_claims_total{mode="sstp-server",result="served"} 3
goSignals_router_peer_claims_total{mode="poll-transmitter",result="empty"} 11
goSignals_router_peer_claim_budget_exhausted_total 1
goSignals_router_ack_batch_size_bucket{le="1"} 5
`

func TestParseRouterProperties(t *testing.T) {
	p, err := parseRouterProperties(strings.NewReader(propertyExposition))
	if err != nil {
		t.Fatal(err)
	}
	want := routerProperties{AckWrites: 40, AckBatches: 100, ReadsUnderLock: 0, ReadsBeforeAck: 2, PeerClaimsServed: 10, PeerClaimBudgetExhausted: 1}
	if p != want {
		t.Fatalf("got %+v want %+v", p, want)
	}
}

func TestSummarizeProperties_DiffsAndSumsNodes(t *testing.T) {
	before := []routerProperties{{AckWrites: 10, AckBatches: 20}, {AckWrites: 1, AckBatches: 1}}
	after := []routerProperties{
		{AckWrites: 30, AckBatches: 70, ReadsUnderLock: 0, ReadsBeforeAck: 0, PeerClaimsServed: 4},
		{AckWrites: 11, AckBatches: 31, PeerClaimsServed: 6, PeerClaimBudgetExhausted: 2},
	}
	s := summarizeProperties(before, after)
	if s.AckWrites != 30 || s.AckBatches != 80 {
		t.Fatalf("writes/batches: %+v", s)
	}
	if s.AckWritesPerBatch != 0.375 {
		t.Fatalf("writes per batch %v", s.AckWritesPerBatch)
	}
	if s.PeerClaimsServed != 10 || s.PeerClaimBudgetExhausted != 2 || s.ReadsUnderLock != 0 || s.ReadsBeforeAck != 0 {
		t.Fatalf("claims/reads: %+v", s)
	}
}

func TestSummarizeProperties_NoBatches(t *testing.T) {
	s := summarizeProperties([]routerProperties{{}}, []routerProperties{{}})
	if s.AckWritesPerBatch != 0 {
		t.Fatalf("no batches must report 0, got %v", s.AckWritesPerBatch)
	}
}

func TestBeyondQueryCost(t *testing.T) {
	stats := map[string]daoOpStats{
		"GetPendingForStream":       {Calls: 10, MeanMs: 1.0},
		"GetPendingForStreamBeyond": {Calls: 4, MeanMs: 1.5},
	}
	c := beyondQueryCost(stats)
	if c == nil || c.BeyondCalls != 4 || c.BeyondMeanMs != 1.5 || c.PlainCalls != 10 || c.PlainMeanMs != 1.0 {
		t.Fatalf("got %+v", c)
	}
	if beyondQueryCost(map[string]daoOpStats{"Ack": {Calls: 1}}) != nil {
		t.Fatal("no GetPendingForStream calls: no cost line")
	}
}

func TestReceiverLegBase(t *testing.T) {
	if got := receiverLegBase("https://gs1:8888", ""); got != "https://gs1:8888" {
		t.Fatalf("unset --gs1b-internal keeps goSignals1: %s", got)
	}
	if got := receiverLegBase("https://gs1:8888", "https://gs1b:8887/"); got != "https://gs1b:8887" {
		t.Fatalf("--gs1b-internal rebases onto the second node: %s", got)
	}
}

func TestSstpResponderBase(t *testing.T) {
	gs1 := &node{name: "goSignals1", internalBase: "https://gs1:8888"}
	gs2 := &node{name: "goSignals2", internalBase: "https://gs2:8889"}
	o := &options{gs1bInternal: "https://gs1b:8887"}
	// goSignals1 responds: goSignals2 dials the second node.
	if got := sstpResponderBase(gs1, gs1, o); got != "https://gs1b:8887" {
		t.Fatalf("responder gs1 with --gs1b-internal: %s", got)
	}
	// goSignals2 responds (goSignals1 initiates): the flag does not apply.
	if got := sstpResponderBase(gs2, gs1, o); got != "https://gs2:8889" {
		t.Fatalf("responder gs2: %s", got)
	}
	o.gs1bInternal = ""
	if got := sstpResponderBase(gs1, gs1, o); got != "https://gs1:8888" {
		t.Fatalf("responder gs1 without the flag: %s", got)
	}
}

func TestValidateGs1bInternalNeedsGs1b(t *testing.T) {
	if err := validateGs1bInternal(&options{gs1bInternal: "https://gs1b:8887"}); err == nil {
		t.Fatal("--gs1b-internal without --gs1b must be rejected")
	}
	if err := validateGs1bInternal(&options{gs1b: "https://localhost:8887", gs1bInternal: "https://gs1b:8887"}); err != nil {
		t.Fatal(err)
	}
	if err := validateGs1bInternal(&options{}); err != nil {
		t.Fatal(err)
	}
}
