package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// Router counters behind planning #112's verified properties (#366): one
// acknowledgement write per coalesced batch, no store or coordinator read
// under the router lock, no read on the acknowledgement path before its
// write, and the claims a lease owner answered for its peers.
const (
	metricAckWrites           = "goSignals_router_ack_writes_total"
	metricAckBatches          = "goSignals_router_ack_batches_total"
	metricReadsUnderLock      = "goSignals_router_reads_under_lock_total"
	metricReadsBeforeAck      = "goSignals_router_reads_before_ack_total"
	metricPeerClaims          = "goSignals_router_peer_claims_total"
	metricPeerClaimsExhausted = "goSignals_router_peer_claim_budget_exhausted_total"
)

// routerProperties is one scrape of the property counters on one node.
type routerProperties struct {
	AckWrites                float64
	AckBatches               float64
	ReadsUnderLock           float64
	ReadsBeforeAck           float64
	PeerClaimsServed         float64 // peer_claims_total{result="served"}, every mode
	PeerClaimBudgetExhausted float64
}

func (p routerProperties) sub(b routerProperties) routerProperties {
	return routerProperties{
		AckWrites:                p.AckWrites - b.AckWrites,
		AckBatches:               p.AckBatches - b.AckBatches,
		ReadsUnderLock:           p.ReadsUnderLock - b.ReadsUnderLock,
		ReadsBeforeAck:           p.ReadsBeforeAck - b.ReadsBeforeAck,
		PeerClaimsServed:         p.PeerClaimsServed - b.PeerClaimsServed,
		PeerClaimBudgetExhausted: p.PeerClaimBudgetExhausted - b.PeerClaimBudgetExhausted,
	}
}

func (p routerProperties) add(b routerProperties) routerProperties {
	return routerProperties{
		AckWrites:                p.AckWrites + b.AckWrites,
		AckBatches:               p.AckBatches + b.AckBatches,
		ReadsUnderLock:           p.ReadsUnderLock + b.ReadsUnderLock,
		ReadsBeforeAck:           p.ReadsBeforeAck + b.ReadsBeforeAck,
		PeerClaimsServed:         p.PeerClaimsServed + b.PeerClaimsServed,
		PeerClaimBudgetExhausted: p.PeerClaimBudgetExhausted + b.PeerClaimBudgetExhausted,
	}
}

// propertyStats is the run's property report: the counters diffed over the
// run and summed over goSignals1's cluster members (gs1, plus gs1b when set),
// which hold the transmitter streams.
type propertyStats struct {
	AckWrites                int     `json:"ack_writes"`
	AckBatches               int     `json:"ack_batches"`
	AckWritesPerBatch        float64 `json:"ack_writes_per_batch"`
	ReadsUnderLock           int     `json:"reads_under_lock"`
	ReadsBeforeAck           int     `json:"reads_before_ack"`
	PeerClaimsServed         int     `json:"peer_claims_served"`
	PeerClaimBudgetExhausted int     `json:"peer_claim_budget_exhausted"`
}

// scrapeRouterProperties fetches /metrics and reads the property counters.
func (n *node) scrapeRouterProperties() (routerProperties, error) {
	resp, err := n.http.Get(n.hostBase + "/metrics")
	if err != nil {
		return routerProperties{}, fmt.Errorf("%s metrics: %w", n.name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return routerProperties{}, fmt.Errorf("%s metrics: HTTP %d", n.name, resp.StatusCode)
	}
	return parseRouterProperties(resp.Body)
}

func parseRouterProperties(r io.Reader) (routerProperties, error) {
	var p routerProperties
	plain := map[string]*float64{
		metricAckWrites:           &p.AckWrites,
		metricAckBatches:          &p.AckBatches,
		metricReadsUnderLock:      &p.ReadsUnderLock,
		metricReadsBeforeAck:      &p.ReadsBeforeAck,
		metricPeerClaimsExhausted: &p.PeerClaimBudgetExhausted,
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, metricPeerClaims+"{") {
			labels, v, ok := parseLabelledSample(line)
			if ok && labels["result"] == "served" {
				p.PeerClaimsServed += v
			}
			continue
		}
		name, rest, found := strings.Cut(line, " ")
		if !found {
			continue
		}
		target, ok := plain[name]
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		if v, err := strconv.ParseFloat(fields[0], 64); err == nil {
			*target = v
		}
	}
	return p, scanner.Err()
}

// summarizeProperties diffs each node's after-scrape against its before-scrape
// and sums the nodes.
func summarizeProperties(before, after []routerProperties) *propertyStats {
	var total routerProperties
	for i := range after {
		total = total.add(after[i].sub(before[i]))
	}
	s := &propertyStats{
		AckWrites:                int(total.AckWrites),
		AckBatches:               int(total.AckBatches),
		ReadsUnderLock:           int(total.ReadsUnderLock),
		ReadsBeforeAck:           int(total.ReadsBeforeAck),
		PeerClaimsServed:         int(total.PeerClaimsServed),
		PeerClaimBudgetExhausted: int(total.PeerClaimBudgetExhausted),
	}
	if total.AckBatches > 0 {
		s.AckWritesPerBatch = total.AckWrites / total.AckBatches
	}
	return s
}

// beyondCost compares GetPendingForStream pages that held every pending row
// with those that did not and so also read PendingPage.OldestBeyond
// (op GetPendingForStreamBeyond, #366). The mean difference is the cost of
// that query.
type beyondCost struct {
	PlainCalls   int     `json:"plain_calls"`
	PlainMeanMs  float64 `json:"plain_mean_ms"`
	BeyondCalls  int     `json:"beyond_calls"`
	BeyondMeanMs float64 `json:"beyond_mean_ms"`
}

const (
	opPendingPage       = "GetPendingForStream"
	opPendingPageBeyond = "GetPendingForStreamBeyond"
)

// beyondQueryCost reads the two op labels from a node's DAO stats, or nil
// when the node served no pending page at all.
func beyondQueryCost(stats map[string]daoOpStats) *beyondCost {
	plain, okP := stats[opPendingPage]
	beyond, okB := stats[opPendingPageBeyond]
	if !okP && !okB {
		return nil
	}
	return &beyondCost{PlainCalls: plain.Calls, PlainMeanMs: plain.MeanMs, BeyondCalls: beyond.Calls, BeyondMeanMs: beyond.MeanMs}
}

// receiverLegBase is the base URL goSignals2 reaches the poll transmitter
// (and, with --sstp-role responder, the SSTP responder) at: the --gs1b node
// when --gs1b-internal is set, goSignals1 otherwise.
func receiverLegBase(gs1Internal, gs1bInternal string) string {
	if gs1bInternal != "" {
		return strings.TrimRight(gs1bInternal, "/")
	}
	return gs1Internal
}

// sstpResponderBase is the base the SSTP initiator dials. When goSignals1
// responds, goSignals2 dials the --gs1b node if --gs1b-internal is set.
func sstpResponderBase(responder, gs1 *node, o *options) string {
	if responder == gs1 {
		return receiverLegBase(gs1.internalBase, o.gs1bInternal)
	}
	return responder.internalBase
}

// validateGs1bInternal rejects --gs1b-internal without --gs1b: the receiver
// legs can only move to a node the run already knows is up.
func validateGs1bInternal(o *options) error {
	if o.gs1bInternal != "" && o.gs1b == "" {
		return errors.New("--gs1b-internal needs --gs1b")
	}
	return nil
}

// scrapeAllProperties scrapes the property counters on every node, failing if
// any node cannot be read.
func scrapeAllProperties(nodes []*node) ([]routerProperties, error) {
	out := make([]routerProperties, len(nodes))
	for i, n := range nodes {
		p, err := n.scrapeRouterProperties()
		if err != nil {
			return nil, err
		}
		out[i] = p
	}
	return out, nil
}
