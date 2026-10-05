package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// legResult records one downstream leg (goSignals1 -> goSignals2).
type legResult struct {
	Transport string `json:"transport"` // PUSH, POLL or SSTP
	Audience  string `json:"audience"`
	TxStream  string `json:"tx_stream"`             // goSignals1 transmitter stream id (SSTP: goSignals1 pair id)
	RxStream  string `json:"rx_stream"`             // goSignals2 receiver stream id (SSTP: goSignals2 inbound sid)
	RxStream2 string `json:"rx_stream_2,omitempty"` // POLL with --poll-targets both: the receiver at gs1b
	Expected  int    `json:"expected"`
	Delivered int    `json:"delivered"`
	// DrainSeconds is measured from the END of ingest until the last event
	// arrived on goSignals2 (0 when the leg kept up with ingest).
	DrainSeconds float64 `json:"drain_seconds"`
	// EndToEndSeconds is from the START of ingest until the last event arrived.
	EndToEndSeconds float64 `json:"end_to_end_seconds"`
	EventsPerSecond float64 `json:"events_per_second"`
	Complete        bool    `json:"complete"`
	// DeliveryLatency is per-SET ingest-to-receiver latency: goSignals2's
	// receipt time minus the toe the harness stamped just before the POST,
	// from the event-age histogram diffed over the run (#325). Absent when
	// the leg carried nothing or goSignals2 does not expose the histogram.
	DeliveryLatency *latencyStats `json:"delivery_latency,omitempty"`
}

type latencyStats struct {
	P50Ms float64 `json:"p50_ms"`
	P95Ms float64 `json:"p95_ms"`
	P99Ms float64 `json:"p99_ms"`
	MaxMs float64 `json:"max_ms"`
}

type benchResult struct {
	Timestamp   time.Time `json:"timestamp"`
	Label       string    `json:"label,omitempty"`
	Note        string    `json:"note,omitempty"` // --note: the change or reason behind the run
	GitRevision string    `json:"git_revision,omitempty"`
	GoVersion   string    `json:"go_version"`
	Host        string    `json:"host"`
	Events      int       `json:"events"`
	Concurrency int       `json:"concurrency"`
	Mix         string    `json:"mix"`
	Issuer      string    `json:"issuer"`
	// SstpRole is the SSTP HTTP role goSignals1 plays: "initiator" (goSignals1
	// dials goSignals2 and carries the events in its requests) or "responder"
	// (goSignals2 dials goSignals1 and receives the events in the responses).
	SstpRole string `json:"sstp_role"`
	// Workers records the server-side worker setting of the run (--workers);
	// the harness cannot set it, the servers are started with it.
	Workers string `json:"workers,omitempty"`
	// SigningAlg is the signing_alg the transmitter streams were created with
	// (--signing-alg); "" means the server default. Durability is the ingress
	// stream's durability (--durability); "" means the server default.
	SigningAlg string `json:"signing_alg,omitempty"`
	Durability string `json:"durability,omitempty"`

	IngressStream string `json:"ingress_stream"`

	// Gs1b is the second member of goSignals1's cluster that shared the
	// ingest load (--gs1b); IngestSplit is how many SETs each member accepted
	// (worker-side 202 counts). Gs1bSyncSeconds is how long the harness waited
	// after creating the streams for gs1b to register the outbound streams
	// (peers sync every 40 s). All three are absent on a single-node run.
	Gs1b            string       `json:"gs1b,omitempty"`
	IngestSplit     *ingestSplit `json:"ingest_split,omitempty"`
	Gs1bSyncSeconds float64      `json:"gs1b_sync_seconds,omitempty"`
	// Gs1bInternal is --gs1b-internal: when set, goSignals2 polled the gs1b
	// node and (SSTP responder role) dialed it, instead of goSignals1.
	Gs1bInternal string `json:"gs1b_internal,omitempty"`
	// PollTargets is --poll-targets ("both": one goSignals2 poll receiver per
	// node); PollPinOwner is --poll-pin-owner (gs1b held the poll lease and
	// goSignals2 polled goSignals1).
	PollTargets  string `json:"poll_targets,omitempty"`
	PollPinOwner bool   `json:"poll_pin_owner,omitempty"`

	// Ingest: harness -> goSignals1 push-receive endpoint.
	IngestSeconds         float64      `json:"ingest_seconds"`
	IngestEventsPerSecond float64      `json:"ingest_events_per_second"`
	IngestErrors          int          `json:"ingest_errors"`
	IngestLatency         latencyStats `json:"ingest_latency"`
	IngressCounted        int          `json:"ingress_counted"` // events_in_total for the ingress stream, summed over gs1 (+ gs1b)

	Push legResult `json:"push"`
	Poll legResult `json:"poll"`
	Sstp legResult `json:"sstp"`

	// TotalSeconds is from first push until every leg drained (or timeout).
	TotalSeconds float64 `json:"total_seconds"`
	Success      bool    `json:"success"`
	Notes        string  `json:"notes,omitempty"`

	Profiles []string `json:"profiles,omitempty"`

	// DaoGs1 / DaoGs2 are the EventDAO latency histograms (i2goSignals#328)
	// accumulated during the run on each node, keyed by op.
	DaoGs1        map[string]daoOpStats `json:"dao_gs1,omitempty"`
	DaoGs1b       map[string]daoOpStats `json:"dao_gs1b,omitempty"` // --gs1b node only
	DaoGs2        map[string]daoOpStats `json:"dao_gs2,omitempty"`
	DominantDaoOp string                `json:"dominant_dao_op,omitempty"` // most total wall time on goSignals1
	// BeyondGs1 / BeyondGs1b compare GetPendingForStream pages with and
	// without the OldestBeyond read (#366), from the DAO histograms above.
	BeyondGs1  *beyondCost `json:"oldest_beyond_gs1,omitempty"`
	BeyondGs1b *beyondCost `json:"oldest_beyond_gs1b,omitempty"`
	// Properties are planning #112's verified-property counters, diffed over
	// the run and summed over goSignals1's cluster members (#366).
	Properties *propertyStats `json:"properties,omitempty"`
	// Journal is the WiredTiger journal delta on the Mongo primary (--mongo-uri).
	Journal *journalResult `json:"journal,omitempty"`
}

// ingestSplit is the number of SETs each cluster member accepted (202) when
// ingest was spread over --gs1 and --gs1b.
type ingestSplit struct {
	Gs1  int `json:"gs1"`
	Gs1b int `json:"gs1b"`
}

func percentiles(durations []time.Duration) latencyStats {
	if len(durations) == 0 {
		return latencyStats{}
	}
	sorted := make([]time.Duration, len(durations))
	copy(sorted, durations)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	pick := func(p float64) float64 {
		idx := int(float64(len(sorted)-1) * p)
		return float64(sorted[idx]) / float64(time.Millisecond)
	}
	return latencyStats{
		P50Ms: pick(0.50),
		P95Ms: pick(0.95),
		P99Ms: pick(0.99),
		MaxMs: float64(sorted[len(sorted)-1]) / float64(time.Millisecond),
	}
}

func gitRevision() string {
	out, err := exec.Command("git", "describe", "--always", "--dirty", "--tags").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func hostDescription() string {
	host, _ := os.Hostname()
	return fmt.Sprintf("%s %s/%s %d cpus", host, runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
}

// writeJSON saves the full result under dir as bench-<timestamp>.json.
func writeJSON(dir string, r *benchResult) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "bench-"+r.Timestamp.UTC().Format("20060102T150405Z")+".json")
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return path, os.WriteFile(path, data, 0o644)
}

const historyHeader = `# End-to-end benchmark history

Appended by ` + "`goSignalsBench --history`" + ` (see [e2e-benchmark.md](e2e-benchmark.md)).
One row per run; compare like with like (same events, concurrency, mix and machine class).

| Date (UTC) | Revision | Label | Events | Conc | Mix | Ingest ev/s | Ingest p50/p99 ms | Push ev/s | Push drain s | Poll ev/s | Poll drain s | SSTP role | SSTP ev/s | SSTP drain s | Push lat p50/p95/p99/max ms | Poll lat p50/p95/p99/max ms | SSTP lat p50/p95/p99/max ms | Total s | OK | Note |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
`

// appendHistory adds one Markdown table row to path, creating the file with
// its header when it does not exist.
func appendHistory(path string, r *benchResult) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() == 0 {
		if _, err := f.WriteString(historyHeader); err != nil {
			return err
		}
	}
	ok := "yes"
	if !r.Success {
		ok = "**no**"
	}
	row := fmt.Sprintf("| %s | %s | %s | %d | %d | %s | %.0f | %.1f / %.1f | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %.1f | %s | %s |\n",
		r.Timestamp.UTC().Format("2006-01-02 15:04"),
		r.GitRevision, r.Label, r.Events, r.Concurrency, r.Mix,
		r.IngestEventsPerSecond, r.IngestLatency.P50Ms, r.IngestLatency.P99Ms,
		legCell(r.Push, "%.0f", r.Push.EventsPerSecond), legCell(r.Push, "%.1f", r.Push.DrainSeconds),
		legCell(r.Poll, "%.0f", r.Poll.EventsPerSecond), legCell(r.Poll, "%.1f", r.Poll.DrainSeconds),
		r.SstpRole,
		legCell(r.Sstp, "%.0f", r.Sstp.EventsPerSecond), legCell(r.Sstp, "%.1f", r.Sstp.DrainSeconds),
		latencyCell(r.Push), latencyCell(r.Poll), latencyCell(r.Sstp),
		r.TotalSeconds, ok, strings.ReplaceAll(r.Note, "|", "\\|"))
	_, err = f.WriteString(row)
	return err
}

// legCell formats one history cell, or "-" when the leg carried no events
// (single-audience mixes leave the other legs idle).
func legCell(leg legResult, format string, v float64) string {
	if leg.Expected == 0 {
		return "-"
	}
	return fmt.Sprintf(format, v)
}

// latencyCell formats a leg's delivery latency as p50/p95/p99/max ms, or "-"
// when it was not measured.
func latencyCell(leg legResult) string {
	l := leg.DeliveryLatency
	if leg.Expected == 0 || l == nil {
		return "-"
	}
	return fmt.Sprintf("%.1f / %.1f / %.1f / %.0f", l.P50Ms, l.P95Ms, l.P99Ms, l.MaxMs)
}

func (r *benchResult) printSummary() {
	fmt.Printf("\n=== goSignalsBench result (%s) ===\n", r.Timestamp.Format(time.RFC3339))
	fmt.Printf("events=%d concurrency=%d mix=%s issuer=%s sstp-role(goSignals1)=%s signing-alg=%s durability=%s\n",
		r.Events, r.Concurrency, r.Mix, r.Issuer, r.SstpRole, orDefault(r.SigningAlg), orDefault(r.Durability))
	fmt.Printf("ingest : %.2fs  %.0f ev/s  errors=%d  latency p50=%.1fms p95=%.1fms p99=%.1fms max=%.1fms  counted=%d\n",
		r.IngestSeconds, r.IngestEventsPerSecond, r.IngestErrors,
		r.IngestLatency.P50Ms, r.IngestLatency.P95Ms, r.IngestLatency.P99Ms, r.IngestLatency.MaxMs, r.IngressCounted)
	if s := r.IngestSplit; s != nil {
		fmt.Printf("ingest split: gs1=%d gs1b=%d (gs1b %s)\n", s.Gs1, s.Gs1b, r.Gs1b)
	}
	if r.Gs1b != "" {
		fmt.Printf("gs1b stream sync: %.1fs\n", r.Gs1bSyncSeconds)
	}
	if r.Gs1bInternal != "" {
		fmt.Printf("receiver legs: goSignals2 polls (and, as SSTP initiator, dials) %s\n", r.Gs1bInternal)
	}
	if r.PollTargets == pollTargetsBoth {
		fmt.Printf("poll targets: goSignals2 polls both nodes (receivers %s, %s)\n", r.Poll.RxStream, r.Poll.RxStream2)
	}
	if r.PollPinOwner {
		fmt.Printf("poll owner pinned: gs1b holds the poll lease, goSignals2 polls goSignals1\n")
	}
	for _, leg := range []legResult{r.Push, r.Poll, r.Sstp} {
		fmt.Printf("%-6s : %d/%d delivered  e2e=%.2fs  drain-after-ingest=%.2fs  %.0f ev/s  complete=%v\n",
			leg.Transport, leg.Delivered, leg.Expected, leg.EndToEndSeconds, leg.DrainSeconds, leg.EventsPerSecond, leg.Complete)
		if l := leg.DeliveryLatency; l != nil {
			fmt.Printf("%-6s   delivery latency p50=%.1fms p95=%.1fms p99=%.1fms max<=%.0fms\n",
				"", l.P50Ms, l.P95Ms, l.P99Ms, l.MaxMs)
		}
	}
	fmt.Printf("total  : %.2fs  success=%v\n", r.TotalSeconds, r.Success)
	if r.Notes != "" {
		fmt.Printf("notes  : %s\n", r.Notes)
	}
	if r.Workers != "" {
		fmt.Printf("workers: %s\n", r.Workers)
	}
	if p := r.Properties; p != nil {
		fmt.Printf("properties: ack writes=%d batches=%d (%.3f writes/batch)  reads under router lock=%d  reads before ack=%d  peer claims served=%d (budget exhausted=%d)\n",
			p.AckWrites, p.AckBatches, p.AckWritesPerBatch, p.ReadsUnderLock, p.ReadsBeforeAck, p.PeerClaimsServed, p.PeerClaimBudgetExhausted)
	}
	printBeyond("gs1", r.BeyondGs1)
	printBeyond("gs1b", r.BeyondGs1b)
	printDao("dao gs1", r.DaoGs1)
	printDao("dao gs1b", r.DaoGs1b)
	printDao("dao gs2", r.DaoGs2)
	if r.DominantDaoOp != "" {
		fmt.Printf("dominant DAO op (goSignals1 total time): %s\n", r.DominantDaoOp)
	}
	if j := r.Journal; j != nil {
		fmt.Printf("journal: %s syncs=%d (%.2f/SET) writes=%d (%.2f/SET) flushes=%d bytes=%d sync-time=%.0fms\n",
			j.Host, j.Syncs, j.SyncsPerSET, j.Writes, j.WritesPerSET, j.Flushes, j.BytesWritten, j.SyncMs)
	}
	for _, p := range r.Profiles {
		fmt.Printf("profile: %s\n", p)
	}
}

func goVersionString() string {
	return runtime.Version()
}

// logf writes progress to stderr with a wall-clock stamp. The standard log
// package is not used because importing the server model packages routes it
// through the repo's slog handler, which double-stamps every line.
func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "%s %s\n", time.Now().Format("15:04:05.000"), fmt.Sprintf(format, args...))
}

// printDao prints one line per EventDAO op, busiest (total time) first.
func printDao(prefix string, stats map[string]daoOpStats) {
	ops := make([]string, 0, len(stats))
	for op := range stats {
		ops = append(ops, op)
	}
	sort.Slice(ops, func(i, j int) bool { return stats[ops[i]].TotalMs > stats[ops[j]].TotalMs })
	for _, op := range ops {
		s := stats[op]
		fmt.Printf("%s: %-26s calls=%-6d total=%8.0fms mean=%6.2fms p50=%6.2fms p95=%6.2fms\n",
			prefix, op, s.Calls, s.TotalMs, s.MeanMs, s.P50Ms, s.P95Ms)
	}
}

// orDefault renders an empty per-run choice (--signing-alg, --durability) as
// the server default rather than a blank field.
func orDefault(v string) string {
	if v == "" {
		return "default"
	}
	return v
}

// printBeyond prints the OldestBeyond query cost line for one node.
func printBeyond(node string, c *beyondCost) {
	if c == nil {
		return
	}
	fmt.Printf("oldest-beyond %s: GetPendingForStreamBeyond calls=%d mean=%.2fms  vs GetPendingForStream calls=%d mean=%.2fms\n",
		node, c.BeyondCalls, c.BeyondMeanMs, c.PlainCalls, c.PlainMeanMs)
}
