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
	Transport string `json:"transport"` // PUSH or POLL
	Audience  string `json:"audience"`
	TxStream  string `json:"tx_stream"` // goSignals1 transmitter stream id
	RxStream  string `json:"rx_stream"` // goSignals2 receiver stream id
	Expected  int    `json:"expected"`
	Delivered int    `json:"delivered"`
	// DrainSeconds is measured from the END of ingest until the last event
	// arrived on goSignals2 (0 when the leg kept up with ingest).
	DrainSeconds float64 `json:"drain_seconds"`
	// EndToEndSeconds is from the START of ingest until the last event arrived.
	EndToEndSeconds float64 `json:"end_to_end_seconds"`
	EventsPerSecond float64 `json:"events_per_second"`
	Complete        bool    `json:"complete"`
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
	GitRevision string    `json:"git_revision,omitempty"`
	GoVersion   string    `json:"go_version"`
	Host        string    `json:"host"`
	Events      int       `json:"events"`
	Concurrency int       `json:"concurrency"`
	Mix         string    `json:"mix"`
	Issuer      string    `json:"issuer"`

	IngressStream string `json:"ingress_stream"`

	// Ingest: harness -> goSignals1 push-receive endpoint.
	IngestSeconds         float64      `json:"ingest_seconds"`
	IngestEventsPerSecond float64      `json:"ingest_events_per_second"`
	IngestErrors          int          `json:"ingest_errors"`
	IngestLatency         latencyStats `json:"ingest_latency"`
	IngressCounted        int          `json:"ingress_counted"` // goSignals1 events_in_total for the ingress stream

	Push legResult `json:"push"`
	Poll legResult `json:"poll"`

	// TotalSeconds is from first push until both legs drained (or timeout).
	TotalSeconds float64 `json:"total_seconds"`
	Success      bool    `json:"success"`
	Notes        string  `json:"notes,omitempty"`

	Profiles []string `json:"profiles,omitempty"`
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

| Date (UTC) | Revision | Label | Events | Conc | Mix | Ingest ev/s | Ingest p50/p99 ms | Push ev/s | Push drain s | Poll ev/s | Poll drain s | Total s | OK |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
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
	row := fmt.Sprintf("| %s | %s | %s | %d | %d | %s | %.0f | %.1f / %.1f | %.0f | %.1f | %.0f | %.1f | %.1f | %s |\n",
		r.Timestamp.UTC().Format("2006-01-02 15:04"),
		r.GitRevision, r.Label, r.Events, r.Concurrency, r.Mix,
		r.IngestEventsPerSecond, r.IngestLatency.P50Ms, r.IngestLatency.P99Ms,
		r.Push.EventsPerSecond, r.Push.DrainSeconds,
		r.Poll.EventsPerSecond, r.Poll.DrainSeconds,
		r.TotalSeconds, ok)
	_, err = f.WriteString(row)
	return err
}

func (r *benchResult) printSummary() {
	fmt.Printf("\n=== goSignalsBench result (%s) ===\n", r.Timestamp.Format(time.RFC3339))
	fmt.Printf("events=%d concurrency=%d mix=%s issuer=%s\n", r.Events, r.Concurrency, r.Mix, r.Issuer)
	fmt.Printf("ingest : %.2fs  %.0f ev/s  errors=%d  latency p50=%.1fms p95=%.1fms p99=%.1fms max=%.1fms  counted=%d\n",
		r.IngestSeconds, r.IngestEventsPerSecond, r.IngestErrors,
		r.IngestLatency.P50Ms, r.IngestLatency.P95Ms, r.IngestLatency.P99Ms, r.IngestLatency.MaxMs, r.IngressCounted)
	for _, leg := range []legResult{r.Push, r.Poll} {
		fmt.Printf("%-6s : %d/%d delivered  e2e=%.2fs  drain-after-ingest=%.2fs  %.0f ev/s  complete=%v\n",
			leg.Transport, leg.Delivered, leg.Expected, leg.EndToEndSeconds, leg.DrainSeconds, leg.EventsPerSecond, leg.Complete)
	}
	fmt.Printf("total  : %.2fs  success=%v\n", r.TotalSeconds, r.Success)
	if r.Notes != "" {
		fmt.Printf("notes  : %s\n", r.Notes)
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
