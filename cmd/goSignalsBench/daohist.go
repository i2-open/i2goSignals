package main

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// DAO latency histograms (i2goSignals#328). The harness scrapes them before
// and after a run and reports the per-op quantiles of the difference, so the
// numbers cover only the SETs this run pushed.
const (
	metricDaoOpDuration = "goSignals_dao_op_duration_seconds"
)

// opHistogram is one EventDAO op's latency histogram, summed over outcomes.
// Buckets are cumulative counts keyed by their upper bound (le), as exposed.
type opHistogram struct {
	Buckets map[float64]float64
	Count   float64
	Sum     float64
}

// daoHistograms maps an EventDAO op name to its histogram.
type daoHistograms map[string]*opHistogram

// daoOpStats is the per-op summary recorded in the result.
type daoOpStats struct {
	Calls   int     `json:"calls"`
	TotalMs float64 `json:"total_ms"`
	MeanMs  float64 `json:"mean_ms"`
	P50Ms   float64 `json:"p50_ms"`
	P95Ms   float64 `json:"p95_ms"`
}

// scrapeDaoHistograms fetches /metrics and parses the DAO op histograms.
func (n *node) scrapeDaoHistograms() (daoHistograms, error) {
	return n.scrapeHistograms(metricDaoOpDuration, "op")
}

// scrapeHistograms fetches /metrics and parses one histogram family, summed
// per value of the key label.
func (n *node) scrapeHistograms(metric, key string) (daoHistograms, error) {
	resp, err := n.http.Get(n.hostBase + "/metrics")
	if err != nil {
		return nil, fmt.Errorf("%s metrics: %w", n.name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s metrics: HTTP %d", n.name, resp.StatusCode)
	}
	return parseHistograms(resp.Body, metric, key)
}

func parseDaoHistograms(r io.Reader) (daoHistograms, error) {
	return parseHistograms(r, metricDaoOpDuration, "op")
}

// parseHistograms parses one histogram family from an exposition, summing the
// series that share a value of the key label (e.g. DAO outcomes per op).
func parseHistograms(r io.Reader, metric, key string) (daoHistograms, error) {
	h := daoHistograms{}
	get := func(op string) *opHistogram {
		oh := h[op]
		if oh == nil {
			oh = &opHistogram{Buckets: map[float64]float64{}}
			h[op] = oh
		}
		return oh
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, metric+"_") {
			continue
		}
		labels, value, ok := parseLabelledSample(line)
		if !ok {
			continue
		}
		op := labels[key]
		if op == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, metric+"_bucket{"):
			le, err := strconv.ParseFloat(labels["le"], 64)
			if err != nil {
				continue
			}
			get(op).Buckets[le] += value
		case strings.HasPrefix(line, metric+"_count{"):
			get(op).Count += value
		case strings.HasPrefix(line, metric+"_sum{"):
			get(op).Sum += value
		}
	}
	return h, scanner.Err()
}

// parseLabelledSample splits one exposition line into its labels and value.
// Label values in these metrics never contain escaped quotes or commas.
func parseLabelledSample(line string) (map[string]string, float64, bool) {
	openBrace := strings.Index(line, "{")
	closeBrace := strings.LastIndex(line, "}")
	if openBrace < 0 || closeBrace < openBrace {
		return nil, 0, false
	}
	fields := strings.Fields(line[closeBrace+1:])
	if len(fields) == 0 {
		return nil, 0, false
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return nil, 0, false
	}
	labels := map[string]string{}
	for _, pair := range strings.Split(line[openBrace+1:closeBrace], ",") {
		k, val, found := strings.Cut(pair, "=")
		if !found {
			continue
		}
		labels[strings.TrimSpace(k)] = strings.Trim(val, `"`)
	}
	return labels, v, true
}

// diffDaoHistograms returns after-before per op, dropping ops with no calls
// in between.
func diffDaoHistograms(before, after daoHistograms) daoHistograms {
	out := daoHistograms{}
	for op, a := range after {
		b := before[op]
		d := &opHistogram{Buckets: map[float64]float64{}, Count: a.Count, Sum: a.Sum}
		for le, v := range a.Buckets {
			d.Buckets[le] = v
		}
		if b != nil {
			d.Count -= b.Count
			d.Sum -= b.Sum
			for le, v := range b.Buckets {
				d.Buckets[le] -= v
			}
		}
		if d.Count > 0 {
			out[op] = d
		}
	}
	return out
}

// quantile estimates the q-quantile (seconds) the way PromQL's
// histogram_quantile does: linear interpolation inside the bucket that holds
// the rank, with the lowest bucket starting at 0 and the +Inf bucket
// reporting the highest finite bound.
func (h *opHistogram) quantile(q float64) float64 {
	bounds := make([]float64, 0, len(h.Buckets))
	for le := range h.Buckets {
		bounds = append(bounds, le)
	}
	sort.Float64s(bounds)
	if len(bounds) == 0 {
		return 0
	}
	total := h.Buckets[bounds[len(bounds)-1]]
	if total <= 0 {
		return 0
	}
	rank := q * total
	prevBound, prevCount := 0.0, 0.0
	for _, le := range bounds {
		count := h.Buckets[le]
		if count >= rank {
			if math.IsInf(le, 1) {
				return prevBound
			}
			if count == prevCount {
				return le
			}
			return prevBound + (le-prevBound)*(rank-prevCount)/(count-prevCount)
		}
		prevBound, prevCount = le, count
	}
	return prevBound
}

// summarizeDao turns a diffed histogram set into per-op stats.
func summarizeDao(d daoHistograms) map[string]daoOpStats {
	if len(d) == 0 {
		return nil
	}
	out := make(map[string]daoOpStats, len(d))
	for op, h := range d {
		s := daoOpStats{Calls: int(math.Round(h.Count)), TotalMs: h.Sum * 1000}
		if h.Count > 0 {
			s.MeanMs = s.TotalMs / h.Count
		}
		s.P50Ms = h.quantile(0.50) * 1000
		s.P95Ms = h.quantile(0.95) * 1000
		out[op] = s
	}
	return out
}

// dominantDaoOp names the op with the most total wall time. WatchPending is
// skipped: on the memory store it blocks for the watch's lifetime, so its
// "latency" is not work (docs/Metrics.md).
func dominantDaoOp(stats map[string]daoOpStats) string {
	best, bestMs := "", -1.0
	for op, s := range stats {
		if op == "WatchPending" {
			continue
		}
		if s.TotalMs > bestMs || (s.TotalMs == bestMs && op < best) {
			best, bestMs = op, s.TotalMs
		}
	}
	return best
}
