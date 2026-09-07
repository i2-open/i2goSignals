package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// streamCounters holds the per-stream router counters scraped from /metrics.
type streamCounters struct {
	In  map[string]float64 // goSignals_router_events_in_total summed by stream_id
	Out map[string]float64 // goSignals_router_events_out_total summed by stream_id
}

const (
	metricEventsIn  = "goSignals_router_events_in_total"
	metricEventsOut = "goSignals_router_events_out_total"
)

// scrapeCounters fetches /metrics (unauthenticated) and folds the router
// counters by stream_id, ignoring the type/iss/tfr label dimensions.
func (n *node) scrapeCounters() (*streamCounters, error) {
	resp, err := n.http.Get(n.hostBase + "/metrics")
	if err != nil {
		return nil, fmt.Errorf("%s metrics: %w", n.name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s metrics: HTTP %d", n.name, resp.StatusCode)
	}
	return parseCounters(resp.Body)
}

func parseCounters(r io.Reader) (*streamCounters, error) {
	c := &streamCounters{In: map[string]float64{}, Out: map[string]float64{}}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		var target map[string]float64
		switch {
		case strings.HasPrefix(line, metricEventsIn+"{"):
			target = c.In
		case strings.HasPrefix(line, metricEventsOut+"{"):
			target = c.Out
		default:
			continue
		}
		sid, value, ok := parseSample(line)
		if !ok {
			continue
		}
		target[sid] += value
	}
	return c, scanner.Err()
}

// parseSample extracts the stream_id label and the sample value from one
// Prometheus text-exposition line of the form
//
//	name{label="v",stream_id="abc"} 12
func parseSample(line string) (streamID string, value float64, ok bool) {
	closeBrace := strings.LastIndex(line, "}")
	openBrace := strings.Index(line, "{")
	if openBrace < 0 || closeBrace < openBrace {
		return "", 0, false
	}
	labels := line[openBrace+1 : closeBrace]
	rest := strings.TrimSpace(line[closeBrace+1:])
	// The value is the first field after the labels; a timestamp may follow.
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return "", 0, false
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return "", 0, false
	}
	const key = `stream_id="`
	idx := strings.Index(labels, key)
	if idx < 0 {
		return "", 0, false
	}
	tail := labels[idx+len(key):]
	end := strings.Index(tail, `"`)
	if end < 0 {
		return "", 0, false
	}
	return tail[:end], v, true
}
