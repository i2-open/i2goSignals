package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// streamCounters holds the per-stream router counters scraped from /metrics.
type streamCounters struct {
	In  map[string]float64 // goSignals_router_events_in_total summed by stream_id
	Out map[string]float64 // goSignals_router_events_out_total summed by stream_id

	// WalDepth is goSignals_wal_depth: SETs acknowledged into the node-local
	// WAL and not yet drained to the store. HasWal is false when the node does
	// not expose the gauge (majority mode, or a build without it).
	WalDepth float64
	HasWal   bool
}

const (
	metricEventsIn  = "goSignals_router_events_in_total"
	metricEventsOut = "goSignals_router_events_out_total"
	metricWalDepth  = "goSignals_wal_depth"
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

// missingStreams returns the ids in want that have no events_in_total series
// in c. A stream shows up in the router's counters (at 0) as soon as the node
// has registered it, so an absent series means the node does not know the
// stream yet.
func missingStreams(c *streamCounters, want []string) []string {
	var missing []string
	for _, id := range want {
		if _, ok := c.In[id]; !ok {
			missing = append(missing, id)
		}
	}
	return missing
}

// waitForStreams polls the node's /metrics every interval until every stream
// in want has an events_in_total series, returning how long that took. It
// fails, naming the streams still absent, once timeout expires.
func (n *node) waitForStreams(want []string, timeout, interval time.Duration) (time.Duration, error) {
	start := time.Now()
	deadline := start.Add(timeout)
	for {
		c, err := n.scrapeCounters()
		if err != nil {
			return 0, err
		}
		missing := missingStreams(c, want)
		if len(missing) == 0 {
			return time.Since(start), nil
		}
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("%s has not registered streams %v after %s (peers sync every 40s); not starting ingest", n.name, missing, timeout)
		}
		time.Sleep(interval)
	}
}

func parseCounters(r io.Reader) (*streamCounters, error) {
	c := &streamCounters{In: map[string]float64{}, Out: map[string]float64{}}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		var target map[string]float64
		switch {
		case strings.HasPrefix(line, metricWalDepth+" "):
			fields := strings.Fields(line)
			if v, err := strconv.ParseFloat(fields[1], 64); err == nil {
				c.WalDepth = v
				c.HasWal = true
			}
			continue
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
