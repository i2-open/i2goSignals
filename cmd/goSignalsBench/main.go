// goSignalsBench is an end-to-end load and profiling harness for the
// docker-compose-dev.yml stack.
//
// Topology it builds (all streams are created fresh per run and removed at
// the end unless --keep is set):
//
//	harness --RFC8935 push--> goSignals1 [ingress: push-receive, FW]
//	                              |-- aud=<push-aud> --RFC8935 push--> goSignals2 [push-receive, IM]
//	                              `-- aud=<poll-aud> <--RFC8936 poll-- goSignals2 [poll-receive, IM]
//
// Each SET carries one (or both) of the two audiences, so goSignals1's
// EventRouter has to match audience per event to pick the outbound stream.
// Delivery is counted on goSignals2's goSignals_router_events_in_total; the
// poll leg cannot be counted on goSignals1 because the transmitter does not
// increment events_out_total on poll delivery.
package main

import (
	"context"
	"crypto/rsa"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

type options struct {
	gs1, gs2                 string
	gs1Internal, gs2Internal string
	caFile                   string
	insecure                 bool
	bootstrapToken           string
	issuer                   string
	issuerKeyFile            string
	pushAud, pollAud         string
	events                   int
	concurrency              int
	mix                      string
	drainTimeout             time.Duration
	pollInterval             time.Duration
	keep                     bool
	outDir                   string
	history                  string
	label                    string
	pprof                    bool
	pprofGs1, pprofGs2       string
	pprofSeconds             int
	verbose                  bool
}

func parseFlags() *options {
	o := &options{}
	flag.StringVar(&o.gs1, "gs1", "https://localhost:8888", "host-side base URL of goSignals1 (ingress + transmitters)")
	flag.StringVar(&o.gs2, "gs2", "https://localhost:8889", "host-side base URL of goSignals2 (receivers)")
	flag.StringVar(&o.gs1Internal, "gs1-internal", "", "base URL goSignals2 uses to reach goSignals1 (default: learned from the server's BASE_URL)")
	flag.StringVar(&o.gs2Internal, "gs2-internal", "", "base URL goSignals1 uses to reach goSignals2 (default: learned from the server's BASE_URL)")
	flag.StringVar(&o.caFile, "ca", "config/certs/ca-cert.pem", "CA certificate used to verify both servers")
	flag.BoolVar(&o.insecure, "insecure", false, "skip TLS verification instead of using --ca")
	flag.StringVar(&o.bootstrapToken, "bootstrap-token", envOr("I2SIG_BOOTSTRAP_TOKEN", "dev-bootstrap-secret"), "I2SIG_BOOTSTRAP_TOKEN shared with the servers")
	flag.StringVar(&o.issuer, "issuer", "bench.example.com", "SET issuer; also the signing key name (kid) minted on goSignals1")
	flag.StringVar(&o.issuerKeyFile, "issuer-key", "", "PEM file for the issuer private key (default bin/bench/<issuer>.pem; created on first run)")
	flag.StringVar(&o.pushAud, "push-aud", "bench.push.example.com", "audience routed over the RFC 8935 push leg")
	flag.StringVar(&o.pollAud, "poll-aud", "bench.poll.example.com", "audience routed over the RFC 8936 poll leg")
	flag.IntVar(&o.events, "events", 1000, "number of SETs to push into goSignals1")
	flag.IntVar(&o.concurrency, "concurrency", 8, "parallel ingest connections")
	flag.StringVar(&o.mix, "mix", string(mixAlternate), "audience mix per event: alternate|both|push|poll")
	flag.DurationVar(&o.drainTimeout, "drain-timeout", 5*time.Minute, "how long to wait for goSignals2 to receive everything")
	flag.DurationVar(&o.pollInterval, "scrape-interval", 500*time.Millisecond, "how often to scrape /metrics while draining")
	flag.BoolVar(&o.keep, "keep", false, "leave the benchmark streams in place after the run")
	flag.StringVar(&o.outDir, "out", "bin/bench", "directory for JSON results (and default key file)")
	flag.StringVar(&o.history, "history", "", "Markdown file to append a summary row to (e.g. docs/perf/e2e-history.md)")
	flag.StringVar(&o.label, "label", "", "free-text label recorded with the result")
	flag.BoolVar(&o.pprof, "pprof", false, "capture CPU profiles from both nodes during the run (needs I2SIG_PPROF_ADDR)")
	flag.StringVar(&o.pprofGs1, "pprof-gs1", "http://localhost:6060", "pprof base URL for goSignals1")
	flag.StringVar(&o.pprofGs2, "pprof-gs2", "http://localhost:6061", "pprof base URL for goSignals2")
	flag.IntVar(&o.pprofSeconds, "pprof-seconds", 0, "CPU profile window (default: 30s, or the drain timeout if smaller)")
	flag.BoolVar(&o.verbose, "v", false, "log each stream as it is created")
	flag.Parse()
	if o.issuerKeyFile == "" {
		o.issuerKeyFile = filepath.Join(o.outDir, o.issuer+".pem")
	}
	if o.events <= 0 || o.concurrency <= 0 {
		fmt.Fprintln(os.Stderr, "--events and --concurrency must be positive")
		os.Exit(2)
	}
	return o
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	o := parseFlags()
	if err := run(o); err != nil {
		fmt.Fprintf(os.Stderr, "goSignalsBench: %v\n", err)
		os.Exit(1)
	}
}

// topology holds every stream the harness created, in creation order.
type topology struct {
	ingress *model.StreamConfiguration // goSignals1 push-receive (FW)
	txPush  *model.StreamConfiguration // goSignals1 push transmitter -> goSignals2
	rxPush  *model.StreamConfiguration // goSignals2 push-receive
	txPoll  *model.StreamConfiguration // goSignals1 poll transmitter
	rxPoll  *model.StreamConfiguration // goSignals2 poll-receive <- goSignals1
}

func run(o *options) error {
	mix, err := parseAudMix(o.mix)
	if err != nil {
		return err
	}
	client, err := newHTTPClient(o.caFile, o.insecure)
	if err != nil {
		return err
	}
	gs1 := &node{name: "goSignals1", hostBase: strings.TrimRight(o.gs1, "/"), internalBase: o.gs1Internal, http: client}
	gs2 := &node{name: "goSignals2", hostBase: strings.TrimRight(o.gs2, "/"), internalBase: o.gs2Internal, http: client}

	logf("bootstrapping clients on %s and %s", gs1.hostBase, gs2.hostBase)
	if err := gs1.bootstrap(o.bootstrapToken); err != nil {
		return fmt.Errorf("goSignals1: %w", err)
	}
	if err := gs2.bootstrap(o.bootstrapToken); err != nil {
		return fmt.Errorf("goSignals2: %w", err)
	}

	key, err := ensureIssuerKey(gs1, o)
	if err != nil {
		return err
	}

	topo, err := buildTopology(gs1, gs2, o)
	if err != nil {
		return err
	}
	if !o.keep {
		defer teardown(gs1, gs2, topo)
	}

	logf("pre-signing %d SETs (issuer %s, mix %s)", o.events, o.issuer, mix)
	events, err := buildEvents(o.events, o.issuer, o.pushAud, o.pollAud, mix, key)
	if err != nil {
		return err
	}

	_, ingressPath, err := splitEndpoint(topo.ingress.Delivery.PushReceiveMethod.EndpointUrl)
	if err != nil {
		return err
	}
	ingressBearer := topo.ingress.Delivery.PushReceiveMethod.AuthorizationHeader

	before2, err := gs2.scrapeCounters()
	if err != nil {
		return err
	}
	before1, err := gs1.scrapeCounters()
	if err != nil {
		return err
	}

	result := &benchResult{
		Timestamp:     time.Now(),
		Label:         o.label,
		GitRevision:   gitRevision(),
		GoVersion:     goVersionString(),
		Host:          hostDescription(),
		Events:        o.events,
		Concurrency:   o.concurrency,
		Mix:           string(mix),
		Issuer:        o.issuer,
		IngressStream: topo.ingress.Id,
	}
	expectPush, expectPoll := mix.expected(o.events)
	result.Push = legResult{Transport: "PUSH", Audience: o.pushAud, TxStream: topo.txPush.Id, RxStream: topo.rxPush.Id, Expected: expectPush}
	result.Poll = legResult{Transport: "POLL", Audience: o.pollAud, TxStream: topo.txPoll.Id, RxStream: topo.rxPoll.Id, Expected: expectPoll}

	profiles := startProfiles(o, gs1.http)

	// ---- ingest ----------------------------------------------------------
	logf("ingesting %d SETs with %d workers -> %s%s", len(events), o.concurrency, gs1.hostBase, ingressPath)
	start := time.Now()
	latencies := make([]time.Duration, len(events))
	var errCount atomic.Int64
	var firstErr atomic.Value
	next := make(chan int, len(events))
	for i := range events {
		next <- i
	}
	close(next)
	var wg sync.WaitGroup
	for w := 0; w < o.concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				t0 := time.Now()
				_, err := gs1.pushSET(ingressPath, ingressBearer, events[i].jws)
				latencies[i] = time.Since(t0)
				if err != nil {
					errCount.Add(1)
					firstErr.CompareAndSwap(nil, err)
				}
			}
		}()
	}
	wg.Wait()
	ingestEnd := time.Now()
	result.IngestSeconds = ingestEnd.Sub(start).Seconds()
	result.IngestEventsPerSecond = float64(len(events)-int(errCount.Load())) / result.IngestSeconds
	result.IngestErrors = int(errCount.Load())
	result.IngestLatency = percentiles(latencies)
	if fe := firstErr.Load(); fe != nil {
		result.Notes = "first ingest error: " + fe.(error).Error()
	}
	logf("ingest done: %.2fs, %.0f ev/s, %d errors", result.IngestSeconds, result.IngestEventsPerSecond, result.IngestErrors)

	// ---- drain -----------------------------------------------------------
	drainErr := waitForDrain(gs1, gs2, before1, before2, topo, result, start, ingestEnd, o)
	result.TotalSeconds = time.Since(start).Seconds()
	result.Success = drainErr == nil && result.IngestErrors == 0 && result.Push.Complete && result.Poll.Complete
	if drainErr != nil {
		if result.Notes != "" {
			result.Notes += "; "
		}
		result.Notes += drainErr.Error()
	}

	result.Profiles = profiles.wait()

	// ---- report ----------------------------------------------------------
	result.printSummary()
	path, err := writeJSON(o.outDir, result)
	if err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	logf("result written to %s", path)
	if o.history != "" {
		if err := appendHistory(o.history, result); err != nil {
			return fmt.Errorf("append history: %w", err)
		}
		logf("history row appended to %s", o.history)
	}
	if !result.Success {
		return errors.New("benchmark did not complete cleanly (see notes)")
	}
	return nil
}

// ensureIssuerKey makes sure goSignals1 holds a signing key named after the
// issuer and that the harness holds the matching private key. The first run
// mints the key and saves the PEM; later runs load it. After a `make
// dev-clean` the server forgets the key and a new one is minted (overwriting
// the file).
func ensureIssuerKey(gs1 *node, o *options) (*rsa.PrivateKey, error) {
	if gs1.hasIssuerKey(o.issuer) {
		pemBytes, readErr := os.ReadFile(o.issuerKeyFile)
		if readErr != nil {
			return nil, fmt.Errorf("goSignals1 already has a key for issuer %q but %s is missing: pick a new --issuer, point --issuer-key at the matching PEM (e.g. config/scim/cluster-scim-issuer.pem for cluster.scim.example.com), or reset the stack", o.issuer, o.issuerKeyFile)
		}
		k, parseErr := parseRSAPrivateKeyPEM(pemBytes)
		if parseErr != nil {
			return nil, fmt.Errorf("parse %s: %w", o.issuerKeyFile, parseErr)
		}
		logf("using existing issuer key %s from %s", o.issuer, o.issuerKeyFile)
		return k, nil
	}
	k, pemBytes, createErr := gs1.createIssuerKey(o.bootstrapToken, o.issuer)
	if createErr != nil {
		return nil, fmt.Errorf("create issuer key %s: %w", o.issuer, createErr)
	}
	if mkErr := os.MkdirAll(filepath.Dir(o.issuerKeyFile), 0o755); mkErr != nil {
		return nil, mkErr
	}
	if writeErr := os.WriteFile(o.issuerKeyFile, pemBytes, 0o600); writeErr != nil {
		return nil, writeErr
	}
	logf("minted issuer key %s on goSignals1, saved to %s", o.issuer, o.issuerKeyFile)
	return k, nil
}

func buildTopology(gs1, gs2 *node, o *options) (*topology, error) {
	t := &topology{}
	events := benchEventTypes

	// 1. Ingress on goSignals1: FW so the router fans out instead of importing.
	ingress, err := gs1.createStream(streamRequest{
		Description:     "bench ingress (harness -> goSignals1)",
		Iss:             o.issuer,
		Aud:             []string{o.pushAud, o.pollAud},
		EventsRequested: events,
		RouteMode:       model.RouteModeForward,
		Delivery:        map[string]any{"method": model.ReceivePush},
	})
	if err != nil {
		return nil, fmt.Errorf("ingress stream: %w", err)
	}
	t.ingress = ingress
	if err := learnInternalBase(gs1, ingress.Delivery.PushReceiveMethod.EndpointUrl); err != nil {
		return nil, err
	}
	jwksURL := gs1.internalBase + "/jwks/" + o.issuer

	// 2. goSignals2 push receiver (needs to exist before the transmitter).
	rxPush, err := gs2.createStream(streamRequest{
		Description:     "bench push receiver (goSignals1 -> goSignals2)",
		Iss:             o.issuer,
		Aud:             []string{o.pushAud},
		EventsRequested: events,
		IssuerJWKSUrl:   jwksURL,
		RouteMode:       model.RouteModeImport,
		Delivery:        map[string]any{"method": model.ReceivePush},
	})
	if err != nil {
		return nil, fmt.Errorf("goSignals2 push receiver: %w", err)
	}
	t.rxPush = rxPush
	if err := learnInternalBase(gs2, rxPush.Delivery.PushReceiveMethod.EndpointUrl); err != nil {
		return nil, err
	}

	// 3. goSignals1 push transmitter pointed at the receiver's docker-side URL.
	pushEndpoint, err := rebase(rxPush.Delivery.PushReceiveMethod.EndpointUrl, gs2.internalBase)
	if err != nil {
		return nil, err
	}
	txPush, err := gs1.createStream(streamRequest{
		Description:     "bench push transmitter (goSignals1 -> goSignals2)",
		Iss:             o.issuer,
		Aud:             []string{o.pushAud},
		EventsRequested: events,
		RouteMode:       model.RouteModePublish,
		DefaultSubjects: "ALL",
		Delivery: map[string]any{
			"method":               model.DeliveryPush,
			"endpoint_url":         pushEndpoint,
			"authorization_header": rxPush.Delivery.PushReceiveMethod.AuthorizationHeader,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("goSignals1 push transmitter: %w", err)
	}
	t.txPush = txPush

	// 4. goSignals1 poll transmitter; goSignals2 polls it.
	txPoll, err := gs1.createStream(streamRequest{
		Description:     "bench poll transmitter (goSignals2 polls goSignals1)",
		Iss:             o.issuer,
		Aud:             []string{o.pollAud},
		EventsRequested: events,
		RouteMode:       model.RouteModePublish,
		DefaultSubjects: "ALL",
		Delivery:        map[string]any{"method": model.DeliveryPoll},
	})
	if err != nil {
		return nil, fmt.Errorf("goSignals1 poll transmitter: %w", err)
	}
	t.txPoll = txPoll
	pollEndpoint, err := rebase(txPoll.Delivery.PollTransmitMethod.EndpointUrl, gs1.internalBase)
	if err != nil {
		return nil, err
	}
	rxPoll, err := gs2.createStream(streamRequest{
		Description:     "bench poll receiver (goSignals2 polls goSignals1)",
		Iss:             o.issuer,
		Aud:             []string{o.pollAud},
		EventsRequested: events,
		IssuerJWKSUrl:   jwksURL,
		RouteMode:       model.RouteModeImport,
		Delivery: map[string]any{
			"method":               model.ReceivePoll,
			"endpoint_url":         pollEndpoint,
			"authorization_header": txPoll.Delivery.PollTransmitMethod.AuthorizationHeader,
			"poll_config": map[string]any{
				"maxEvents":         500,
				"returnImmediately": false,
				"timeoutSecs":       10,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("goSignals2 poll receiver: %w", err)
	}
	t.rxPoll = rxPoll

	logf("streams: ingress=%s txPush=%s rxPush=%s txPoll=%s rxPoll=%s", ingress.Id, txPush.Id, rxPush.Id, txPoll.Id, rxPoll.Id)
	if o.verbose {
		logf("ingress endpoint %s", ingress.Delivery.PushReceiveMethod.EndpointUrl)
		logf("push leg  %s -> %s", txPush.Id, pushEndpoint)
		logf("poll leg  %s <- %s", pollEndpoint, rxPoll.Id)
		logf("issuer jwks %s", jwksURL)
	}
	return t, nil
}

// learnInternalBase records the base URL the server advertises for itself
// (its BASE_URL) unless the user overrode it on the command line.
func learnInternalBase(n *node, endpoint string) error {
	if n.internalBase != "" {
		return nil
	}
	base, _, err := splitEndpoint(endpoint)
	if err != nil {
		return err
	}
	n.internalBase = base
	return nil
}

func teardown(gs1, gs2 *node, t *topology) {
	type victim struct {
		n  *node
		id string
	}
	// Receivers first so no transmitter is left pointing at a deleted peer.
	victims := []victim{{gs2, idOf(t.rxPoll)}, {gs1, idOf(t.txPoll)}, {gs1, idOf(t.txPush)}, {gs2, idOf(t.rxPush)}, {gs1, idOf(t.ingress)}}
	for _, v := range victims {
		if v.id == "" {
			continue
		}
		if err := v.n.deleteStream(v.id); err != nil {
			logf("warning: delete stream %s on %s: %v", v.id, v.n.name, err)
		}
	}
	logf("benchmark streams removed (use --keep to retain them)")
}

func idOf(s *model.StreamConfiguration) string {
	if s == nil {
		return ""
	}
	return s.Id
}

// waitForDrain scrapes both nodes until goSignals2 has counted every expected
// event on each leg, or the timeout elapses.
func waitForDrain(gs1, gs2 *node, before1, before2 *streamCounters, t *topology, r *benchResult, start, ingestEnd time.Time, o *options) error {
	deadline := time.Now().Add(o.drainTimeout)
	legs := []*legResult{&r.Push, &r.Poll}
	for _, leg := range legs {
		if leg.Expected == 0 {
			leg.Complete = true
		}
	}
	lastLog := time.Now()
	for {
		now2, err := gs2.scrapeCounters()
		if err != nil {
			return err
		}
		allDone := true
		for _, leg := range legs {
			delivered := int(now2.In[leg.RxStream] - before2.In[leg.RxStream])
			leg.Delivered = delivered
			if leg.Complete {
				continue
			}
			if delivered >= leg.Expected {
				leg.Complete = true
				finish := time.Now()
				leg.EndToEndSeconds = finish.Sub(start).Seconds()
				if finish.After(ingestEnd) {
					leg.DrainSeconds = finish.Sub(ingestEnd).Seconds()
				}
				leg.EventsPerSecond = float64(delivered) / leg.EndToEndSeconds
				logf("%s leg complete: %d events in %.2fs", leg.Transport, delivered, leg.EndToEndSeconds)
			} else {
				allDone = false
			}
		}
		if allDone {
			break
		}
		if time.Since(lastLog) > 5*time.Second {
			logf("draining: push %d/%d, poll %d/%d", r.Push.Delivered, r.Push.Expected, r.Poll.Delivered, r.Poll.Expected)
			lastLog = time.Now()
		}
		if time.Now().After(deadline) {
			for _, leg := range legs {
				if !leg.Complete {
					leg.EndToEndSeconds = time.Since(start).Seconds()
					leg.DrainSeconds = time.Since(ingestEnd).Seconds()
					if leg.EndToEndSeconds > 0 {
						leg.EventsPerSecond = float64(leg.Delivered) / leg.EndToEndSeconds
					}
				}
			}
			break
		}
		time.Sleep(o.pollInterval)
	}
	if now1, err := gs1.scrapeCounters(); err == nil {
		r.IngressCounted = int(now1.In[t.ingress.Id] - before1.In[t.ingress.Id])
	}
	for _, leg := range legs {
		if !leg.Complete {
			return fmt.Errorf("%s leg timed out after %s with %d/%d delivered", leg.Transport, o.drainTimeout, leg.Delivered, leg.Expected)
		}
	}
	return nil
}

// ---- pprof capture -------------------------------------------------------

type profileJob struct {
	wg    sync.WaitGroup
	mu    sync.Mutex
	files []string
}

func (p *profileJob) wait() []string {
	if p == nil {
		return nil
	}
	p.wg.Wait()
	return p.files
}

// startProfiles kicks off a CPU profile fetch against each node's pprof
// listener. The fetch blocks server-side for the whole window, so it runs in
// the background and is joined after the drain phase.
func startProfiles(o *options, client *http.Client) *profileJob {
	if !o.pprof {
		return nil
	}
	seconds := o.pprofSeconds
	if seconds <= 0 {
		seconds = 30
		if int(o.drainTimeout.Seconds()) < seconds {
			seconds = int(o.drainTimeout.Seconds())
		}
	}
	dir := filepath.Join(o.outDir, "pprof")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		logf("warning: pprof dir: %v", err)
		return nil
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	job := &profileJob{}
	for _, target := range []struct{ name, base string }{{"goSignals1", o.pprofGs1}, {"goSignals2", o.pprofGs2}} {
		if target.base == "" {
			continue
		}
		job.wg.Add(1)
		go func(name, base string) {
			defer job.wg.Done()
			out := filepath.Join(dir, fmt.Sprintf("cpu-%s-%s.pb.gz", name, stamp))
			url := fmt.Sprintf("%s/debug/pprof/profile?seconds=%d", strings.TrimRight(base, "/"), seconds)
			if err := fetchToFile(client, url, out, time.Duration(seconds+30)*time.Second); err != nil {
				logf("warning: pprof %s: %v", name, err)
				return
			}
			job.mu.Lock()
			job.files = append(job.files, out)
			job.mu.Unlock()
		}(target.name, target.base)
	}
	logf("capturing %ds CPU profiles into %s", seconds, dir)
	return job
}

func fetchToFile(client *http.Client, url, out string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = io.Copy(f, resp.Body)
	return err
}
