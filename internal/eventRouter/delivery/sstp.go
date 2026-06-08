// SSTP client-side delivery seam (PRD #154 slice 7, issue #164).
//
// SstpDelivery is the client-side counterpart of PushDelivery for the
// Synchronous SET Transfer Protocol (draft-hunt-secevent-sstp-00). One Deliver
// call performs exactly one SSTP HTTP cycle for a pair: it posts any queued
// outbound SETs in an application/sstp+json body to the peer's /sstp/{id}
// endpoint and classifies the response via goSetSstp.ClassifyResult.
//
// Scope discipline mirrors PushDelivery: one cycle per call. Lease ownership,
// heartbeats, parent-context cancellation, takeover jitter, POLL_RETRY_* backoff,
// and per-direction pausing all stay in the router's runSstpClientLoop.
package delivery

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// SstpDelivery is the seam consumed by the router's SSTP client loop. One SSTP
// HTTP cycle per DeliverSstp call. Two adapters land in the same package:
// SstpHTTPAdapter (production) and SstpMemoryAdapter (tests).
type SstpDelivery interface {
	DeliverSstp(ctx context.Context, req SstpRequest) SstpOutcome
}

// SstpRequest is the input to a single SSTP client cycle. Stream carries the
// pair record (StreamConfiguration is the transmit/outbound side; SstpMethod
// carries the endpoint and per-pair bearer). Events are the outbound SET records
// to flush this cycle, already resolved from the EventPollBuffer JTIs; Key and
// Kid sign them (publish mode) or are ignored (RouteModeForward forwards
// Event.Original verbatim).
type SstpRequest struct {
	Stream *model.StreamStateRecord
	Events []*model.AgEventRecord
	Key    *rsa.PrivateKey
	Kid    string

	// ReturnEvents sets the wire "returnEvents" field. Nil (the primary cycle)
	// omits it so the peer applies the §2.1 default (true) and holds its long-poll.
	// A second, parallel push-while-poll-held cycle (Q7.2) sets this to false so
	// the peer returns immediately without holding a long-poll for the push.
	ReturnEvents *bool
}

// SstpOutcome is the result of a single SSTP client cycle. Classification reports
// the peer's verdict per goSetSstp; Acked carries the JTIs the peer acknowledged
// (from the response "ack") so the caller can ack them in the buffer/provider.
type SstpOutcome struct {
	Classification goSetSstp.Classification
	Acked          []string
}

// SstpHTTPAdapter is the production SstpDelivery. It builds an SSTP request body
// (signing or forwarding each outbound SET), posts it to the pair endpoint with
// the per-pair bearer, and classifies the response. It performs exactly one HTTP
// cycle — no retry, no backoff (those live in the router).
type SstpHTTPAdapter struct {
	client *http.Client
}

// NewSstpHTTPAdapter wires the adapter for production. A nil client uses a
// default with a 60s timeout (the long-poll wait is bounded by the peer).
func NewSstpHTTPAdapter(client *http.Client) *SstpHTTPAdapter {
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	return &SstpHTTPAdapter{client: client}
}

// DeliverSstp implements SstpDelivery: one SSTP HTTP cycle. See type docs for scope.
func (a *SstpHTTPAdapter) DeliverSstp(ctx context.Context, req SstpRequest) SstpOutcome {
	method := req.Stream.SstpMethod
	if method == nil || method.EndpointUrl == "" {
		return SstpOutcome{Classification: goSetSstp.Classification{Class: goSetSstp.ClassRequestError}}
	}

	msg := goSetSstp.Message{
		ReturnEvents: req.ReturnEvents,
		Sets:         a.buildSets(req),
	}
	body, err := json.Marshal(msg)
	if err != nil {
		return SstpOutcome{Classification: goSetSstp.Classification{Class: goSetSstp.ClassRequestError}}
	}

	httpReq, err := http.NewRequestWithContext(ctx, goSetSstp.Method, method.EndpointUrl, bytes.NewReader(body))
	if err != nil {
		return SstpOutcome{Classification: goSetSstp.Classification{Class: goSetSstp.ClassTransport}}
	}
	httpReq.Header.Set("Content-Type", goSetSstp.ContentType)
	httpReq.Header.Set("Accept", goSetSstp.ContentType)
	if method.AuthorizationHeader != "" {
		auth := method.AuthorizationHeader
		if !strings.Contains(strings.ToLower(auth), "bearer") && !strings.Contains(auth, " ") {
			auth = "Bearer " + auth
		}
		httpReq.Header.Set("Authorization", auth)
	}

	resp, err := a.client.Do(httpReq)
	if err != nil {
		// Transport-layer failure: no HTTP response received.
		return SstpOutcome{Classification: goSetSstp.ClassifyResult(goSetSstp.Result{Err: err})}
	}
	defer func() { _ = resp.Body.Close() }()

	result := goSetSstp.Result{
		StatusCode: resp.StatusCode,
		RetryAfter: goSetPush.ParseRetryAfter(resp.Header.Get("Retry-After"), time.Now()),
	}

	if resp.StatusCode == http.StatusOK {
		raw, rErr := io.ReadAll(resp.Body)
		var parsed goSetSstp.Message
		switch {
		case rErr != nil:
			// Could not even read the 200 body — treat as a failed parse so the
			// classifier returns transient (retry, do not ack).
			result.Err = rErr
		case len(raw) == 0:
			// A 200 with an empty body is the §2.3 success-without-detail case:
			// no SetErrs, no explicit ack list. Leave Message/Err nil so the
			// classifier returns ClassOK and the runner acks the sent set.
		default:
			if jErr := json.Unmarshal(raw, &parsed); jErr == nil {
				result.Message = &parsed
			} else {
				// A 200 with an unparseable body is NOT success (a broken peer or
				// an on-path proxy). Surface the parse error so ClassifyResult
				// classifies it transient/retryable instead of silently acking.
				result.Err = jErr
			}
		}
		cls := goSetSstp.ClassifyResult(result)
		acked := []string(nil)
		if result.Message != nil {
			acked = result.Message.Ack
		}
		return SstpOutcome{Classification: cls, Acked: acked}
	}

	return SstpOutcome{Classification: goSetSstp.ClassifyResult(result)}
}

// buildSets renders each outbound event to its on-wire SET string: forwarded
// verbatim in RouteModeForward, or signed with the pair's issuer key otherwise.
func (a *SstpHTTPAdapter) buildSets(req SstpRequest) map[string]string {
	if len(req.Events) == 0 {
		return nil
	}
	cfg := req.Stream.StreamConfiguration
	forward := cfg.RouteMode == model.RouteModeForward
	sets := make(map[string]string, len(req.Events))
	for _, ev := range req.Events {
		if ev == nil {
			continue
		}
		if forward {
			sets[ev.Jti] = ev.Original
			continue
		}
		signed, ok := signOne(req, ev)
		if !ok {
			continue
		}
		sets[ev.Jti] = signed
	}
	return sets
}

// signOne signs a single event SET with the pair's issuer key. Returns ("", false)
// when the key is missing or signing fails so the caller skips the JTI rather than
// emitting an unsigned SET.
func signOne(req SstpRequest, ev *model.AgEventRecord) (string, bool) {
	if req.Key == nil {
		return "", false
	}
	cfg := req.Stream.StreamConfiguration
	token := &ev.Event
	token.Issuer = cfg.Iss
	token.Audience = cfg.Aud
	token.IssuedAt = jwt.NewNumericDate(time.Now())
	token.Kid = req.Kid
	signed, err := token.JWS(jwt.SigningMethodRS256, req.Key)
	if err != nil {
		return "", false
	}
	return signed, true
}

// SstpMemoryAdapter is the in-memory SstpDelivery used by tests. It returns a
// scripted SstpOutcome — either a single outcome on every call, or a sequence
// consumed in order (the final entry repeats after exhaustion). It records each
// request so tests can assert what was sent, and honors ctx cancellation by
// returning a transport-class outcome (so lease-loss cancellation is observable).
type SstpMemoryAdapter struct {
	mu        sync.Mutex
	outcomes  []SstpOutcome
	calls     int
	requests  []SstpRequest
	blockCh   chan struct{}
	onDeliver func()
}

// NewSstpMemoryAdapter returns an adapter that yields outcome on every DeliverSstp call.
func NewSstpMemoryAdapter(outcome SstpOutcome) *SstpMemoryAdapter {
	return &SstpMemoryAdapter{outcomes: []SstpOutcome{outcome}}
}

// NewSstpMemoryScript returns an adapter that yields each entry of outcomes in
// order; the final entry repeats after exhaustion.
func NewSstpMemoryScript(outcomes ...SstpOutcome) *SstpMemoryAdapter {
	cp := make([]SstpOutcome, len(outcomes))
	copy(cp, outcomes)
	return &SstpMemoryAdapter{outcomes: cp}
}

// SetBlocking makes every DeliverSstp call block until ctx is cancelled or the
// adapter is unblocked, returning a ClassTransport outcome on cancellation. This
// lets a test prove that lease-loss cancels an in-flight cycle.
func (m *SstpMemoryAdapter) SetBlocking() {
	m.mu.Lock()
	m.blockCh = make(chan struct{})
	m.mu.Unlock()
}

// SetOnDeliver registers a callback invoked at the start of each DeliverSstp call
// (before any blocking), so tests can signal that a cycle began.
func (m *SstpMemoryAdapter) SetOnDeliver(fn func()) {
	m.mu.Lock()
	m.onDeliver = fn
	m.mu.Unlock()
}

// DeliverSstp implements SstpDelivery, returning the next scripted outcome and
// recording the request. If SetBlocking was called, it blocks until ctx is
// cancelled, then returns a ClassTransport outcome.
func (m *SstpMemoryAdapter) DeliverSstp(ctx context.Context, req SstpRequest) SstpOutcome {
	m.mu.Lock()
	m.requests = append(m.requests, req)
	idx := m.calls
	if idx >= len(m.outcomes) {
		idx = len(m.outcomes) - 1
	}
	m.calls++
	out := m.outcomes[idx]
	block := m.blockCh
	onDeliver := m.onDeliver
	m.mu.Unlock()

	if onDeliver != nil {
		onDeliver()
	}

	if block != nil {
		select {
		case <-ctx.Done():
			return SstpOutcome{Classification: goSetSstp.Classification{Class: goSetSstp.ClassTransport}}
		case <-block:
		}
	}
	return out
}

// Calls returns the number of DeliverSstp invocations observed so far.
func (m *SstpMemoryAdapter) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

// Requests returns a copy of the requests observed so far.
func (m *SstpMemoryAdapter) Requests() []SstpRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]SstpRequest, len(m.requests))
	copy(cp, m.requests)
	return cp
}
