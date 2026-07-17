package goSetSstp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/i2-open/i2goSignals/pkg/goSetPush"
)

// DialerConfig configures one SSTP HTTP cycle. Loop cadence, backoff, and
// credential resolution are the caller's responsibility — this package
// performs a single-cycle exchange only (ADR-0067). The struct mirrors the
// house pattern used by pkg/goSetPush.TransmitterConfig and
// pkg/goSetPoll's poll config: a flat value type carrying an already-resolved
// endpoint URL, an already-formed Authorization header value, and an
// injected *http.Client that owns TLS posture and any OAuth transport.
type DialerConfig struct {
	// EndpointURL is the peer's SSTP URL (…/sstp/{id}). Required.
	EndpointURL string

	// Authorization is the full HTTP Authorization header value; empty means
	// no Authorization header is sent. Consumers may pass "Bearer <tok>"
	// verbatim; no prefixing or normalization happens here.
	Authorization string

	// HTTPClient is the injected client that carries TLS posture and any
	// OAuth transport wrapping. Nil ⇒ a default *http.Client with a 60s
	// timeout is used.
	HTTPClient *http.Client

	// Timeout bounds the whole cycle when HTTPClient is nil; ignored when
	// HTTPClient is supplied (the caller's client owns its own timeout).
	// Zero ⇒ 60s default.
	Timeout time.Duration
}

// defaultDialerTimeout is the value used when DialerConfig.Timeout is zero
// AND DialerConfig.HTTPClient is nil. It matches goSetPush.PushSET's default.
const defaultDialerTimeout = 60 * time.Second

// Exchange executes one SSTP request/response cycle: marshal msg to the
// application/sstp+json body, POST it to EndpointURL with the configured
// Authorization header, parse a 200 response body back to *Message, and
// return a Result describing the outcome. Failure is signaled via the
// returned Result (never via a Go error return) so callers reach
// ClassifyResult without a null-safety branch — see classifier.go's Result
// contract for the encoding of transport-layer failure (StatusCode == 0),
// unparseable-200 (StatusCode == 200, Err non-nil, Message nil), and
// success-with-detail vs success-without-detail.
//
// Exchange is single-cycle: no retries, no backoff, no goroutines, no
// sleeps. Consumer-owned loops call Exchange once per attempt.
func Exchange(ctx context.Context, msg Message, config DialerConfig) Result {
	client := config.HTTPClient
	if client == nil {
		timeout := config.Timeout
		if timeout <= 0 {
			timeout = defaultDialerTimeout
		}
		client = &http.Client{Timeout: timeout}
	}

	body, err := json.Marshal(msg)
	if err != nil {
		// Marshal failure is a transport-layer failure from the caller's
		// perspective (no HTTP cycle occurred). Encoded as StatusCode == 0
		// with Err set so ClassifyResult returns ClassTransport.
		return Result{Err: fmt.Errorf("sstp: marshal request: %w", err)}
	}

	req, err := http.NewRequestWithContext(ctx, Method, config.EndpointURL, bytes.NewReader(body))
	if err != nil {
		return Result{Err: fmt.Errorf("sstp: build request: %w", err)}
	}
	req.Header.Set("Content-Type", ContentType)
	req.Header.Set("Accept", ContentType)
	if config.Authorization != "" {
		req.Header.Set("Authorization", config.Authorization)
	}

	resp, err := client.Do(req)
	if err != nil {
		return Result{Err: fmt.Errorf("sstp: HTTP exchange: %w", err)}
	}
	defer func() { _ = resp.Body.Close() }()

	// Retry-After parsing is delegated to goSetPush (single implementation for
	// both push and SSTP dialers) — pkg/goSetSstp already depends on
	// pkg/goSetPush for the ingestion adapter.
	retryAfter := goSetPush.ParseRetryAfter(resp.Header.Get("Retry-After"), time.Now())

	if resp.StatusCode != http.StatusOK {
		// Non-200: leave Message nil; drain the body so the connection
		// can be reused. Body content is not part of Result on non-200 —
		// callers classify off StatusCode.
		_, _ = io.Copy(io.Discard, resp.Body)
		return Result{
			StatusCode: resp.StatusCode,
			RetryAfter: retryAfter,
		}
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		// A 200 whose body cannot be read is not success — encode as
		// unparseable-200 so ClassifyResult returns ClassTransient.
		return Result{
			StatusCode: resp.StatusCode,
			Err:        fmt.Errorf("sstp: read 200 body: %w", err),
			RetryAfter: retryAfter,
		}
	}
	// Empty body on 200 is success-without-detail (Message nil, Err nil) —
	// the classifier maps that to ClassOK.
	if len(bytes.TrimSpace(respBody)) == 0 {
		return Result{StatusCode: resp.StatusCode, RetryAfter: retryAfter}
	}
	var out Message
	if err := json.Unmarshal(respBody, &out); err != nil {
		// A 200 with an unparseable body is treated as unparseable-200 so
		// ClassifyResult routes it to ClassTransient (never ClassOK): a
		// broken peer or on-path proxy returning 200 with garbage must
		// not be acked.
		return Result{
			StatusCode: resp.StatusCode,
			Err:        fmt.Errorf("sstp: parse 200 body: %w", err),
			RetryAfter: retryAfter,
		}
	}
	return Result{
		StatusCode: resp.StatusCode,
		Message:    &out,
		RetryAfter: retryAfter,
	}
}
