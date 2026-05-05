package goSetPush

import (
	"errors"
	"net/http"
	"strconv"
	"time"
)

// FailureClass categorizes a push response into the action the transmitter should take.
// The classifier is the bridge between the RFC8935 wire protocol and the caller's recovery
// state machine — every push response maps to exactly one FailureClass.
type FailureClass int

const (
	// ClassAccepted: 202 — the receiver took ownership of the SET. Ack and continue.
	ClassAccepted FailureClass = iota

	// ClassTransport: connection refused, DNS failure, TLS handshake failure, timeout.
	// No HTTP response was received. Caller should exponentially back off, capped by total elapsed time.
	ClassTransport

	// ClassServerError: HTTP 5xx (excluding 503 with Retry-After, which falls under RateLimited semantics).
	// Caller should exponentially back off, capped by total elapsed time.
	ClassServerError

	// ClassUnauthorized: HTTP 401. Bounded retries (the receiver's auth may be momentarily inconsistent).
	ClassUnauthorized

	// ClassForbidden: HTTP 403. The receiver has rejected this transmitter. Disable immediately.
	ClassForbidden

	// ClassRateLimited: HTTP 429 (or any response carrying a Retry-After header). Honor Retry-After.
	ClassRateLimited

	// ClassRFC8935Error: HTTP 400 with a parseable RFC8935 §2.4 DeliveryErr body. The error code on
	// PushResult.Err (a *DeliveryErr) determines the sub-policy (e.g. jws_signature_failed → key flush).
	ClassRFC8935Error

	// ClassWeirdClientError: HTTP 4xx other than 400/401/403/429 (e.g. 404, 410, 422). Treated as
	// configuration error: the receiver is responding but rejecting the request shape. Disable.
	ClassWeirdClientError

	// ClassWeirdResponse: any other status code (e.g. 1xx, 3xx, 200 instead of 202, or unparseable 400).
	// Treated as a misconfigured receiver. Disable.
	ClassWeirdResponse
)

// String returns the FailureClass label suitable for logs and metric labels.
func (c FailureClass) String() string {
	switch c {
	case ClassAccepted:
		return "Accepted"
	case ClassTransport:
		return "Transport"
	case ClassServerError:
		return "ServerError"
	case ClassUnauthorized:
		return "Unauthorized"
	case ClassForbidden:
		return "Forbidden"
	case ClassRateLimited:
		return "RateLimited"
	case ClassRFC8935Error:
		return "RFC8935Error"
	case ClassWeirdClientError:
		return "WeirdClientError"
	case ClassWeirdResponse:
		return "WeirdResponse"
	default:
		return "Unknown"
	}
}

// Classification is the structured output of ClassifyResult — what happened and what the caller
// should know to make a recovery decision.
type Classification struct {
	// Class is the FailureClass enum value.
	Class FailureClass

	// NextDelay is the receiver-suggested wait before the next attempt, parsed from Retry-After.
	// Zero when no Retry-After was present. Caller may treat zero as "use my own backoff".
	NextDelay time.Duration

	// RFC8935ErrCode is set only for ClassRFC8935Error and carries the receiver's error code
	// (e.g. "jws_signature_failed", "invalid_audience"). Empty otherwise.
	RFC8935ErrCode string

	// RFC8935Description is set only for ClassRFC8935Error and carries the receiver's human-readable
	// error description (informational; for logging and operator diagnostics).
	RFC8935Description string
}

// ClassifyResult maps a PushResult to its FailureClass and the metadata needed for recovery.
// The caller — the push state machine — uses Classification.Class to dispatch the next action.
func ClassifyResult(result PushResult) Classification {
	if result.Accepted {
		return Classification{Class: ClassAccepted, NextDelay: result.RetryAfter}
	}

	// Transport-layer failure: no HTTP response received. PushSET reports this with Err set
	// and StatusCode == 0.
	if result.StatusCode == 0 {
		return Classification{Class: ClassTransport}
	}

	switch result.StatusCode {
	case http.StatusBadRequest:
		var deliveryErr *DeliveryErr
		if errors.As(result.Err, &deliveryErr) {
			return Classification{
				Class:              ClassRFC8935Error,
				NextDelay:          result.RetryAfter,
				RFC8935ErrCode:     deliveryErr.ErrCode,
				RFC8935Description: deliveryErr.Description,
			}
		}
		// 400 without parseable RFC8935 body → receiver is misbehaving.
		return Classification{Class: ClassWeirdResponse, NextDelay: result.RetryAfter}

	case http.StatusUnauthorized:
		return Classification{Class: ClassUnauthorized, NextDelay: result.RetryAfter}

	case http.StatusForbidden:
		return Classification{Class: ClassForbidden, NextDelay: result.RetryAfter}

	case http.StatusTooManyRequests:
		return Classification{Class: ClassRateLimited, NextDelay: result.RetryAfter}
	}

	if result.StatusCode >= 500 && result.StatusCode <= 599 {
		// 503 with Retry-After is back-pressure from the peer rather than an error condition.
		// Treat it as RateLimited so the caller honors Retry-After uncapped, instead of folding
		// it into the bounded transport-backoff window.
		if result.StatusCode == http.StatusServiceUnavailable && result.RetryAfter > 0 {
			return Classification{Class: ClassRateLimited, NextDelay: result.RetryAfter}
		}
		return Classification{Class: ClassServerError, NextDelay: result.RetryAfter}
	}

	if result.StatusCode >= 400 && result.StatusCode <= 499 {
		return Classification{Class: ClassWeirdClientError, NextDelay: result.RetryAfter}
	}

	return Classification{Class: ClassWeirdResponse, NextDelay: result.RetryAfter}
}

// ParseRetryAfter parses an HTTP Retry-After header value. Per RFC9110 §10.2.3, the value may be
// either delta-seconds (integer) or an HTTP-date. Returns zero on empty, malformed, or past values.
// The `now` argument allows callers to inject a clock for deterministic testing.
func ParseRetryAfter(value string, now time.Time) time.Duration {
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds <= 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil {
		delta := when.Sub(now)
		if delta <= 0 {
			return 0
		}
		return delta
	}
	return 0
}
