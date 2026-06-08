package goSetSstp

import (
	"net/http"
	"time"
)

// FailureClass categorizes an SSTP response into the action the SSTP-client should take.
// It is the bridge between the SSTP wire protocol and the caller's recovery state machine,
// parallel to goSetPush.FailureClass. HTTP status is the primary error signal end-to-end;
// per-JTI "setErrs" are read only after a successful 200 body parse (§2.3, Q20).
type FailureClass int

const (
	// ClassOK: HTTP 200 with no per-JTI errors. The cycle succeeded; continue.
	ClassOK FailureClass = iota

	// ClassTransport: connection refused, DNS failure, TLS handshake failure, timeout — no HTTP
	// response was received. Caller should back off per POLL_RETRY_* and retry.
	ClassTransport

	// ClassTransient: HTTP 5xx. The peer is reachable but failing transiently. Caller should
	// back off and retry; the direction is NOT paused.
	ClassTransient

	// ClassRequestError: HTTP 4xx (auth/path/content-type/JSON-parse, exhausted-auth-retries,
	// deleted pair). Request-level failure; the caller pauses ONLY the affected direction of the
	// pair (Q12.3). A paused pair is signaled differently — 200 with returnEvents=false, not 4xx.
	ClassRequestError

	// ClassPerJTI: HTTP 200 with a non-empty "setErrs" object. The cycle itself succeeded but one
	// or more individual SETs were rejected; Classification.SetErrs carries the per-JTI detail.
	ClassPerJTI

	// ClassWeirdResponse: any status outside the 2xx/4xx/5xx contract (e.g. 1xx, 3xx). Treated as
	// a misconfigured peer, parallel to goSetPush.ClassWeirdResponse.
	ClassWeirdResponse
)

// String returns the FailureClass label suitable for logs and metric labels.
func (c FailureClass) String() string {
	switch c {
	case ClassOK:
		return "OK"
	case ClassTransport:
		return "Transport"
	case ClassTransient:
		return "Transient"
	case ClassRequestError:
		return "RequestError"
	case ClassPerJTI:
		return "PerJTI"
	case ClassWeirdResponse:
		return "WeirdResponse"
	default:
		return "Unknown"
	}
}

// Result describes the outcome of one SSTP HTTP cycle as observed by the SSTP-client, the input
// to ClassifyResult.
type Result struct {
	// StatusCode is the HTTP status received from the SSTP-server. Zero means no response was
	// received (transport-layer failure).
	StatusCode int

	// Err is non-nil if the cycle failed at the transport layer or the body could not be parsed.
	Err error

	// Message is the parsed SSTP response body, when a 200 body was successfully parsed. The
	// classifier inspects its SetErrs to distinguish ClassOK from ClassPerJTI.
	Message *Message

	// RetryAfter is the parsed value of any Retry-After response header. Zero when absent.
	RetryAfter time.Duration
}

// Classification is the structured output of ClassifyResult — what happened and what the caller
// needs to make a recovery decision. Mirrors goSetPush.Classification's surface.
type Classification struct {
	// Class is the FailureClass enum value.
	Class FailureClass

	// NextDelay is the peer-suggested wait before the next attempt, parsed from Retry-After.
	// Zero when no Retry-After was present.
	NextDelay time.Duration

	// SetErrs carries the per-JTI errors for ClassPerJTI; empty otherwise.
	SetErrs map[string]SetErr
}

// ClassifyResult maps an SSTP Result to its FailureClass and the metadata needed for recovery.
// 4xx → request-level, 5xx → transient, 200-with-non-empty-setErrs → per-JTI (Q12.1, Q12.2, Q20).
func ClassifyResult(result Result) Classification {
	// Transport-layer failure: no HTTP response received.
	if result.StatusCode == 0 {
		return Classification{Class: ClassTransport}
	}

	if result.StatusCode == http.StatusOK {
		if result.Message != nil && len(result.Message.SetErrs) > 0 {
			return Classification{
				Class:     ClassPerJTI,
				NextDelay: result.RetryAfter,
				SetErrs:   result.Message.SetErrs,
			}
		}
		return Classification{Class: ClassOK, NextDelay: result.RetryAfter}
	}

	if result.StatusCode >= 400 && result.StatusCode <= 499 {
		return Classification{Class: ClassRequestError, NextDelay: result.RetryAfter}
	}

	if result.StatusCode >= 500 && result.StatusCode <= 599 {
		return Classification{Class: ClassTransient, NextDelay: result.RetryAfter}
	}

	return Classification{Class: ClassWeirdResponse, NextDelay: result.RetryAfter}
}
