package goSetSstp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
)

// ReqError is the gate/parse rejection surface. The consumer decides how to
// render — plain-text http.Error, RFC-8935-style JSON envelope, or the
// consumer's own error shape — because "today's shape" already differs
// between community (JSON DeliveryErr) and admin (plain text). Rendering is
// deliberately consumer-local (ADR-0067 carve-out: policy stays with the
// consumer); pkg/goSetSstp only reports the classification.
//
// Status is the HTTP status the consumer SHOULD emit; Err is a short
// machine-readable token (mirroring the RFC-8935 error-code shape); and
// Description is human-readable detail suitable for the response body.
type ReqError struct {
	Status      int
	Err         string
	Description string
}

// Error implements the error interface so *ReqError may be wrapped or
// returned where a Go error is expected in tests.
func (e *ReqError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("sstp: %s (%d): %s", e.Err, e.Status, e.Description)
}

// Rejection-vocabulary tokens used inside ReqError.Err. They are neutral
// short slugs (not the SSTP §2.3 per-JTI keywords, which are strictly for
// per-SET rejections inside a 200 response body). Consumers may pass these
// through or remap to their preferred error surface.
const (
	// ErrCodeMethodNotAllowed: HTTP method != Method (POST).
	ErrCodeMethodNotAllowed = "method_not_allowed"
	// ErrCodeUnsupportedMediaType: Content-Type base is not
	// application/sstp+json (parameters ignored).
	ErrCodeUnsupportedMediaType = "unsupported_media_type"
	// ErrCodePayloadTooLarge: request body exceeded the caller's cap.
	ErrCodePayloadTooLarge = "payload_too_large"
	// ErrCodeInvalidRequest: body was unreadable, empty when required, or
	// unparseable as application/sstp+json.
	ErrCodeInvalidRequest = "invalid_request"
)

// CheckExchangeRequest is the acceptor's pre-auth gate: it enforces the
// method (405 on mismatch) and the Content-Type base type (415 on mismatch,
// media-type parameters tolerated via mime.ParseMediaType). It NEVER reads
// r.Body — this is deliberate so a consumer can keep its observable ordering
// (auth gates before body gates) with no pre-auth body read. Callers that
// want body gating call ParseExchangeRequest after their auth check.
//
// The Method check returns a 405 with an "Allow" header value set to Method
// so consumers can propagate it to the response.
//
// Returns nil when the request passes both gates.
func CheckExchangeRequest(r *http.Request) *ReqError {
	if r.Method != Method {
		return &ReqError{
			Status:      http.StatusMethodNotAllowed,
			Err:         ErrCodeMethodNotAllowed,
			Description: "SSTP endpoint accepts " + Method + " only",
		}
	}
	baseType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(baseType, ContentType) {
		return &ReqError{
			Status:      http.StatusUnsupportedMediaType,
			Err:         ErrCodeUnsupportedMediaType,
			Description: "Expecting Content-Type " + ContentType,
		}
	}
	return nil
}

// ParseOptions configures the acceptor body-parse step.
//
// MaxBodyBytes caps the request body length. Zero (the zero value)
// disables the cap — pkg/goSetSstp does NOT impose a default; the consumer
// chooses. When set to N > 0, a body larger than N bytes is rejected with a
// 413 (ErrCodePayloadTooLarge). This lets community stay uncapped (its
// tests exercise large SET batches) while admin can hardcode a 4 MiB cap.
type ParseOptions struct {
	MaxBodyBytes int64
}

// ParseExchangeRequest reads and JSON-decodes the SSTP request body,
// assuming CheckExchangeRequest has already passed. It owns the 413/400
// body-gate half of the acceptor pipeline. Returns (msg, nil) on success or
// (nil, *ReqError) on any parse failure.
//
// An empty body is valid — the returned Message is a zero-value Message
// (nil pointers, empty maps), matching the SSTP draft's "unspecified"
// defaults; the caller uses Message.ReturnEventsResolved / .ReturnImmediately
// -Resolved to apply the §2.1 defaults.
//
// r.Body is drained but not closed — request lifecycle stays with the
// consumer (net/http closes it on handler return).
func ParseExchangeRequest(r *http.Request, opts ParseOptions) (*Message, *ReqError) {
	reader := r.Body
	var maxCap int64
	if opts.MaxBodyBytes > 0 {
		maxCap = opts.MaxBodyBytes
		// http.MaxBytesReader wraps the reader so an over-size body errors
		// with a *http.MaxBytesError (Go 1.19+). It also caps subsequent
		// io.ReadAll cleanly.
		reader = http.MaxBytesReader(nil, r.Body, maxCap)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, &ReqError{
				Status:      http.StatusRequestEntityTooLarge,
				Err:         ErrCodePayloadTooLarge,
				Description: fmt.Sprintf("SSTP request body exceeds cap of %d bytes", maxCap),
			}
		}
		return nil, &ReqError{
			Status:      http.StatusBadRequest,
			Err:         ErrCodeInvalidRequest,
			Description: "Unable to read SSTP request body",
		}
	}
	msg := &Message{}
	if len(body) > 0 {
		if jErr := json.Unmarshal(body, msg); jErr != nil {
			return nil, &ReqError{
				Status:      http.StatusBadRequest,
				Err:         ErrCodeInvalidRequest,
				Description: "SSTP request body is not valid application/sstp+json",
			}
		}
	}
	return msg, nil
}

// WriteExchangeResponse writes msg as a 200 OK SSTP response body with the
// strict application/sstp+json Content-Type. Error rendering (405/415/413/
// 400) is deliberately NOT provided — see the ReqError doc for the
// consumer-local rendering rationale.
//
// The returned error is non-nil only on JSON-marshal or Write failure; the
// consumer usually logs and drops it (the response has already been
// committed by the time a Write fails).
func WriteExchangeResponse(w http.ResponseWriter, msg Message) error {
	body, err := json.Marshal(msg)
	if err != nil {
		// Write an explicit 500 so a caller that only logs the returned
		// error does not exit with net/http's implicit 200-OK-empty-body,
		// which a peer would treat as "no detail, delivered" — silently
		// dropping SETs on a marshal failure.
		w.WriteHeader(http.StatusInternalServerError)
		return fmt.Errorf("sstp: marshal response: %w", err)
	}
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("sstp: write response: %w", err)
	}
	return nil
}
