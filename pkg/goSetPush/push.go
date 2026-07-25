// Package goSetPush implements the RFC8935 Push-Based Delivery of Security Event Tokens (SETs) using HTTP.
// It provides both transmitter-side (HTTP client pushing SETs) and receiver-side (HTTP handler accepting
// pushed SETs) protocol handling. This package handles only the wire protocol; authentication, event routing,
// and persistence are the caller's responsibility.
package goSetPush

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetValidate"
)

// RFC8935 error codes per Section 2.4.
const (
	ErrAccessDenied         = "access_denied"
	ErrAuthenticationFailed = "authentication_failed"
	ErrNotFound             = "not_found"
	ErrInvalidRequest       = "invalid_request"
	ErrInvalidIssuer        = "invalid_issuer"
	ErrInvalidAudience      = "invalid_audience"
	ErrInvalidKey           = "invalid_key"
	ErrJwsSignatureFailed   = "jws_signature_failed"
	ErrJweDecryptionFailed  = "jwe_decryption_failed"
)

// DeliveryErr represents an RFC8935 SET delivery error response.
// It is returned as JSON in the body of 400 Bad Request responses.
type DeliveryErr struct {
	ErrCode     string `json:"err"`
	Description string `json:"description"`
}

// Error implements the error interface.
func (e *DeliveryErr) Error() string {
	return fmt.Sprintf("%s: %s", e.ErrCode, e.Description)
}

// ReceivedSET holds a parsed and validated SET from an incoming push.
type ReceivedSET struct {
	Token       *goSet.SecurityEventToken
	TokenString string

	// Validation reports the event-payload dispositions computed by
	// ReceiverConfig.Validators, so the caller that owns event_validation mode
	// policy can act on them and count them. It is the ZERO SetResult
	// (Disposition == goSetValidate.Valid, no Results) when no validator set was
	// configured — this package never rejects on a disposition and never maps one
	// to an RFC8935 error.
	Validation goSetValidate.SetResult
}

// ReceiverConfig configures the push receiver protocol handler.
type ReceiverConfig struct {
	// JWKS used to validate incoming SET signatures. If nil, tokens are parsed without signature verification.
	JWKS *keyfunc.JWKS

	// ExpectedIssuer is the expected "iss" claim value. If empty, issuer validation is skipped.
	ExpectedIssuer string

	// ExpectedAudiences is the list of acceptable "aud" values. If empty, audience validation is skipped.
	ExpectedAudiences []string

	// RequireSignature makes JWS signature verification mandatory (#184 signing-only
	// posture): the SET is rejected with jws_signature_failed if no JWKS is available
	// to verify against or if verification fails. When false (default) behavior is
	// unchanged — a nil JWKS skips verification and a verify failure is invalid_request.
	RequireSignature bool

	// Validators optionally engages event-payload validation for this receiver
	// stream (spec #247). When nil — the default — no validation runs and
	// ReceivedSET.Validation is left zero, so behavior is exactly as it was
	// before the field existed. When set, dispositions are computed and reported
	// on ReceivedSET.Validation; this package NEVER rejects a SET because of one.
	// event_validation mode policy (NONE/WARN/ENFORCE/STRICT), the wire mapping,
	// and the metrics belong to the caller.
	Validators *goSetValidate.ValidatorSet

	// Logger is an optional structured logger. If nil, a default is used.
	Logger *slog.Logger
}

// TransmitterConfig configures the push transmitter (HTTP client).
type TransmitterConfig struct {
	// EndpointURL is the receiver's push endpoint.
	EndpointURL string

	// Authorization is the full Authorization header value (e.g., "Bearer <token>").
	// If empty, no Authorization header is sent.
	Authorization string

	// HTTPClient is an optional custom HTTP client. If nil, a default with 60s timeout is used.
	HTTPClient *http.Client

	// InsecureSkipVerify, when true and HTTPClient is nil, builds the default
	// client with TLS certificate verification disabled. It carries the stream's
	// tx_tls_skip_verify flag for receivers that present a self-signed or
	// otherwise unverifiable TLS cert. Ignored when HTTPClient is supplied.
	InsecureSkipVerify bool

	// Logger is an optional structured logger. If nil, a default is used.
	Logger *slog.Logger
}

// PushResult describes the outcome of a push attempt.
type PushResult struct {
	// StatusCode is the HTTP status code received from the receiver.
	StatusCode int

	// Err is non-nil if the push failed. For 400 responses, this is a *DeliveryErr.
	Err error

	// Accepted is true when the receiver returned 202 Accepted.
	Accepted bool

	// RetryAfter is the parsed value of the Retry-After response header, if present.
	// Set for any response (typically 429 or 503). Zero when the header is absent or unparseable.
	RetryAfter time.Duration
}
