// Package goSetPush implements the RFC8935 Push-Based Delivery of Security Event Tokens (SETs) using HTTP.
// It provides both transmitter-side (HTTP client pushing SETs) and receiver-side (HTTP handler accepting
// pushed SETs) protocol handling. This package handles only the wire protocol; authentication, event routing,
// and persistence are the caller's responsibility.
package goSetPush

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/MicahParks/keyfunc"
	"github.com/i2-open/i2goSignals/pkg/goSet"
)

// RFC8935 error codes per Section 2.4.
const (
	ErrAccessDenied         = "access_denied"
	ErrAuthenticationFailed = "authentication_failed"
	ErrNotFound             = "not_found"
	ErrInvalidRequest       = "invalid_request"
	ErrInvalidIssuer        = "invalid_issuer"
	ErrInvalidAudience      = "invalid_audience"
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
}

// ReceiverConfig configures the push receiver protocol handler.
type ReceiverConfig struct {
	// JWKS used to validate incoming SET signatures. If nil, tokens are parsed without signature verification.
	JWKS *keyfunc.JWKS

	// ExpectedIssuer is the expected "iss" claim value. If empty, issuer validation is skipped.
	ExpectedIssuer string

	// ExpectedAudiences is the list of acceptable "aud" values. If empty, audience validation is skipped.
	ExpectedAudiences []string

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
}
