// Package goSetPoll implements the RFC8936 Poll-Based Delivery of Security Event Tokens (SETs) using HTTP.
// It provides both transmitter-side (HTTP handler serving poll requests) and receiver-side (HTTP client
// polling for SETs) protocol handling. This package handles only the wire protocol; authentication, event
// routing, and persistence are the caller's responsibility.
package goSetPoll

import (
	"log/slog"
	"net/http"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetValidate"
)

// PollRequest represents the JSON body of an RFC8936 poll request.
type PollRequest struct {
	// MaxEvents is an optional integer indicating the maximum number of unacknowledged SETs to return.
	MaxEvents int32 `json:"maxEvents,omitzero"`

	// ReturnImmediately indicates whether the transmitter should return immediately even if no results
	// are available (short polling). When false, the transmitter may hold the connection open (long polling).
	ReturnImmediately bool `json:"returnImmediately,omitzero"`

	// Acks is a list of event JTIs that the receiver is acknowledging.
	Acks []string `json:"ack,omitempty"`

	// SetErrs reports errors for specific SETs identified by JTI.
	SetErrs map[string]SetErrType `json:"setErrs,omitempty"`

	// TimeoutSecs is an optional timeout in seconds for long polling.
	TimeoutSecs int `json:"timeoutSecs,omitzero"`
}

// PollResponse represents the JSON body of an RFC8936 poll response.
type PollResponse struct {
	// Sets maps JTI to the corresponding SET token string (JWT).
	Sets map[string]string `json:"sets"`

	// MoreAvailable indicates whether additional SETs are ready to be delivered.
	MoreAvailable bool `json:"moreAvailable,omitzero"`
}

// SetErrType represents an error reported by the receiver for a specific SET.
type SetErrType struct {
	Error       string `json:"err"`
	Description string `json:"description,omitempty"`
}

// ParsedPollResponse extends PollResponse with parsed and validated SET tokens.
type ParsedPollResponse struct {
	// Sets contains the raw SET token strings keyed by JTI.
	Sets map[string]string

	// ParsedSETs maps JTI to the parsed SecurityEventToken for tokens that passed
	// parsing and issuer/audience validation.
	ParsedSETs map[string]*goSet.SecurityEventToken

	// Errors maps JTI to a SetErrType for tokens that failed parsing or validation.
	// These should be sent back in the next poll's SetErrs field.
	Errors map[string]SetErrType

	// Validations maps JTI to the event-payload dispositions computed by
	// ReceiverConfig.Validators, for every JTI that reached ParsedSETs. It is nil
	// when no validator set was configured. A malformed or unsupported disposition
	// does NOT move a JTI into Errors — this package reports, and the caller that
	// owns event_validation mode policy decides whether the JTI is acked or
	// reported in the next poll's setErrs.
	Validations map[string]goSetValidate.SetResult

	// MoreAvailable indicates whether the transmitter has more events ready.
	MoreAvailable bool
}

// ReceiverConfig configures the poll receiver (HTTP client).
type ReceiverConfig struct {
	// EndpointURL is the transmitter's poll endpoint.
	EndpointURL string

	// Authorization is the full Authorization header value (e.g., "Bearer <token>").
	Authorization string

	// JWKS for validating received SET signatures. If nil, tokens are parsed without verification.
	JWKS *keyfunc.JWKS

	// ExpectedIssuer is the expected "iss" claim. Empty skips validation.
	ExpectedIssuer string

	// ExpectedAudiences is the list of acceptable "aud" values. Empty skips validation.
	ExpectedAudiences []string

	// RequireSignature makes signature verification of pulled SETs mandatory (#184
	// signing-only posture): a SET is rejected with jws_signature_failed when no JWKS
	// is available to verify it or when verification fails. When false (default),
	// verification is conditional on JWKS being non-nil (prior behavior).
	RequireSignature bool

	// Validators optionally engages event-payload validation for this receiver
	// stream (spec #247). When nil — the default — no validation runs and
	// ParsedPollResponse.Validations stays nil, so behavior is exactly as it was
	// before the field existed. When set, dispositions are computed per JTI and
	// reported on ParsedPollResponse.Validations; this package NEVER moves a JTI
	// into Errors because of one. event_validation mode policy
	// (NONE/WARN/ENFORCE/STRICT), the ack/setErrs decision, and the metrics
	// belong to the caller.
	Validators *goSetValidate.ValidatorSet

	// HTTPClient is an optional custom HTTP client. If nil, a default is used.
	HTTPClient *http.Client

	// Logger is an optional structured logger. If nil, a default is used.
	Logger *slog.Logger
}

var defaultLogger = slog.Default()

func getLogger(l *slog.Logger) *slog.Logger {
	if l != nil {
		return l
	}
	return defaultLogger
}
