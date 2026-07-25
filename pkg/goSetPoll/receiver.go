package goSetPoll

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetValidate"
	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
)

// PollRaw sends an RFC8936 poll request to the configured endpoint and returns
// the raw PollResponse without parsing individual SET tokens.
// Returns the response, the HTTP status code, and any error.
// On HTTP-level errors (status >= 400), the PollResponse is nil and the error describes the failure.
func PollRaw(ctx context.Context, request PollRequest, config ReceiverConfig) (*PollResponse, int, error) {
	log := getLogger(config.Logger)

	client := config.HTTPClient
	if client == nil {
		client = &http.Client{}
		tlsSupport.CheckCaInstalled(client)
	}

	bodyBytes, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		return nil, 0, fmt.Errorf("RFC8936: error marshaling poll request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.EndpointURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, 0, fmt.Errorf("RFC8936: error creating poll request: %w", err)
	}

	// Set proper JSON headers per RFC8936 poll request conventions
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if config.Authorization != "" {
		req.Header.Set("Authorization", config.Authorization)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 400 {
		// Read a small portion of the body for diagnostics without overwhelming logs
		b, _ := io.ReadAll(resp.Body)
		if len(b) > 512 {
			b = b[:512]
		}
		log.Debug("RFC8936: Poll returned error status", "status", resp.StatusCode, "body", string(b))
		return nil, resp.StatusCode, fmt.Errorf("RFC8936: HTTP %s", resp.Status)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("RFC8936: error reading response body: %w", err)
	}

	var pollResponse PollResponse
	if err := json.Unmarshal(respBody, &pollResponse); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("RFC8936: error parsing poll response: %w", err)
	}

	return &pollResponse, resp.StatusCode, nil
}

// Poll sends an RFC8936 poll request to the configured endpoint, parses the response,
// and validates each SET token using the configured JWKS, issuer, and audience settings.
//
// Successfully validated tokens are placed in ParsedSETs. Tokens that fail parsing
// or validation are placed in Errors, ready to be sent back as SetErrs in the next poll.
//
// Returns the parsed response, the HTTP status code, and any transport/protocol error.
func Poll(ctx context.Context, request PollRequest, config ReceiverConfig) (*ParsedPollResponse, int, error) {
	rawResp, statusCode, err := PollRaw(ctx, request, config)
	if err != nil {
		return nil, statusCode, err
	}

	log := getLogger(config.Logger)

	result := &ParsedPollResponse{
		Sets:          rawResp.Sets,
		ParsedSETs:    make(map[string]*goSet.SecurityEventToken),
		Errors:        make(map[string]SetErrType),
		MoreAvailable: rawResp.MoreAvailable,
	}
	// Only allocated when validation is engaged, so an unconfigured receiver
	// reports a nil Validations map — the documented "zero" (spec #247 #251).
	if config.Validators != nil {
		result.Validations = make(map[string]goSetValidate.SetResult, len(rawResp.Sets))
	}

	for jti, setString := range rawResp.Sets {
		// Per ADR-0066 §D2 the "None + unverified" state is unrepresentable:
		// every business stream MUST have at least one active authentication
		// layer. Stream-config validation enforces this at configure time
		// (i2goSignals#235); this poll receiver enforces it defensively at
		// runtime — nil JWKS is always a rejection, an unverified parse is
		// never the accepted token. Signature failures are expected peer
		// events (WARN, CONTEXT.md log-level policy).
		if config.JWKS == nil {
			if config.RequireSignature {
				log.Warn("RFC8936: SET signature required but no JWKS available to verify (signing-only)", "jti", jti)
				result.Errors[jti] = SetErrType{
					Error:       "jws_signature_failed",
					Description: "The SET signature could not be validated.",
				}
				continue
			}
			// Defense in depth for ADR-0066 §D2 — see receiver.go in goSetPush.
			log.Warn("RFC8936: no JWKS configured; refusing to accept unverified SET (ADR-0066)", "jti", jti)
			result.Errors[jti] = SetErrType{
				Error:       "invalid_request",
				Description: "The SET could not be verified: no trust anchor is configured.",
			}
			continue
		}

		token, err := goSet.Parse(setString, config.JWKS)
		if err != nil {
			// When verifying against a JWKS under the signing-only posture, a parse
			// failure is a bad signature → jws_signature_failed (the RFC8935 §2.4
			// rotate-and-retry signal). Otherwise the prior invalid_request is kept.
			if config.RequireSignature {
				log.Warn("RFC8936: SET signature verification failed (signing-only)", "jti", jti, "error", err)
				result.Errors[jti] = SetErrType{
					Error:       "jws_signature_failed",
					Description: "The SET signature could not be validated.",
				}
				continue
			}
			log.Warn("RFC8936: SET parsing error", "jti", jti, "error", err)
			result.Errors[jti] = SetErrType{
				Error:       "invalid_request",
				Description: "The SET could not be parsed: " + err.Error(),
			}
			continue
		}

		// Validate issuer
		if config.ExpectedIssuer != "" {
			if token.Issuer != config.ExpectedIssuer {
				log.Warn("RFC8936: Invalid issuer", "jti", jti, "expected", config.ExpectedIssuer, "actual", token.Issuer)
				result.Errors[jti] = SetErrType{
					Error:       "invalid_issuer",
					Description: "The SET Issuer is invalid for the SET Recipient.",
				}
				continue
			}
		}

		// Validate audience
		if len(config.ExpectedAudiences) > 0 {
			audMatch := false
			for _, aud := range config.ExpectedAudiences {
				if slices.Contains([]string(token.Audience), aud) {
					audMatch = true
					break
				}
			}
			if !audMatch {
				log.Warn("RFC8936: Audience mismatch", "jti", jti, "actual", token.Audience)
				result.Errors[jti] = SetErrType{
					Error:       "invalid_audience",
					Description: "The SET Audience does not correspond to the SET Recipient.",
				}
				continue
			}
		}

		// Event-payload validation (spec #247). Runs only once the SET is fully
		// trusted — signature, iss and aud are all settled above — and only
		// reports: the JTI still lands in ParsedSETs whatever the disposition, so
		// this package never silently drops or nacks an event. The caller reads
		// Validations, applies the stream's event_validation mode, and decides
		// between ack and setErrs.
		if config.Validators != nil {
			result.Validations[jti] = config.Validators.Validate(token)
		}

		result.ParsedSETs[jti] = token
	}

	return result, statusCode, nil
}
