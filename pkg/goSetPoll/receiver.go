package goSetPoll

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/i2-open/i2goSignals/pkg/goSet"
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
		log.Debug("RFC8936: Poll returned error status", "status", resp.StatusCode)
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

	for jti, setString := range rawResp.Sets {
		token, err := goSet.Parse(setString, config.JWKS)
		if err != nil {
			log.Warn("RFC8936: SET parsing error", "jti", jti, "error", err)
			result.Errors[jti] = SetErrType{
				Error:       "invalid_request",
				Description: "The SET could not be parsed: " + err.Error(),
			}
			continue
		}

		// Validate issuer
		if config.ExpectedIssuer != "" {
			if !token.VerifyIssuer(config.ExpectedIssuer, true) {
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
				if token.VerifyAudience(aud, false) {
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

		result.ParsedSETs[jti] = token
	}

	return result, statusCode, nil
}
