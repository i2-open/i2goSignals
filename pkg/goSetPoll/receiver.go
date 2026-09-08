package goSetPoll

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime"
	"slices"
	"sort"
	"sync"

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

	// Compact, not indented — see WritePollResponse. A poll request is
	// machine-to-machine and is sent once per polling interval per stream.
	bodyBytes, err := json.Marshal(request)
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

	// Signature verification is the CPU cost of a poll response and has no
	// shared state, so the SETs are verified across the cores; the outcomes
	// are merged into the result maps on this goroutine.
	jtis := make([]string, 0, len(rawResp.Sets))
	for jti := range rawResp.Sets {
		jtis = append(jtis, jti)
	}
	sort.Strings(jtis)
	outcomes := make([]pollSetOutcome, len(jtis))
	workers := runtime.GOMAXPROCS(0)
	if workers > len(jtis) {
		workers = len(jtis)
	}
	if workers <= 1 {
		for i, jti := range jtis {
			outcomes[i] = verifyPollSet(log, config, jti, rawResp.Sets[jti])
		}
	} else {
		next := make(chan int, len(jtis))
		for i := range jtis {
			next <- i
		}
		close(next)
		var wg sync.WaitGroup
		wg.Add(workers)
		for w := 0; w < workers; w++ {
			go func() {
				defer wg.Done()
				for i := range next {
					outcomes[i] = verifyPollSet(log, config, jtis[i], rawResp.Sets[jtis[i]])
				}
			}()
		}
		wg.Wait()
	}
	for i, jti := range jtis {
		o := outcomes[i]
		if o.setErr != nil {
			result.Errors[jti] = *o.setErr
			continue
		}
		if config.Validators != nil {
			result.Validations[jti] = o.validation
		}
		result.ParsedSETs[jti] = o.token
	}

	return result, statusCode, nil
}

// pollSetOutcome is the disposition of one SET of a poll response: either a
// setErr to report back, or the verified token (with its event-payload
// validation when a validator set is configured).
type pollSetOutcome struct {
	token      *goSet.SecurityEventToken
	validation goSetValidate.SetResult
	setErr     *SetErrType
}

// verifyPollSet applies the receiver's trust checks to one SET: JWKS presence,
// signature (goSet.Parse), issuer, audience, then event-payload validation.
func verifyPollSet(log *slog.Logger, config ReceiverConfig, jti, setString string) pollSetOutcome {
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
			return pollSetOutcome{setErr: &SetErrType{
				Error:       "jws_signature_failed",
				Description: "The SET signature could not be validated.",
			}}
		}
		// Defense in depth for ADR-0066 §D2 — see receiver.go in goSetPush.
		log.Warn("RFC8936: no JWKS configured; refusing to accept unverified SET (ADR-0066)", "jti", jti)
		return pollSetOutcome{setErr: &SetErrType{
			Error:       "invalid_request",
			Description: "The SET could not be verified: no trust anchor is configured.",
		}}
	}

	token, err := goSet.Parse(setString, config.JWKS)
	if err != nil {
		// When verifying against a JWKS under the signing-only posture, a parse
		// failure is a bad signature → jws_signature_failed (the RFC8935 §2.4
		// rotate-and-retry signal). Otherwise the prior invalid_request is kept.
		if config.RequireSignature {
			log.Warn("RFC8936: SET signature verification failed (signing-only)", "jti", jti, "error", err)
			return pollSetOutcome{setErr: &SetErrType{
				Error:       "jws_signature_failed",
				Description: "The SET signature could not be validated.",
			}}
		}
		log.Warn("RFC8936: SET parsing error", "jti", jti, "error", err)
		return pollSetOutcome{setErr: &SetErrType{
			Error:       "invalid_request",
			Description: "The SET could not be parsed: " + err.Error(),
		}}
	}

	// Validate issuer
	if config.ExpectedIssuer != "" && token.Issuer != config.ExpectedIssuer {
		log.Warn("RFC8936: Invalid issuer", "jti", jti, "expected", config.ExpectedIssuer, "actual", token.Issuer)
		return pollSetOutcome{setErr: &SetErrType{
			Error:       "invalid_issuer",
			Description: "The SET Issuer is invalid for the SET Recipient.",
		}}
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
			return pollSetOutcome{setErr: &SetErrType{
				Error:       "invalid_audience",
				Description: "The SET Audience does not correspond to the SET Recipient.",
			}}
		}
	}

	out := pollSetOutcome{token: token}
	// Event-payload validation (spec #247). Runs only once the SET is fully
	// trusted — signature, iss and aud are all settled above — and only
	// reports: the JTI still lands in ParsedSETs whatever the disposition, so
	// this package never silently drops or nacks an event. The caller reads
	// Validations, applies the stream's event_validation mode, and decides
	// between ack and setErrs.
	if config.Validators != nil {
		out.validation = config.Validators.Validate(token)
	}
	return out
}
