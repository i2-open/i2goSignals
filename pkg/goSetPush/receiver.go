package goSetPush

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/i2-open/i2goSignals/pkg/goSet"
)

var defaultLogger = slog.Default()

func getLogger(l *slog.Logger) *slog.Logger {
	if l != nil {
		return l
	}
	return defaultLogger
}

// ParseReceivedSET parses and validates an incoming RFC8935 push request without writing any HTTP response.
// It validates Content-Type, reads the body, parses the SET token, and validates issuer/audience claims.
//
// Returns (*ReceivedSET, nil) on success or (nil, *DeliveryErr) on protocol error.
// The caller is responsible for writing the HTTP response using WriteAccepted or WriteDeliveryError.
func ParseReceivedSET(r *http.Request, config ReceiverConfig) (*ReceivedSET, *DeliveryErr) {
	log := getLogger(config.Logger)

	// Validate Content-Type
	contentType := r.Header.Get("Content-Type")
	if contentType != "" && !strings.EqualFold(contentType, "application/secevent+jwt") {
		log.Warn("RFC8935: Invalid content type received", "contentType", contentType)
		return nil, &DeliveryErr{
			ErrCode:     ErrInvalidRequest,
			Description: "Expecting Content-Type application/secevent+jwt",
		}
	}

	// Read body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Warn("RFC8935: Unable to read request body", "error", err)
		return nil, &DeliveryErr{
			ErrCode:     ErrInvalidRequest,
			Description: "Expecting body with Content-Type application/secevent+jwt",
		}
	}

	if len(bodyBytes) == 0 {
		return nil, &DeliveryErr{
			ErrCode:     ErrInvalidRequest,
			Description: "Expecting body with Content-Type application/secevent+jwt",
		}
	}

	tokenString := string(bodyBytes)

	// Peek at the token's claims (UNVERIFIED) to check issuer/audience before
	// signature verification. This ensures we return the correct RFC8935 error
	// code (invalid_issuer, invalid_audience) rather than a generic
	// invalid_request when the JWKS kid lookup fails due to a wrong issuer.
	// Per ADR-0066 §D3 the peek result is never accepted as the trust decision —
	// the accepted token below is the verified one only.
	unverified, err := goSet.Peek(tokenString)
	if err != nil {
		log.Warn("RFC8935: Error parsing SET token", "error", err)
		return nil, &DeliveryErr{
			ErrCode:     ErrInvalidRequest,
			Description: "The request could not be parsed as a SET.",
		}
	}

	// Validate issuer before signature verification
	if config.ExpectedIssuer != "" {
		if unverified.Issuer != config.ExpectedIssuer {
			log.Warn("RFC8935: Invalid issuer", "expected", config.ExpectedIssuer, "actual", unverified.Issuer)
			return nil, &DeliveryErr{
				ErrCode:     ErrInvalidIssuer,
				Description: "Issuer is invalid for this SET Recipient.",
			}
		}
	}

	// Validate audience before signature verification
	if len(config.ExpectedAudiences) > 0 {
		audMatch := false
		for _, aud := range config.ExpectedAudiences {
			if slices.Contains([]string(unverified.Audience), aud) {
				audMatch = true
				break
			}
		}
		if !audMatch {
			log.Warn("RFC8935: Audience mismatch", "expected", config.ExpectedAudiences, "actual", unverified.Audience)
			return nil, &DeliveryErr{
				ErrCode:     ErrInvalidAudience,
				Description: "Audience does not correspond to this SET Recipient.",
			}
		}
	}

	// Verify the signature. Per ADR-0066 §D2 the "None + unverified" state is
	// unrepresentable: every business stream MUST have at least one active
	// authentication layer (L2 channel auth OR L3 SET-signature verification
	// against a configured trust root). Stream-config validation enforces this
	// at configure time (i2goSignals#235); this receiver enforces it defensively
	// at runtime — a nil JWKS is always a hard reject, an unverified parse is
	// never the accepted token.
	//
	// Issuer mismatch was already handled above, so a failure here is a bad
	// signature, not a trust failure. Signature failures are expected peer
	// events, hence WARN, not ERROR (CONTEXT.md log-level policy).
	if config.JWKS == nil {
		if config.RequireSignature {
			log.Warn("RFC8935: SET signature required but no JWKS available to verify (signing-only)")
			return nil, &DeliveryErr{
				ErrCode:     ErrJwsSignatureFailed,
				Description: "The SET signature could not be validated.",
			}
		}
		// Defense in depth for ADR-0066 §D2: reaching this branch means the
		// stream is configured without a trust anchor and without transport
		// auth as the signature gate. Stream-config validation should have
		// prevented this; reject the delivery rather than accept unverified.
		log.Warn("RFC8935: no JWKS configured; refusing to accept unverified SET (ADR-0066)")
		return nil, &DeliveryErr{
			ErrCode:     ErrInvalidRequest,
			Description: "The SET could not be verified: no trust anchor is configured.",
		}
	}

	token, err := goSet.Parse(tokenString, config.JWKS)
	if err != nil {
		if config.RequireSignature {
			log.Warn("RFC8935: SET signature verification failed (signing-only)", "error", err)
			return nil, &DeliveryErr{
				ErrCode:     ErrJwsSignatureFailed,
				Description: "The SET signature could not be validated.",
			}
		}
		log.Warn("RFC8935: Error validating SET token signature", "error", err)
		return nil, &DeliveryErr{
			ErrCode:     ErrInvalidRequest,
			Description: "The request could not be parsed as a SET.",
		}
	}

	// The peek result (`unverified`) was consumed above for iss/aud pre-check
	// only and is intentionally discarded here — the accepted token below is
	// the signature-verified one (ADR-0066 §D3).

	return &ReceivedSET{
		Token:       token,
		TokenString: tokenString,
	}, nil
}

// WriteDeliveryError writes an RFC8935 error response with a 400 Bad Request status and JSON body.
func WriteDeliveryError(w http.ResponseWriter, errCode string, description string) {
	respBody := DeliveryErr{
		ErrCode:     errCode,
		Description: description,
	}
	responseBytes, err := json.MarshalIndent(respBody, "", "  ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write(responseBytes)
}

// WriteAccepted writes an HTTP 202 Accepted response with an empty body per RFC8935.
func WriteAccepted(w http.ResponseWriter) {
	w.WriteHeader(http.StatusAccepted)
}
