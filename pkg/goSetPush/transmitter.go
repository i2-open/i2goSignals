package goSetPush

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
)

// PushSET sends a SET token string to the receiver endpoint per RFC8935.
// It sets Content-Type to application/secevent+jwt, includes the Authorization header
// if configured, and interprets the response.
func PushSET(ctx context.Context, tokenString string, config TransmitterConfig) PushResult {
	log := getLogger(config.Logger)

	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
		tlsSupport.CheckCaInstalled(client)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.EndpointURL, strings.NewReader(tokenString))
	if err != nil {
		log.Error("RFC8935: Failed to create push request", "error", err)
		return PushResult{Err: err}
	}

	req.Header.Set("Content-Type", "application/secevent+jwt")
	req.Header.Set("Accept", "application/json")

	if config.Authorization != "" {
		authorization := config.Authorization
		if !strings.Contains(strings.ToLower(authorization), "bearer") && !strings.Contains(authorization, " ") {
			authorization = "Bearer " + authorization
		}
		req.Header.Set("Authorization", authorization)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Error("RFC8935: Error sending push request", "url", config.EndpointURL, "error", err)
		return PushResult{Err: err}
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	retryAfter := ParseRetryAfter(resp.Header.Get("Retry-After"), time.Now())

	if resp.StatusCode == http.StatusAccepted {
		return PushResult{
			StatusCode: resp.StatusCode,
			Accepted:   true,
			RetryAfter: retryAfter,
		}
	}

	// Handle 400 Bad Request with RFC8935 error body
	if resp.StatusCode == http.StatusBadRequest {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return PushResult{
				StatusCode: resp.StatusCode,
				Err:        fmt.Errorf("RFC8935: unable to read error response: %w", err),
				RetryAfter: retryAfter,
			}
		}

		var deliveryErr DeliveryErr
		if err := json.Unmarshal(body, &deliveryErr); err != nil {
			return PushResult{
				StatusCode: resp.StatusCode,
				Err:        fmt.Errorf("RFC8935: unable to parse error response: %w", err),
				RetryAfter: retryAfter,
			}
		}

		log.Warn("RFC8935: Push delivery error", "code", deliveryErr.ErrCode, "desc", deliveryErr.Description)
		return PushResult{
			StatusCode: resp.StatusCode,
			Err:        &deliveryErr,
			RetryAfter: retryAfter,
		}
	}

	// Handle other error status codes
	return PushResult{
		StatusCode: resp.StatusCode,
		Err:        fmt.Errorf("RFC8935: HTTP %s from %s", resp.Status, config.EndpointURL),
		RetryAfter: retryAfter,
	}
}
