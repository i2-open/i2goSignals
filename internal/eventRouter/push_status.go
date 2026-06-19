package eventRouter

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/i2-open/i2goSignals/pkg/httpSupport"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// insecureStatusClient is the lazily-built HTTP client used for push /status
// pre-flight checks against receivers whose stream sets tx_tls_skip_verify. It
// mirrors the push delivery path so the status check and the delivery agree on
// TLS posture (otherwise the pre-flight would fail verification on every cycle).
var (
	insecureStatusClient     *http.Client
	insecureStatusClientOnce sync.Once
)

func getInsecureStatusClient() *http.Client {
	insecureStatusClientOnce.Do(func() {
		insecureStatusClient = &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // per-stream tx_tls_skip_verify opt-in
			},
		}
	})
	return insecureStatusClient
}

// derivePushStatusURL converts a push receiver's events URL (POST <base>/events/<sid>) into
// the corresponding /status URL used by recoveryLoop's StatusFetcher. The receiver authoritatively
// reads the stream identifier from the auth token's StreamId claim, but we still set
// `?stream_id=<sid>` for parity with how poll-side status URLs are formed and so the link is
// self-describing in network captures.
func derivePushStatusURL(endpointURL, sid string) (string, error) {
	if endpointURL == "" {
		return "", fmt.Errorf("empty endpoint URL")
	}
	u, err := url.Parse(endpointURL)
	if err != nil {
		return "", err
	}
	p := strings.TrimSuffix(u.Path, "/")
	segments := strings.Split(p, "/")
	idx := -1
	for i := len(segments) - 1; i >= 0; i-- {
		if segments[i] == "events" {
			idx = i
			break
		}
	}
	if idx == -1 {
		u.Path = strings.TrimRight(p, "/") + "/status"
	} else {
		segments[idx] = "status"
		u.Path = strings.Join(segments[:idx+1], "/")
	}
	q := u.Query()
	if q.Get("stream_id") == "" && sid != "" {
		q.Set("stream_id", sid)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// pushStatusFetcher returns a StatusFetcher closure bound to the router's HTTP client. The
// fetcher reuses the push transmitter's configured Authorization header — receivers in this
// codebase carry the stream identity inside that token (StreamMgmt scope), so the same
// credential that authorizes event delivery also authorizes /status reads.
func (r *router) pushStatusFetcher() StatusFetcher {
	return func(ctx context.Context, stream *model.StreamStateRecord) (*model.StreamStatus, error) {
		// The receiver status-poll is a goSignals/SSTP extension with no basis in
		// standard SSF push (§7.1.3 places the status endpoint on the transmitter).
		// When disabled, make no request: callers treat the error as "couldn't
		// determine state" and fall back to push-response-driven behavior.
		if PushReceiverStatusDisabled() {
			return nil, fmt.Errorf("PUSH-SRV: receiver status-poll disabled (%s)", pushReceiverStatusDisabledEnvVar)
		}
		if stream == nil || stream.StreamConfiguration.Delivery == nil ||
			stream.StreamConfiguration.Delivery.PushTransmitMethod == nil {
			return nil, fmt.Errorf("PUSH-SRV: stream missing push transmit method")
		}
		push := stream.StreamConfiguration.Delivery.PushTransmitMethod
		statusURL, err := derivePushStatusURL(push.EndpointUrl, stream.StreamConfiguration.Id)
		if err != nil {
			return nil, fmt.Errorf("PUSH-SRV: derive status URL: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, statusURL, nil)
		if err != nil {
			return nil, fmt.Errorf("PUSH-SRV: build status request: %w", err)
		}
		if push.AuthorizationHeader != "" {
			req.Header.Set("Authorization", push.AuthorizationHeader)
		}
		req.Header.Set("Accept", "application/json")

		client := r.httpClient
		if stream.StreamConfiguration.TxTLSSkipVerify {
			client = getInsecureStatusClient()
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("PUSH-SRV: status request failed: %w", err)
		}
		defer httpSupport.HandleRespClose(resp)

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("PUSH-SRV: status returned %d", resp.StatusCode)
		}

		var status model.StreamStatus
		if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
			return nil, fmt.Errorf("PUSH-SRV: decode status: %w", err)
		}
		return &status, nil
	}
}
