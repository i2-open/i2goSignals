package goSsfUtils

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/i2-open/i2goSignals/pkg/httpSupport"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/i2-open/i2goSignals/pkg/wellKnownSupport"
)

func loadConfig(ctx context.Context, oauthHttpClient *http.Client, server *model.Server) error {
	if server == nil {
		return errors.New("server is nil")
	}
	if server.ServerConfiguration == nil {
		cfg, err := wellKnownSupport.FetchSSFConfiguration(ctx, oauthHttpClient, server.Host)
		if err != nil {
			return err
		}
		server.ServerConfiguration = cfg
	}
	return nil
}

func GetStatusEndpoint(ctx context.Context, oauthHttpClient *http.Client, server *model.Server) (string, error) {
	err := loadConfig(ctx, oauthHttpClient, server)
	if err != nil {
		return "", err
	}
	return server.ServerConfiguration.StatusEndpoint, nil
}

func GetStreamConfigEndpoint(ctx context.Context, oauthHttpClient *http.Client, server *model.Server) (string, error) {
	err := loadConfig(ctx, oauthHttpClient, server)
	if err != nil {
		return "", err
	}
	return server.ServerConfiguration.ConfigurationEndpoint, nil
}

func GetVerificationEndpoint(ctx context.Context, oauthHttpClient *http.Client, server *model.Server) (string, error) {
	err := loadConfig(ctx, oauthHttpClient, server)
	if err != nil {
		return "", err
	}
	return server.ServerConfiguration.VerificationEndpoint, nil
}

func GetStreamStatus(ctx context.Context, oauthHttpClient *http.Client, server *model.Server, streamId string) (*model.StreamStatus, error) {
	statusEndpoint, err := GetStatusEndpoint(ctx, oauthHttpClient, server)
	if err != nil {
		return nil, err
	}
	return GetResourceFromEndpoint[model.StreamStatus](ctx, oauthHttpClient, statusEndpoint, streamId, "status check")
}

func GetStreamConfig(ctx context.Context, oauthHttpClient *http.Client, server *model.Server, streamId string) (*model.StreamConfiguration, error) {
	configEndpoint, err := GetStreamConfigEndpoint(ctx, oauthHttpClient, server)
	if err != nil {
		return nil, err
	}
	return GetResourceFromEndpoint[model.StreamConfiguration](ctx, oauthHttpClient, configEndpoint, streamId, "configuration retrieve")
}

// CreateSstpPair provisions an SSTP pair on the peer named by server: it POSTs
// the SstpPairBootstrap body to the peer's configuration endpoint (POST /stream)
// and decodes the returned bidirectional StreamStateRecord (PairId, SstpInbound,
// SstpMethod). The server discriminates the body shape via
// model.IsSstpBootstrapBody and dispatches to createSstpPairHandler
// (api_stream_management.go:543-544 / :660) — no admin-local pair-create surface
// is required (PRD #49 Seam 4, admin commitments 1–3).
//
// Per-direction status is retrieved by the caller via TWO GetStreamStatus calls
// (txSid == rec.PairId, rxSid == rec.SstpInbound.Id) — the per-pair bearer
// covers both SIDs by construction (IssueSstpPairToken(pairId, inboundSid, …)).
// The community deliberately DOES NOT add a "GetPairStatus" helper: two existing
// pulls satisfy the surface without creating a parallel management path.
//
// Parameters follow the house convention of this file: ctx first,
// oauthHttpClient second (carries the OAuth/pair bearer), server third,
// bootstrap fourth. The returned record is a value pointer to a decoded
// response, safe to consume without further server-side lookups.
func CreateSstpPair(ctx context.Context, oauthHttpClient *http.Client, server *model.Server, bootstrap model.SstpPairBootstrap) (*model.StreamStateRecord, error) {
	if oauthHttpClient == nil {
		return nil, errors.New("CreateSstpPair: oauthHttpClient is nil")
	}
	configEndpoint, err := GetStreamConfigEndpoint(ctx, oauthHttpClient, server)
	if err != nil {
		return nil, fmt.Errorf("CreateSstpPair: resolve configuration endpoint: %w", err)
	}

	body, err := json.Marshal(bootstrap)
	if err != nil {
		return nil, fmt.Errorf("CreateSstpPair: marshal bootstrap: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, configEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("CreateSstpPair: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := oauthHttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("CreateSstpPair: request failed: %w", err)
	}
	defer httpSupport.HandleRespClose(resp)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		// Body may carry a server-side error description; surface it verbatim
		// so the caller sees what the peer said.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("CreateSstpPair: peer returned status %d: %s", resp.StatusCode, string(snippet))
	}

	var record model.StreamStateRecord
	if err := json.NewDecoder(resp.Body).Decode(&record); err != nil {
		return nil, fmt.Errorf("CreateSstpPair: decode response: %w", err)
	}
	return &record, nil
}

func AddStreamIdToUrl(endpoint string, streamId string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return endpoint
	}
	query := u.Query()
	if query.Get("stream_id") == "" {
		query.Set("stream_id", streamId)
		u.RawQuery = query.Encode()
		return u.String()
	}
	return endpoint
}

func GetResourceFromEndpoint[T any](ctx context.Context, oauthHttpClient *http.Client, endpoint string, streamId string, errorMsgPrefix string) (*T, error) {
	fullUrl := AddStreamIdToUrl(endpoint, streamId)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create request: %w", errorMsgPrefix, err)
	}

	resp, err := oauthHttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: request failed: %w", errorMsgPrefix, err)
	}
	defer httpSupport.HandleRespClose(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s failed with status %d", errorMsgPrefix, resp.StatusCode)
	}

	var resource T
	if err := json.NewDecoder(resp.Body).Decode(&resource); err != nil {
		return nil, fmt.Errorf("%s: failed to decode response: %w", errorMsgPrefix, err)
	}

	return &resource, nil
}

func PostVerification(ctx context.Context, oauthHttpClient *http.Client, endpoint string, params model.VerificationParameters) error {
	body, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("failed to marshal verification parameters: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create verification request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := oauthHttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("verification request failed: %w", err)
	}
	defer httpSupport.HandleRespClose(resp)

	if resp.StatusCode == http.StatusUnauthorized {
		return errors.New("unauthorized")
	}

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("verification endpoint returned error: status %d", resp.StatusCode)
	}

	return nil
}
