package goSsfUtils

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

func GetStreamStatus(ctx context.Context, oauthHttpClient *http.Client, server *model.Server, streamId string) (*model.StreamStatus, error) {
	statusEndpoint, err := GetStatusEndpoint(ctx, oauthHttpClient, server)
	if err != nil {
		return nil, err
	}
	return getStreamResource[model.StreamStatus](ctx, oauthHttpClient, statusEndpoint, streamId, "status check")
}

func GetStreamConfig(ctx context.Context, oauthHttpClient *http.Client, server *model.Server, streamId string) (*model.StreamConfiguration, error) {
	configEndpoint, err := GetStreamConfigEndpoint(ctx, oauthHttpClient, server)
	if err != nil {
		return nil, err
	}
	return getStreamResource[model.StreamConfiguration](ctx, oauthHttpClient, configEndpoint, streamId, "configuration retrieve")
}

func getStreamResource[T any](ctx context.Context, oauthHttpClient *http.Client, endpoint string, streamId string, errorMsgPrefix string) (*T, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid endpoint URL: %w", errorMsgPrefix, err)
	}
	query := u.Query()
	query.Set("stream_id", streamId)
	u.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
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
