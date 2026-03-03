package wellKnownSupport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

const (
	SSFConfigurationPath         = "/.well-known/ssf-configuration"
	SSEConfigurationPath         = "/.well-known/sse-configuration"
	OpenIDConfigurationPath      = "/.well-known/openid-configuration"
	OAuthAuthorizationServerPath = "/.well-known/oauth-authorization-server"
	OAuthProtectedResourcePath   = "/.well-known/oauth-protected-resource"
)

// OIDCConfiguration represents common fields from the OpenID Provider Configuration
type OIDCConfiguration struct {
	Issuer                 string   `json:"issuer"`
	AuthorizationEndpoint  string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint          string   `json:"token_endpoint,omitempty"`
	JWKSURI                string   `json:"jwks_uri,omitempty"`
	RegistrationEndpoint   string   `json:"registration_endpoint,omitempty"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported []string `json:"response_types_supported,omitempty"`
	ClaimsSupported        []string `json:"claims_supported,omitempty"`
}

// BuildWellKnownURLs generates candidate URLs for a well-known endpoint.
// It follows RFC 8414 logic for inserting .well-known and also handles simple appending.
func BuildWellKnownURLs(baseURL string, wellKnownPath string) ([]string, error) {
	if baseURL == "" {
		return nil, errors.New("baseURL is empty")
	}
	if wellKnownPath == "" {
		return nil, errors.New("wellKnownPath is empty")
	}

	// Ensure baseURL has a scheme
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	wellKnownPath = "/" + strings.TrimPrefix(wellKnownPath, "/")

	var candidates []string

	// 1. RFC 8414 insertion strategy (for issuers with paths)
	// Example: https://example.com/issuer1 -> https://example.com/.well-known/oauth-authorization-server/issuer1
	if u.Path != "" && u.Path != "/" {
		uRFC := *u
		originalPath := strings.TrimPrefix(uRFC.Path, "/")
		uRFC.Path = wellKnownPath + "/" + originalPath
		candidates = append(candidates, uRFC.String())
	}

	// 2. Simple appending strategy (widely supported)
	// Example: https://example.com/issuer1 -> https://example.com/issuer1/.well-known/oauth-authorization-server
	uApp := *u
	uApp.Path = strings.TrimSuffix(uApp.Path, "/") + wellKnownPath
	candidates = append(candidates, uApp.String())

	return candidates, nil
}

// FetchWellKnown retrieves and decodes a well-known configuration from the given baseURL.
// It uses both insertion and appending strategies to find the endpoint.
func FetchWellKnown[T any](ctx context.Context, client *http.Client, baseURL string, wellKnownPath string) (*T, error) {
	urls, err := BuildWellKnownURLs(baseURL, wellKnownPath)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, targetURL := range urls {
		result, err := Fetch[T](ctx, client, targetURL)
		if err == nil {
			return result, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("could not retrieve well-known configuration from %s: %w", baseURL, lastErr)
}

// Fetch retrieves and decodes a JSON response from the given URL into the target type T.
func Fetch[T any](ctx context.Context, client *http.Client, targetURL string) (*T, error) {
	if client == nil {
		client = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request to %s failed with status %d: %s", targetURL, resp.StatusCode, string(body))
	}

	var result T
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode response from %s: %w", targetURL, err)
	}

	return &result, nil
}

// CheckWellKnown verifies that a well-known configuration exists and is reachable.
// It does not attempt to decode the response body.
func CheckWellKnown(ctx context.Context, client *http.Client, baseURL string, wellKnownPath string) error {
	if client == nil {
		client = http.DefaultClient
	}

	urls, err := BuildWellKnownURLs(baseURL, wellKnownPath)
	if err != nil {
		return err
	}

	var lastErr error
	for _, targetURL := range urls {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			lastErr = err
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("request to %s failed with status %d", targetURL, resp.StatusCode)
			continue
		}

		return nil
	}

	return fmt.Errorf("could not reach well-known configuration at %s: %w", baseURL, lastErr)
}

// CheckSSFConfiguration verifies that an SSF configuration exists and is reachable.
func CheckSSFConfiguration(ctx context.Context, client *http.Client, baseURL string) error {
	err := CheckWellKnown(ctx, client, baseURL, SSFConfigurationPath)
	if err != nil {
		// Try fallback to sse-configuration
		err = CheckWellKnown(ctx, client, baseURL, SSEConfigurationPath)
	}
	return err
}

// FetchSSFConfiguration retrieves the SSF configuration.
func FetchSSFConfiguration(ctx context.Context, client *http.Client, baseURL string) (*model.TransmitterConfiguration, error) {
	// SSF spec uses /ssf-configuration, but some use /sse-configuration
	res, err := FetchWellKnown[model.TransmitterConfiguration](ctx, client, baseURL, SSFConfigurationPath)
	if err != nil {
		// Try fallback to sse-configuration
		res, err = FetchWellKnown[model.TransmitterConfiguration](ctx, client, baseURL, SSEConfigurationPath)
	}
	return res, err
}

// FetchOpenIDConfiguration retrieves the OpenID configuration.
func FetchOpenIDConfiguration(ctx context.Context, client *http.Client, baseURL string) (*OIDCConfiguration, error) {
	return FetchWellKnown[OIDCConfiguration](ctx, client, baseURL, OpenIDConfigurationPath)
}

// FetchProtectedResourceMetadata retrieves the Protected Resource Metadata (RFC 9728).
func FetchProtectedResourceMetadata(ctx context.Context, client *http.Client, baseURL string) (*model.ProtectedResourceMetadata, error) {
	return FetchWellKnown[model.ProtectedResourceMetadata](ctx, client, baseURL, OAuthProtectedResourcePath)
}
