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

// IsWellKnownPath returns true if the given path is a standard well-known discovery path.
func IsWellKnownPath(path string) bool {
	p := "/" + strings.TrimPrefix(path, "/")
	return p == SSFConfigurationPath ||
		p == SSEConfigurationPath ||
		p == OpenIDConfigurationPath ||
		p == OAuthAuthorizationServerPath ||
		p == OAuthProtectedResourcePath ||
		strings.HasPrefix(p, "/.well-known/")
}

// allWellKnownPaths is the list of well-known paths supported by this package.
var allWellKnownPaths = []string{
	SSFConfigurationPath,
	SSEConfigurationPath,
	OpenIDConfigurationPath,
	OAuthAuthorizationServerPath,
	OAuthProtectedResourcePath,
}

func stripWellKnown(path string) string {
	if idx := strings.Index(path, "/.well-known/"); idx != -1 {
		pathAfter := path[idx:]
		for _, known := range allWellKnownPaths {
			if strings.HasPrefix(pathAfter, known) {
				// Recover original path by stripping the well-known part.
				// For appended URLs: /issuer/.well-known/type -> /issuer
				// For RFC 8414 URLs: /.well-known/type/issuer -> /issuer
				rest := strings.TrimPrefix(pathAfter, known)
				if rest == "" || rest == "/" {
					return path[:idx]
				} else if strings.HasPrefix(rest, "/") {
					return path[:idx] + rest
				}
			}
		}
		// If it's an unknown well-known path, just strip it for safety.
		return path[:idx]
	}
	return path
}

// OIDCConfiguration represents common fields from the OpenID Provider Configuration
type OIDCConfiguration struct {
	Issuer                 string   `json:"issuer"`
	AuthorizationEndpoint  string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint          string   `json:"token_endpoint,omitempty"`
	RevocationEndpoint     string   `json:"revocation_endpoint,omitempty"`
	DeviceAuthEndpoint     string   `json:"device_authorization_endpoint,omitempty"`
	JWKSURI                string   `json:"jwks_uri,omitempty"`
	RegistrationEndpoint   string   `json:"registration_endpoint,omitempty"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported []string `json:"response_types_supported,omitempty"`
	ClaimsSupported        []string `json:"claims_supported,omitempty"`
}

// InsertWellKnownURL builds the single, spec-correct discovery URL by inserting
// the well-known component between the host and the issuer path, per RFC 8615
// and SSF §7.2 (Figure 17). Unlike BuildWellKnownURLs, this returns exactly one
// deterministic URL and never appends — callers that must match the OpenID SSF
// transmitter routing (e.g. the admin CLI's `add server`) require insertion.
//
//	https://tr.example.com/issuer1 -> https://tr.example.com/.well-known/ssf-configuration/issuer1
//	https://tr.example.com         -> https://tr.example.com/.well-known/ssf-configuration
func InsertWellKnownURL(baseURL string, wellKnownPath string) (string, error) {
	if baseURL == "" {
		return "", errors.New("baseURL is empty")
	}
	if wellKnownPath == "" {
		return "", errors.New("wellKnownPath is empty")
	}

	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	wellKnownPath = "/" + strings.TrimPrefix(wellKnownPath, "/")

	issuerPath := strings.Trim(u.Path, "/")
	if issuerPath == "" {
		u.Path = wellKnownPath
	} else {
		u.Path = wellKnownPath + "/" + issuerPath
	}
	return u.String(), nil
}

// normalizeIssuerURL canonicalizes an issuer/location URL for the SSF §7.2.4
// binding comparison: scheme and host are lowercased (RFC 3986 case-insensitive
// components) and a single trailing slash is trimmed. The path is left
// case-sensitive. An empty/blank input normalizes to "".
func normalizeIssuerURL(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil {
		return strings.ToLower(strings.TrimRight(s, "/"))
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String()
}

// IssuerMatchesLocation reports whether a transmitter's advertised metadata
// issuer is consistent with the location its discovery document was retrieved
// from — the bare SSF §7.2.4 fact, with NO enforcement policy attached.
// Comparison is scheme/host case-insensitive and ignores a single trailing
// slash (the path stays case-sensitive per RFC 3986). An empty metadataIssuer
// never matches (the transmitter advertised no issuer, which is itself a
// §7.2.4 violation).
//
// This is the policy-free primitive: callers that must only *surface* a
// mismatch (e.g. a pre-registration discovery probe where no StrictSsf posture
// is committed yet) use this directly and decide their own warn/render
// behavior, rather than calling EvaluateIssuerBinding with a meaningless
// strict=false purely to dodge its error branch. jwks_uri is intentionally not
// a parameter: it is free-form and must never be coupled to iss/issuer.
func IssuerMatchesLocation(metadataIssuer, discoveryLocation string) bool {
	mi := normalizeIssuerURL(metadataIssuer)
	if mi == "" {
		return false
	}
	return mi == normalizeIssuerURL(discoveryLocation)
}

// IssuerBindingDetail returns a human-readable description of an SSF §7.2.4
// issuer↔discovery-location mismatch, WITHOUT deciding warn-vs-fail. It returns
// "" exactly when IssuerMatchesLocation reports true (a consistent binding has
// nothing to describe). Like IssuerMatchesLocation this is policy-free: a
// visibility-only consumer renders this string in its own dialog copy, while
// the enforcement callers go through EvaluateIssuerBinding.
func IssuerBindingDetail(metadataIssuer, discoveryLocation string) string {
	if IssuerMatchesLocation(metadataIssuer, discoveryLocation) {
		return ""
	}
	advertised := metadataIssuer
	if strings.TrimSpace(advertised) == "" {
		advertised = "(none advertised)"
	}
	return fmt.Sprintf(
		"SSF §7.2.4 issuer binding mismatch: transmitter discovery document advertises issuer %q but was retrieved from %q; these MUST match to prevent transmitter impersonation (jwks_uri is free-form and is not part of this check)",
		advertised, discoveryLocation)
}

// EvaluateIssuerBinding checks the SSF §7.2.4 issuer↔discovery-location binding:
// the `issuer` advertised inside a transmitter's discovery document MUST equal
// the location that document was retrieved from (the host + issuer path the
// .well-known/ssf-configuration URL was built from), to prevent transmitter
// impersonation. It is the symmetric counterpart of the OpenID conformance
// suite's OIDSSFCheckTransmitterMetadataIssuer.
//
// jwks_uri is intentionally NOT a parameter: it is free-form (any HTTPS URL
// serving the issuer's keys) and must never be required to equal iss/issuer.
// Keeping it out of this signature structurally prevents anyone from coupling
// the two.
//
// Comparison is scheme/host case-insensitive and ignores a single trailing
// slash (the path stays case-sensitive per RFC 3986). On a consistent binding
// it returns ("", nil). On a mismatch the behavior is keyed off the peer's
// operator-declared strict posture (model.Server.StrictSsf / the CLI's
// --strict-ssf — NOT the goSsfServer-only I2SIG_STRICT_SSF env flag):
//
//   - strict == true  -> ("", error): abort. The peer claims to be a strict,
//     properly-administered SSF transmitter, so a mismatch is an impersonation
//     or misconfiguration signal that must not be recorded.
//   - strict == false -> (warning, nil): the caller logs the warning and
//     continues (the flexible default; the binding is advisory).
func EvaluateIssuerBinding(metadataIssuer, discoveryLocation string, strict bool) (string, error) {
	detail := IssuerBindingDetail(metadataIssuer, discoveryLocation)
	if detail == "" {
		return "", nil
	}
	if strict {
		return "", errors.New(detail)
	}
	return detail, nil
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

	// If baseURL already contains the target wellKnownPath, it might be exactly the endpoint we need.
	if idx := strings.Index(u.Path, wellKnownPath); idx != -1 {
		// Check if it's exactly the endpoint or inserted pattern (RFC 8414)
		pathAfter := u.Path[idx:]
		if pathAfter == wellKnownPath || pathAfter == wellKnownPath+"/" || strings.HasPrefix(pathAfter, wellKnownPath+"/") {
			u.Path = strings.TrimSuffix(u.Path, "/")
			return []string{u.String()}, nil
		}
	}

	// Otherwise, strip any existing well-known component to find the base/issuer URL.
	u.Path = stripWellKnown(u.Path)
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

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("request to %s failed with status %d: %s", targetURL, resp.StatusCode, string(body))
			continue
		}
		_ = resp.Body.Close()

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
