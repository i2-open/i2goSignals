package test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type SSFConformanceSuite struct {
	suite.Suite
	instance *ssfInstance
}

func (suite *SSFConformanceSuite) SetupSuite() {
	instance, err := createServer(suite.T(), "ssf_conformance_test", true)
	assert.NoError(suite.T(), err)
	suite.instance = instance
}

func (suite *SSFConformanceSuite) TearDownSuite() {
	if suite.instance != nil {
		suite.instance.app.Shutdown()
		suite.instance.ts.Close()
	}
}

func TestSSFConformanceSuite(t *testing.T) {
	suite.Run(t, new(SSFConformanceSuite))
}

// TestWellKnownContentType tests that well-known endpoint returns application/json per SSF spec
func (suite *SSFConformanceSuite) TestWellKnownContentType() {
	t := suite.T()

	resp, err := http.Get(suite.instance.ts.URL + "/.well-known/ssf-configuration")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	contentType := resp.Header.Get("Content-Type")
	assert.Contains(t, contentType, "application/json", "Content-Type must be application/json per SSF spec")
}

// TestWellKnownIssuerMatch tests that issuer in response matches the URL used per SSF spec
func (suite *SSFConformanceSuite) TestWellKnownIssuerMatch() {
	t := suite.T()

	resp, err := http.Get(suite.instance.ts.URL + "/.well-known/ssf-configuration")
	assert.NoError(t, err)

	body, _ := io.ReadAll(resp.Body)
	var config model.TransmitterConfiguration
	_ = json.Unmarshal(body, &config)

	// The issuer should match what the server advertises
	assert.NotEmpty(t, config.Issuer, "Issuer must be present")
	// In the default case, issuer is "DEFAULT"
	assert.Equal(t, "DEFAULT", config.Issuer)
}

// TestWellKnownRequiredFields tests that all required fields are present per SSF spec
func (suite *SSFConformanceSuite) TestWellKnownRequiredFields() {
	t := suite.T()

	resp, err := http.Get(suite.instance.ts.URL + "/.well-known/ssf-configuration")
	assert.NoError(t, err)

	body, _ := io.ReadAll(resp.Body)
	var config model.TransmitterConfiguration
	_ = json.Unmarshal(body, &config)

	// Required fields per SSF spec
	assert.NotEmpty(t, config.Issuer, "issuer is REQUIRED")

	// Recommended fields
	assert.NotEmpty(t, config.JwksUri, "jwks_uri is RECOMMENDED")
	assert.NotEmpty(t, config.DeliveryMethodsSupported, "delivery_methods_supported is RECOMMENDED")
}

// TestDeliveryMethodsSupported tests that delivery_methods_supported contains valid URIs per SSF spec
func (suite *SSFConformanceSuite) TestDeliveryMethodsSupported() {
	t := suite.T()

	resp, err := http.Get(suite.instance.ts.URL + "/.well-known/ssf-configuration")
	assert.NoError(t, err)

	body, _ := io.ReadAll(resp.Body)
	var config model.TransmitterConfiguration
	_ = json.Unmarshal(body, &config)

	assert.NotEmpty(t, config.DeliveryMethodsSupported, "delivery_methods_supported should be present")

	// Check for expected delivery methods
	deliveryMethods := config.DeliveryMethodsSupported
	assert.Contains(t, deliveryMethods, model.DeliveryPoll, "Should support poll delivery")
	assert.Contains(t, deliveryMethods, model.DeliveryPush, "Should support push delivery")
	assert.Contains(t, deliveryMethods, model.DeliverySstp, "Should advertise SSTP delivery unconditionally")

	// All delivery methods should be valid URIs (at minimum, contain "urn:")
	for _, method := range deliveryMethods {
		assert.True(t, strings.Contains(method, "urn:") || strings.Contains(method, "http"),
			"Delivery method should be a URI: "+method)
	}
}

// TestOptionalEndpoints tests that optional endpoints are properly formatted if present per SSF spec
func (suite *SSFConformanceSuite) TestOptionalEndpoints() {
	t := suite.T()

	resp, err := http.Get(suite.instance.ts.URL + "/.well-known/ssf-configuration")
	assert.NoError(t, err)

	body, _ := io.ReadAll(resp.Body)
	var config model.TransmitterConfiguration
	_ = json.Unmarshal(body, &config)

	// If present, these should be valid URLs
	if config.ConfigurationEndpoint != "" {
		assert.True(t, strings.HasPrefix(config.ConfigurationEndpoint, "http"),
			"configuration_endpoint should be a valid URL")
	}

	if config.StatusEndpoint != "" {
		assert.True(t, strings.HasPrefix(config.StatusEndpoint, "http"),
			"status_endpoint should be a valid URL")
	}

	if config.AddSubjectEndpoint != "" {
		assert.True(t, strings.HasPrefix(config.AddSubjectEndpoint, "http"),
			"add_subject_endpoint should be a valid URL")
	}

	if config.RemoveSubjectEndpoint != "" {
		assert.True(t, strings.HasPrefix(config.RemoveSubjectEndpoint, "http"),
			"remove_subject_endpoint should be a valid URL")
	}

	if config.VerificationEndpoint != "" {
		assert.True(t, strings.HasPrefix(config.VerificationEndpoint, "http"),
			"verification_endpoint should be a valid URL")
	}
}

// TestMultipleIssuerPaths tests path-based issuer discovery per SSF spec
func (suite *SSFConformanceSuite) TestMultipleIssuerPaths() {
	t := suite.T()

	// Create a new issuer
	issuerName := "conformance.example.com"
	req, _ := http.NewRequest(http.MethodPost, suite.instance.ts.URL+"/key/"+issuerName, nil)
	req.Header.Set("Authorization", "Bearer "+suite.instance.streamMgmtToken)

	resp, err := suite.instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	// Test well-known endpoint with issuer path
	resp, err = http.Get(suite.instance.ts.URL + "/.well-known/ssf-configuration/" + issuerName)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var config model.TransmitterConfiguration
	_ = json.Unmarshal(body, &config)

	// The issuer in the response should match the path
	assert.Equal(t, issuerName, config.Issuer, "Issuer should match the path-based issuer")

	// JWKS URI should point to the issuer-specific endpoint
	assert.Contains(t, config.JwksUri, issuerName, "JwksUri should reference the specific issuer")
}

// TestJWKSEndpointFormat tests that JWKS endpoint returns proper format per RFC7517
func (suite *SSFConformanceSuite) TestJWKSEndpointFormat() {
	t := suite.T()

	resp, err := http.Get(suite.instance.ts.URL + "/jwks.json")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	contentType := resp.Header.Get("Content-Type")
	assert.Contains(t, contentType, "application/json", "JWKS Content-Type must be application/json")

	body, _ := io.ReadAll(resp.Body)
	var jwks map[string]interface{}
	err = json.Unmarshal(body, &jwks)
	assert.NoError(t, err, "JWKS must be valid JSON")

	// JWKS must have a "keys" array
	keys, ok := jwks["keys"]
	assert.True(t, ok, "JWKS must have a 'keys' field")
	assert.NotNil(t, keys, "keys field must not be null")

	keysArray, ok := keys.([]interface{})
	assert.True(t, ok, "keys must be an array")
	assert.NotEmpty(t, keysArray, "keys array must not be empty")

	// Each key should have required fields
	for _, keyInterface := range keysArray {
		key, ok := keyInterface.(map[string]interface{})
		assert.True(t, ok, "Each key must be an object")

		// Required JWK fields per RFC7517
		assert.Contains(t, key, "kty", "JWK must have kty (key type)")
		assert.Contains(t, key, "use", "JWK should have use field")
		assert.Contains(t, key, "kid", "JWK should have kid (key ID)")
	}
}

// TestSupportedScopes tests that supported_scopes is properly formatted if present
func (suite *SSFConformanceSuite) TestSupportedScopes() {
	t := suite.T()

	resp, err := http.Get(suite.instance.ts.URL + "/.well-known/ssf-configuration")
	assert.NoError(t, err)

	body, _ := io.ReadAll(resp.Body)
	var config model.TransmitterConfiguration
	_ = json.Unmarshal(body, &config)

	if len(config.ScopesSupported) > 0 {
		// Roles should be non-empty strings
		for _, scope := range config.ScopesSupported {
			assert.NotEmpty(t, scope, "Each scope should be a non-empty string")
		}
	}

	if len(config.SupportedScopes) > 0 {
		// SupportedScopes maps endpoints to required scopes
		for endpoint, scopes := range config.SupportedScopes {
			assert.NotEmpty(t, endpoint, "Endpoint name should not be empty")
			assert.NotEmpty(t, scopes, "Roles array should not be empty for endpoint "+endpoint)
		}
	}
}

// TestAuthorizationSchemes tests that authorization_schemes is properly formatted if present
func (suite *SSFConformanceSuite) TestAuthorizationSchemes() {
	t := suite.T()

	resp, err := http.Get(suite.instance.ts.URL + "/.well-known/ssf-configuration")
	assert.NoError(t, err)

	body, _ := io.ReadAll(resp.Body)
	var config model.TransmitterConfiguration
	_ = json.Unmarshal(body, &config)

	if len(config.AuthorizationSchemes) > 0 {
		for _, scheme := range config.AuthorizationSchemes {
			assert.NotEmpty(t, scheme.SpecUrn, "Authorization scheme must have spec_urn")
			// spec_urn should be a URN
			assert.True(t, strings.HasPrefix(scheme.SpecUrn, "urn:") || strings.HasPrefix(scheme.SpecUrn, "http"),
				"spec_urn should be a URI/URN: "+scheme.SpecUrn)
		}
	}
}

// TestProtectedResourceMetadata tests RFC9728 Protected Resource Metadata endpoint
func (suite *SSFConformanceSuite) TestProtectedResourceMetadata() {
	t := suite.T()

	resp, err := http.Get(suite.instance.ts.URL + "/.well-known/oauth-protected-resource")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	contentType := resp.Header.Get("Content-Type")
	assert.Contains(t, contentType, "application/json")

	body, _ := io.ReadAll(resp.Body)
	var prMeta model.ProtectedResourceMetadata
	err = json.Unmarshal(body, &prMeta)
	assert.NoError(t, err, "Protected Resource Metadata must be valid JSON")

	// Check required/recommended fields
	if prMeta.Resource != nil {
		assert.NotEmpty(t, *prMeta.Resource, "resource field should not be empty if present")
	}

	if len(prMeta.ScopesSupported) > 0 {
		for _, scope := range prMeta.ScopesSupported {
			assert.NotEmpty(t, scope, "Each scope should be non-empty")
		}
	}

	if len(prMeta.BearerMethodsSupported) > 0 {
		// Common bearer methods are "header", "body", "query"
		for _, method := range prMeta.BearerMethodsSupported {
			assert.Contains(t, []string{"header", "body", "query"}, method,
				"Bearer method should be one of the standard methods")
		}
	}
}

// TestCriticalSubjectMembers tests critical_subject_members field if present
func (suite *SSFConformanceSuite) TestCriticalSubjectMembers() {
	t := suite.T()

	resp, err := http.Get(suite.instance.ts.URL + "/.well-known/ssf-configuration")
	assert.NoError(t, err)

	body, _ := io.ReadAll(resp.Body)
	var config model.TransmitterConfiguration
	_ = json.Unmarshal(body, &config)

	// This is optional, but if present should be an array of strings
	if len(config.CriticalSubjectMembers) > 0 {
		for _, member := range config.CriticalSubjectMembers {
			assert.NotEmpty(t, member, "Critical subject member should be non-empty string")
		}
	}
}

// TestWellKnownIssuerValidation tests that issuer validation works correctly
func (suite *SSFConformanceSuite) TestWellKnownIssuerValidation() {
	t := suite.T()

	// Get the default configuration
	resp, err := http.Get(suite.instance.ts.URL + "/.well-known/ssf-configuration")
	assert.NoError(t, err)

	body, _ := io.ReadAll(resp.Body)
	var config model.TransmitterConfiguration
	_ = json.Unmarshal(body, &config)

	// The issuer should be consistent across requests
	defaultIssuer := config.Issuer

	// Request again and verify same issuer
	resp2, err := http.Get(suite.instance.ts.URL + "/.well-known/ssf-configuration")
	assert.NoError(t, err)

	body2, _ := io.ReadAll(resp2.Body)
	var config2 model.TransmitterConfiguration
	_ = json.Unmarshal(body2, &config2)

	assert.Equal(t, defaultIssuer, config2.Issuer, "Issuer should be consistent across requests")
}

// TestVersionInformation tests that version information is present in configuration
func (suite *SSFConformanceSuite) TestVersionInformation() {
	t := suite.T()

	resp, err := http.Get(suite.instance.ts.URL + "/.well-known/ssf-configuration")
	assert.NoError(t, err)

	body, _ := io.ReadAll(resp.Body)
	var config model.TransmitterConfiguration
	_ = json.Unmarshal(body, &config)

	// Check for version fields (these are custom goSignals fields)
	assert.NotEmpty(t, config.GoSignalsVersion, "Implementation should advertise its version")
	assert.NotEmpty(t, config.SpecVersion, "Implementation should advertise SSF spec version")
}

// TestStreamEndpointsRequireAuth tests that stream management endpoints require authorization
func (suite *SSFConformanceSuite) TestStreamEndpointsRequireAuth() {
	t := suite.T()

	endpoints := []string{
		"/stream",
		"/status",
	}

	for _, endpoint := range endpoints {
		// GET without auth should fail
		req, _ := http.NewRequest(http.MethodGet, suite.instance.ts.URL+endpoint, nil)
		resp, err := suite.instance.client.Do(req)
		assert.NoError(t, err)
		assert.NotEqual(t, http.StatusOK, resp.StatusCode,
			"Endpoint "+endpoint+" should require authorization")
		assert.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusBadRequest},
			resp.StatusCode, "Should return 401, 403, or 400 for "+endpoint)
	}
}
