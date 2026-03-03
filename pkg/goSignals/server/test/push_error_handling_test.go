package test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type PushErrorSuite struct {
	suite.Suite
	instance *ssfInstance
	stream   model.StreamConfiguration
	jwks     interface{}
}

func (suite *PushErrorSuite) SetupSuite() {
	instance, err := createServer(suite.T(), "push_error_test", true)
	assert.NoError(suite.T(), err)
	suite.instance = instance

	// Create a push receiver stream
	streamConfig := model.StreamConfiguration{
		Iss:             "DEFAULT",
		Aud:             []string{"https://receiver.example.com"},
		EventsSupported: []string{"*"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PushReceiveMethod: &model.PushReceiveMethod{
				Method: model.ReceivePush,
			},
		},
		RouteMode: model.RouteModeImport,
	}

	body, _ := json.Marshal(streamConfig)
	req, _ := http.NewRequest(http.MethodPost, instance.ts.URL+"/stream", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+instance.streamMgmtToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := instance.client.Do(req)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var createdStream model.StreamConfiguration
	_ = json.NewDecoder(resp.Body).Decode(&createdStream)
	suite.stream = createdStream
	suite.jwks = instance.provider.GetPublicTransmitterJWKS("DEFAULT")
}

func (suite *PushErrorSuite) TearDownSuite() {
	if suite.instance != nil {
		suite.instance.app.Shutdown()
		suite.instance.ts.Close()
	}
}

func TestPushErrorSuite(t *testing.T) {
	suite.Run(t, new(PushErrorSuite))
}

// TestInvalidRequest tests the invalid_request error code per RFC8935
func (suite *PushErrorSuite) TestInvalidRequest() {
	t := suite.T()

	// Test 1: Malformed JWT
	req, _ := http.NewRequest(http.MethodPost, suite.stream.Delivery.PushReceiveMethod.EndpointUrl, strings.NewReader("not-a-jwt"))
	req.Header.Set("Authorization", suite.stream.Delivery.PushReceiveMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/secevent+jwt")

	resp, err := suite.instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errResp model.SetDeliveryErr
	body, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &errResp)
	assert.Equal(t, "invalid_request", errResp.ErrCode)
	assert.NotEmpty(t, errResp.Description)

	// Test 2: Empty body
	req, _ = http.NewRequest(http.MethodPost, suite.stream.Delivery.PushReceiveMethod.EndpointUrl, strings.NewReader(""))
	req.Header.Set("Authorization", suite.stream.Delivery.PushReceiveMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/secevent+jwt")

	resp, err = suite.instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	body, _ = io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &errResp)
	assert.Equal(t, "invalid_request", errResp.ErrCode)
}

// TestInvalidIssuer tests the invalid_issuer error code per RFC8935
func (suite *PushErrorSuite) TestInvalidIssuer() {
	t := suite.T()

	subject := &goSet.EventSubject{
		SubjectIdentifier: goSet.SubjectIdentifier{
			Format:                    "scim",
			UniformResourceIdentifier: goSet.UniformResourceIdentifier{Uri: "/Users/test"},
		},
	}

	// Create SET with wrong issuer
	set := goSet.CreateSet(subject, "WRONG-ISSUER", suite.stream.Aud)
	set.AddEventPayload("https://schemas.openid.net/secevent/risc/event-type/account-disabled", map[string]interface{}{
		"reason": "test",
	})

	// Get private key and sign
	privKey, _ := suite.instance.provider.GetIssuerPrivateKey("DEFAULT")
	tokenString, err := set.JWS(jwt.SigningMethodRS256, privKey)
	assert.NoError(t, err)

	// Send to push endpoint
	req, _ := http.NewRequest(http.MethodPost, suite.stream.Delivery.PushReceiveMethod.EndpointUrl, strings.NewReader(tokenString))
	req.Header.Set("Authorization", suite.stream.Delivery.PushReceiveMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/secevent+jwt")

	resp, err := suite.instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errResp model.SetDeliveryErr
	body, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &errResp)
	assert.Equal(t, "invalid_issuer", errResp.ErrCode)
	assert.Contains(t, errResp.Description, "Issuer")
}

// TestInvalidAudience tests the invalid_audience error code per RFC8935
func (suite *PushErrorSuite) TestInvalidAudience() {
	t := suite.T()

	subject := &goSet.EventSubject{
		SubjectIdentifier: goSet.SubjectIdentifier{
			Format:                    "scim",
			UniformResourceIdentifier: goSet.UniformResourceIdentifier{Uri: "/Users/test"},
		},
	}

	// Create SET with wrong audience
	set := goSet.CreateSet(subject, suite.stream.Iss, []string{"https://wrong-audience.example.com"})
	set.AddEventPayload("https://schemas.openid.net/secevent/risc/event-type/account-disabled", map[string]interface{}{
		"reason": "test",
	})

	// Get private key and sign
	privKey, _ := suite.instance.provider.GetIssuerPrivateKey("DEFAULT")
	tokenString, err := set.JWS(jwt.SigningMethodRS256, privKey)
	assert.NoError(t, err)

	// Send to push endpoint
	req, _ := http.NewRequest(http.MethodPost, suite.stream.Delivery.PushReceiveMethod.EndpointUrl, strings.NewReader(tokenString))
	req.Header.Set("Authorization", suite.stream.Delivery.PushReceiveMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/secevent+jwt")

	resp, err := suite.instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errResp model.SetDeliveryErr
	body, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &errResp)
	assert.Contains(t, errResp.ErrCode, "invalid")
	assert.Contains(t, errResp.Description, "Audience")
}

// TestAuthenticationFailed tests the authentication_failed error code per RFC8935
func (suite *PushErrorSuite) TestAuthenticationFailed() {
	t := suite.T()

	subject := &goSet.EventSubject{
		SubjectIdentifier: goSet.SubjectIdentifier{
			Format:                    "scim",
			UniformResourceIdentifier: goSet.UniformResourceIdentifier{Uri: "/Users/test"},
		},
	}

	set := goSet.CreateSet(subject, suite.stream.Iss, suite.stream.Aud)
	set.AddEventPayload("https://schemas.openid.net/secevent/risc/event-type/account-disabled", map[string]interface{}{
		"reason": "test",
	})

	privKey, _ := suite.instance.provider.GetIssuerPrivateKey("DEFAULT")
	tokenString, err := set.JWS(jwt.SigningMethodRS256, privKey)
	assert.NoError(t, err)

	// Test 1: No authorization header
	req, _ := http.NewRequest(http.MethodPost, suite.stream.Delivery.PushReceiveMethod.EndpointUrl, strings.NewReader(tokenString))
	req.Header.Set("Content-Type", "application/secevent+jwt")

	resp, err := suite.instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errResp model.SetDeliveryErr
	body, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &errResp)
	assert.Equal(t, "authentication_failed", errResp.ErrCode)

	// Test 2: Invalid authorization token
	req, _ = http.NewRequest(http.MethodPost, suite.stream.Delivery.PushReceiveMethod.EndpointUrl, strings.NewReader(tokenString))
	req.Header.Set("Authorization", "Bearer invalid-token")
	req.Header.Set("Content-Type", "application/secevent+jwt")

	resp, err = suite.instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	body, _ = io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &errResp)
	assert.Equal(t, "authentication_failed", errResp.ErrCode)
}

// TestAccessDenied tests the access_denied error code per RFC8935
func (suite *PushErrorSuite) TestAccessDenied() {
	t := suite.T()

	subject := &goSet.EventSubject{
		SubjectIdentifier: goSet.SubjectIdentifier{
			Format:                    "scim",
			UniformResourceIdentifier: goSet.UniformResourceIdentifier{Uri: "/Users/test"},
		},
	}

	set := goSet.CreateSet(subject, suite.stream.Iss, suite.stream.Aud)
	set.AddEventPayload("https://schemas.openid.net/secevent/risc/event-type/account-disabled", map[string]interface{}{
		"reason": "test",
	})

	privKey, _ := suite.instance.provider.GetIssuerPrivateKey("DEFAULT")
	tokenString, err := set.JWS(jwt.SigningMethodRS256, privKey)
	assert.NoError(t, err)

	// Use a token from a different stream (should be denied)
	// Create another stream
	streamConfig2 := model.StreamConfiguration{
		Iss:             "DEFAULT",
		Aud:             []string{"https://other-receiver.example.com"},
		EventsSupported: []string{"*"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PushReceiveMethod: &model.PushReceiveMethod{
				Method: model.ReceivePush,
			},
		},
		RouteMode: model.RouteModeImport,
	}

	stream2, _ := suite.instance.provider.CreateStream(streamConfig2, suite.instance.projectId)

	// Try to use stream2's auth token to access stream1's endpoint
	req, _ := http.NewRequest(http.MethodPost, suite.stream.Delivery.PushReceiveMethod.EndpointUrl, strings.NewReader(tokenString))
	req.Header.Set("Authorization", stream2.Delivery.PushReceiveMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/secevent+jwt")

	resp, err := suite.instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errResp model.SetDeliveryErr
	body, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &errResp)
	assert.Equal(t, "access_denied", errResp.ErrCode)
}

// TestInvalidContentType tests rejection of wrong Content-Type per RFC8935
func (suite *PushErrorSuite) TestInvalidContentType() {
	t := suite.T()

	subject := &goSet.EventSubject{
		SubjectIdentifier: goSet.SubjectIdentifier{
			Format:                    "scim",
			UniformResourceIdentifier: goSet.UniformResourceIdentifier{Uri: "/Users/test"},
		},
	}

	set := goSet.CreateSet(subject, suite.stream.Iss, suite.stream.Aud)
	set.AddEventPayload("https://schemas.openid.net/secevent/risc/event-type/account-disabled", map[string]interface{}{
		"reason": "test",
	})

	privKey, _ := suite.instance.provider.GetIssuerPrivateKey("DEFAULT")
	tokenString, err := set.JWS(jwt.SigningMethodRS256, privKey)
	assert.NoError(t, err)

	// Test with wrong Content-Type
	req, _ := http.NewRequest(http.MethodPost, suite.stream.Delivery.PushReceiveMethod.EndpointUrl, strings.NewReader(tokenString))
	req.Header.Set("Authorization", suite.stream.Delivery.PushReceiveMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/json") // Wrong!

	resp, err := suite.instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errResp model.SetDeliveryErr
	body, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &errResp)
	assert.Equal(t, "invalid_request", errResp.ErrCode)
	assert.Contains(t, errResp.Description, "Content-Type")
}

// TestDuplicateSET tests idempotency of duplicate SET delivery per RFC8935
func (suite *PushErrorSuite) TestDuplicateSET() {
	t := suite.T()

	subject := &goSet.EventSubject{
		SubjectIdentifier: goSet.SubjectIdentifier{
			Format:                    "scim",
			UniformResourceIdentifier: goSet.UniformResourceIdentifier{Uri: "/Users/duplicate-test"},
		},
	}

	set := goSet.CreateSet(subject, suite.stream.Iss, suite.stream.Aud)
	set.AddEventPayload("https://schemas.openid.net/secevent/risc/event-type/account-disabled", map[string]interface{}{
		"reason": "duplicate test",
	})

	privKey, _ := suite.instance.provider.GetIssuerPrivateKey("DEFAULT")
	tokenString, err := set.JWS(jwt.SigningMethodRS256, privKey)
	assert.NoError(t, err)

	// Send first time
	req, _ := http.NewRequest(http.MethodPost, suite.stream.Delivery.PushReceiveMethod.EndpointUrl, strings.NewReader(tokenString))
	req.Header.Set("Authorization", suite.stream.Delivery.PushReceiveMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/secevent+jwt")

	resp, err := suite.instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusAccepted, resp.StatusCode, "First delivery should return 202 Accepted")

	// Send second time (duplicate)
	req, _ = http.NewRequest(http.MethodPost, suite.stream.Delivery.PushReceiveMethod.EndpointUrl, strings.NewReader(tokenString))
	req.Header.Set("Authorization", suite.stream.Delivery.PushReceiveMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/secevent+jwt")

	resp, err = suite.instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusAccepted, resp.StatusCode, "Duplicate delivery should also return 202 Accepted (idempotent)")

	// Verify only one event stored
	event := suite.instance.provider.GetEventRecord(set.ID)
	assert.NotNil(t, event, "Event should be stored")
}

// TestSuccessResponseFormat tests that successful delivery returns HTTP 202 with empty body per RFC8935
func (suite *PushErrorSuite) TestSuccessResponseFormat() {
	t := suite.T()

	subject := &goSet.EventSubject{
		SubjectIdentifier: goSet.SubjectIdentifier{
			Format:                    "scim",
			UniformResourceIdentifier: goSet.UniformResourceIdentifier{Uri: "/Users/success-test"},
		},
	}

	set := goSet.CreateSet(subject, suite.stream.Iss, suite.stream.Aud)
	set.AddEventPayload("https://schemas.openid.net/secevent/risc/event-type/account-disabled", map[string]interface{}{
		"reason": "success test",
	})

	privKey, _ := suite.instance.provider.GetIssuerPrivateKey("DEFAULT")
	tokenString, err := set.JWS(jwt.SigningMethodRS256, privKey)
	assert.NoError(t, err)

	req, _ := http.NewRequest(http.MethodPost, suite.stream.Delivery.PushReceiveMethod.EndpointUrl, strings.NewReader(tokenString))
	req.Header.Set("Authorization", suite.stream.Delivery.PushReceiveMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/secevent+jwt")

	resp, err := suite.instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusAccepted, resp.StatusCode, "Successful delivery MUST return HTTP 202 Accepted per RFC8935")

	body, _ := io.ReadAll(resp.Body)
	assert.Empty(t, body, "Successful response MUST have empty body per RFC8935")
}
