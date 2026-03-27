package goSetPush

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestSET creates a signed SET token string for testing.
func createTestSET(t *testing.T, issuer string, audience []string, key *rsa.PrivateKey) string {
	t.Helper()
	set := goSet.CreateSet(nil, issuer, audience)
	set.Events["https://schemas.openid.net/secevent/risc/event-type/credential-compromise"] = map[string]interface{}{}
	tokenString, err := set.JWS(jwt.SigningMethodRS256, key)
	require.NoError(t, err)
	return tokenString
}

func generateTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

func createTestJWKS(t *testing.T, key *rsa.PrivateKey) *keyfunc.JWKS {
	t.Helper()
	givenKey := keyfunc.NewGivenRSA(&key.PublicKey, keyfunc.GivenKeyOptions{})
	jwks := keyfunc.NewGiven(map[string]keyfunc.GivenKey{"test-kid": givenKey})
	return jwks
}

func buildPushRequest(t *testing.T, body string, contentType string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/events/test-stream", strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return req
}

// --- Receiver Tests ---

func TestParseReceivedSET_ValidToken(t *testing.T) {
	key := generateTestKey(t)
	tokenString := createTestSET(t, "https://issuer.example.com", []string{"https://audience.example.com"}, key)

	// Parse without signature verification (no JWKS)
	req := buildPushRequest(t, tokenString, "application/secevent+jwt")
	config := ReceiverConfig{
		ExpectedIssuer:    "https://issuer.example.com",
		ExpectedAudiences: []string{"https://audience.example.com"},
	}

	result, deliveryErr := ParseReceivedSET(req, config)
	assert.Nil(t, deliveryErr)
	require.NotNil(t, result)
	assert.Equal(t, "https://issuer.example.com", result.Token.Issuer)
	assert.Equal(t, tokenString, result.TokenString)
}

func TestParseReceivedSET_EmptyContentType(t *testing.T) {
	key := generateTestKey(t)
	tokenString := createTestSET(t, "https://issuer.example.com", nil, key)

	// Empty Content-Type should be accepted (per existing behavior)
	req := buildPushRequest(t, tokenString, "")
	config := ReceiverConfig{}

	result, deliveryErr := ParseReceivedSET(req, config)
	assert.Nil(t, deliveryErr)
	require.NotNil(t, result)
}

func TestParseReceivedSET_InvalidContentType(t *testing.T) {
	req := buildPushRequest(t, "some-body", "application/json")
	config := ReceiverConfig{}

	result, deliveryErr := ParseReceivedSET(req, config)
	assert.Nil(t, result)
	require.NotNil(t, deliveryErr)
	assert.Equal(t, ErrInvalidRequest, deliveryErr.ErrCode)
	assert.Contains(t, deliveryErr.Description, "Content-Type")
}

func TestParseReceivedSET_EmptyBody(t *testing.T) {
	req := buildPushRequest(t, "", "application/secevent+jwt")
	config := ReceiverConfig{}

	result, deliveryErr := ParseReceivedSET(req, config)
	assert.Nil(t, result)
	require.NotNil(t, deliveryErr)
	assert.Equal(t, ErrInvalidRequest, deliveryErr.ErrCode)
}

func TestParseReceivedSET_MalformedJWT(t *testing.T) {
	req := buildPushRequest(t, "not.a.valid.jwt.token", "application/secevent+jwt")
	config := ReceiverConfig{}

	result, deliveryErr := ParseReceivedSET(req, config)
	assert.Nil(t, result)
	require.NotNil(t, deliveryErr)
	assert.Equal(t, ErrInvalidRequest, deliveryErr.ErrCode)
}

func TestParseReceivedSET_InvalidIssuer(t *testing.T) {
	key := generateTestKey(t)
	tokenString := createTestSET(t, "https://wrong-issuer.example.com", nil, key)

	req := buildPushRequest(t, tokenString, "application/secevent+jwt")
	config := ReceiverConfig{
		ExpectedIssuer: "https://expected-issuer.example.com",
	}

	result, deliveryErr := ParseReceivedSET(req, config)
	assert.Nil(t, result)
	require.NotNil(t, deliveryErr)
	assert.Equal(t, ErrInvalidIssuer, deliveryErr.ErrCode)
}

func TestParseReceivedSET_InvalidAudience(t *testing.T) {
	key := generateTestKey(t)
	tokenString := createTestSET(t, "https://issuer.example.com", []string{"https://wrong-aud.example.com"}, key)

	req := buildPushRequest(t, tokenString, "application/secevent+jwt")
	config := ReceiverConfig{
		ExpectedAudiences: []string{"https://expected-aud.example.com"},
	}

	result, deliveryErr := ParseReceivedSET(req, config)
	assert.Nil(t, result)
	require.NotNil(t, deliveryErr)
	assert.Equal(t, ErrInvalidAudience, deliveryErr.ErrCode)
}

func TestParseReceivedSET_SkipIssuerValidation(t *testing.T) {
	key := generateTestKey(t)
	tokenString := createTestSET(t, "https://any-issuer.example.com", nil, key)

	req := buildPushRequest(t, tokenString, "application/secevent+jwt")
	config := ReceiverConfig{} // no ExpectedIssuer set

	result, deliveryErr := ParseReceivedSET(req, config)
	assert.Nil(t, deliveryErr)
	require.NotNil(t, result)
}

func TestParseReceivedSET_SkipAudienceValidation(t *testing.T) {
	key := generateTestKey(t)
	tokenString := createTestSET(t, "https://issuer.example.com", []string{"https://any-aud.example.com"}, key)

	req := buildPushRequest(t, tokenString, "application/secevent+jwt")
	config := ReceiverConfig{} // no ExpectedAudiences set

	result, deliveryErr := ParseReceivedSET(req, config)
	assert.Nil(t, deliveryErr)
	require.NotNil(t, result)
}

func TestWriteDeliveryError(t *testing.T) {
	w := httptest.NewRecorder()
	WriteDeliveryError(w, ErrInvalidIssuer, "The SET Issuer is invalid.")

	resp := w.Result()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var deliveryErr DeliveryErr
	err = json.Unmarshal(body, &deliveryErr)
	require.NoError(t, err)
	assert.Equal(t, ErrInvalidIssuer, deliveryErr.ErrCode)
	assert.Equal(t, "The SET Issuer is invalid.", deliveryErr.Description)
}

func TestWriteAccepted(t *testing.T) {
	w := httptest.NewRecorder()
	WriteAccepted(w)

	resp := w.Result()
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Empty(t, body)
}

// --- Transmitter Tests ---

func TestPushSET_Accepted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/secevent+jwt", r.Header.Get("Content-Type"))
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	result := PushSET(context.Background(), "test-token-string", TransmitterConfig{
		EndpointURL: server.URL,
	})

	assert.True(t, result.Accepted)
	assert.Equal(t, http.StatusAccepted, result.StatusCode)
	assert.NoError(t, result.Err)
}

func TestPushSET_BadRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		errBody := DeliveryErr{
			ErrCode:     ErrInvalidIssuer,
			Description: "The SET Issuer is invalid.",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(errBody)
	}))
	defer server.Close()

	result := PushSET(context.Background(), "test-token-string", TransmitterConfig{
		EndpointURL: server.URL,
	})

	assert.False(t, result.Accepted)
	assert.Equal(t, http.StatusBadRequest, result.StatusCode)
	require.Error(t, result.Err)

	var deliveryErr *DeliveryErr
	assert.ErrorAs(t, result.Err, &deliveryErr)
	assert.Equal(t, ErrInvalidIssuer, deliveryErr.ErrCode)
}

func TestPushSET_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	result := PushSET(context.Background(), "test-token-string", TransmitterConfig{
		EndpointURL: server.URL,
	})

	assert.False(t, result.Accepted)
	assert.Equal(t, http.StatusInternalServerError, result.StatusCode)
	assert.Error(t, result.Err)
}

func TestPushSET_AuthorizationHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer test-token-123", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	result := PushSET(context.Background(), "test-set", TransmitterConfig{
		EndpointURL:   server.URL,
		Authorization: "Bearer test-token-123",
	})

	assert.True(t, result.Accepted)
}

func TestPushSET_BareTokenPrefixed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer raw-token-value", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	result := PushSET(context.Background(), "test-set", TransmitterConfig{
		EndpointURL:   server.URL,
		Authorization: "raw-token-value",
	})

	assert.True(t, result.Accepted)
}

func TestPushSET_NoAuthorizationHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	result := PushSET(context.Background(), "test-set", TransmitterConfig{
		EndpointURL: server.URL,
	})

	assert.True(t, result.Accepted)
}

func TestPushSET_BodyContent(t *testing.T) {
	expectedToken := "eyJhbGciOiJSUzI1NiJ9.test.signature"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.Equal(t, expectedToken, string(body))
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	result := PushSET(context.Background(), expectedToken, TransmitterConfig{
		EndpointURL: server.URL,
	})

	assert.True(t, result.Accepted)
}

func TestPushSET_ConnectionError(t *testing.T) {
	result := PushSET(context.Background(), "test-set", TransmitterConfig{
		EndpointURL: "http://localhost:1", // port 1 should not be listening
	})

	assert.False(t, result.Accepted)
	assert.Error(t, result.Err)
	assert.Equal(t, 0, result.StatusCode)
}

func TestPushSET_CustomHTTPClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	customClient := &http.Client{}
	result := PushSET(context.Background(), "test-set", TransmitterConfig{
		EndpointURL: server.URL,
		HTTPClient:  customClient,
	})

	assert.True(t, result.Accepted)
}

func TestDeliveryErr_ErrorInterface(t *testing.T) {
	err := &DeliveryErr{
		ErrCode:     ErrInvalidRequest,
		Description: "Bad request",
	}
	assert.Equal(t, "invalid_request: Bad request", err.Error())

	// Verify it satisfies the error interface
	var e error = err
	assert.NotNil(t, e)
}
