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

// jwksForKey builds a JWKS keyed by the issuer string, matching the "kid"
// goSet.JWS emits when SecurityEventToken.Kid is empty (it falls back to the
// issuer). This lets a verifying parse resolve the key for a signed SET.
func jwksForKey(t *testing.T, issuer string, key *rsa.PrivateKey) *keyfunc.JWKS {
	t.Helper()
	givenKey := keyfunc.NewGivenRSA(&key.PublicKey, keyfunc.GivenKeyOptions{})
	return keyfunc.NewGiven(map[string]keyfunc.GivenKey{issuer: givenKey})
}

// --- Signing-only receive posture (#184): RequireSignature ---

// A valid signature with a matching JWKS is accepted under RequireSignature.
func TestParseReceivedSET_RequireSignature_ValidAccepted(t *testing.T) {
	key := generateTestKey(t)
	iss := "https://issuer.example.com"
	aud := []string{"https://audience.example.com"}
	tokenString := createTestSET(t, iss, aud, key)

	req := buildPushRequest(t, tokenString, "application/secevent+jwt")
	config := ReceiverConfig{
		JWKS:              jwksForKey(t, iss, key),
		ExpectedIssuer:    iss,
		ExpectedAudiences: aud,
		RequireSignature:  true,
	}

	result, deliveryErr := ParseReceivedSET(req, config)
	assert.Nil(t, deliveryErr)
	require.NotNil(t, result)
	assert.Equal(t, iss, result.Token.Issuer)
}

// A SET signed by a key that does not match the issuer's JWKS is rejected with
// jws_signature_failed (the RFC8935 §2.4 rotate-and-retry signal) — not the
// generic invalid_request used when signatures are optional.
func TestParseReceivedSET_RequireSignature_BadSignatureRejected(t *testing.T) {
	signKey := generateTestKey(t)
	otherKey := generateTestKey(t)
	iss := "https://issuer.example.com"
	aud := []string{"https://audience.example.com"}
	tokenString := createTestSET(t, iss, aud, signKey)

	req := buildPushRequest(t, tokenString, "application/secevent+jwt")
	config := ReceiverConfig{
		JWKS:              jwksForKey(t, iss, otherKey), // wrong public key for this kid
		ExpectedIssuer:    iss,
		ExpectedAudiences: aud,
		RequireSignature:  true,
	}

	result, deliveryErr := ParseReceivedSET(req, config)
	require.NotNil(t, deliveryErr)
	assert.Nil(t, result)
	assert.Equal(t, ErrJwsSignatureFailed, deliveryErr.ErrCode)
}

// Under RequireSignature a missing trust anchor (nil JWKS) is a hard reject: the
// SET must NOT be accepted unverified. This is the core difference from the
// default posture, where a nil JWKS skips verification.
func TestParseReceivedSET_RequireSignature_NoJWKSRejected(t *testing.T) {
	key := generateTestKey(t)
	iss := "https://issuer.example.com"
	aud := []string{"https://audience.example.com"}
	tokenString := createTestSET(t, iss, aud, key)

	req := buildPushRequest(t, tokenString, "application/secevent+jwt")
	config := ReceiverConfig{
		JWKS:              nil,
		ExpectedIssuer:    iss,
		ExpectedAudiences: aud,
		RequireSignature:  true,
	}

	result, deliveryErr := ParseReceivedSET(req, config)
	require.NotNil(t, deliveryErr)
	assert.Nil(t, result)
	assert.Equal(t, ErrJwsSignatureFailed, deliveryErr.ErrCode)
}

// An issuer mismatch is reported as invalid_issuer (a trust failure, not a
// signature failure) and is detected before signature verification, so a sender
// does not pointlessly rotate keys.
func TestParseReceivedSET_RequireSignature_WrongIssuerRejected(t *testing.T) {
	key := generateTestKey(t)
	aud := []string{"https://audience.example.com"}
	tokenString := createTestSET(t, "https://attacker.example.com", aud, key)

	req := buildPushRequest(t, tokenString, "application/secevent+jwt")
	config := ReceiverConfig{
		JWKS:              jwksForKey(t, "https://attacker.example.com", key),
		ExpectedIssuer:    "https://issuer.example.com",
		ExpectedAudiences: aud,
		RequireSignature:  true,
	}

	result, deliveryErr := ParseReceivedSET(req, config)
	require.NotNil(t, deliveryErr)
	assert.Nil(t, result)
	assert.Equal(t, ErrInvalidIssuer, deliveryErr.ErrCode)
}

// aud validation still runs (and runs before signature verification) under the
// signing-only posture.
func TestParseReceivedSET_RequireSignature_AudMismatchRejected(t *testing.T) {
	key := generateTestKey(t)
	iss := "https://issuer.example.com"
	tokenString := createTestSET(t, iss, []string{"https://other.example.com"}, key)

	req := buildPushRequest(t, tokenString, "application/secevent+jwt")
	config := ReceiverConfig{
		JWKS:              jwksForKey(t, iss, key),
		ExpectedIssuer:    iss,
		ExpectedAudiences: []string{"https://audience.example.com"},
		RequireSignature:  true,
	}

	result, deliveryErr := ParseReceivedSET(req, config)
	require.NotNil(t, deliveryErr)
	assert.Nil(t, result)
	assert.Equal(t, ErrInvalidAudience, deliveryErr.ErrCode)
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

// TestPushSET_InsecureSkipVerify pins the tx_tls_skip_verify wiring: a receiver
// presenting a self-signed TLS cert (httptest.NewTLSServer) is rejected by the
// default verifying client, but accepted when InsecureSkipVerify is set.
func TestPushSET_InsecureSkipVerify(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	// Default (verify): the self-signed cert is untrusted, so the push fails at
	// the TLS layer with no HTTP response.
	verifyResult := PushSET(context.Background(), "test-token-string", TransmitterConfig{
		EndpointURL: server.URL,
	})
	require.Error(t, verifyResult.Err, "default client must reject the self-signed receiver cert")
	assert.False(t, verifyResult.Accepted)

	// InsecureSkipVerify: TLS verification is skipped and the push is accepted.
	skipResult := PushSET(context.Background(), "test-token-string", TransmitterConfig{
		EndpointURL:        server.URL,
		InsecureSkipVerify: true,
	})
	assert.NoError(t, skipResult.Err, "InsecureSkipVerify must accept the self-signed receiver cert")
	assert.True(t, skipResult.Accepted)
	assert.Equal(t, http.StatusAccepted, skipResult.StatusCode)
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
