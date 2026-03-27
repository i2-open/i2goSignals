package goSetPoll

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

	"github.com/golang-jwt/jwt/v4"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

func createTestSET(t *testing.T, issuer string, audience []string, key *rsa.PrivateKey) (string, string) {
	t.Helper()
	set := goSet.CreateSet(nil, issuer, audience)
	set.Events["https://schemas.openid.net/secevent/risc/event-type/credential-compromise"] = map[string]interface{}{}
	jti := set.ID
	tokenString, err := set.JWS(jwt.SigningMethodRS256, key)
	require.NoError(t, err)
	return jti, tokenString
}

// --- Transmitter Tests ---

func TestParsePollRequest_Valid(t *testing.T) {
	body := `{
		"maxEvents": 10,
		"returnImmediately": true,
		"ack": ["jti-1", "jti-2"],
		"setErrs": {
			"jti-3": {"err": "invalid_request", "description": "bad token"}
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/poll/test", strings.NewReader(body))

	pollReq, err := ParsePollRequest(req)
	require.NoError(t, err)
	require.NotNil(t, pollReq)
	assert.Equal(t, int32(10), pollReq.MaxEvents)
	assert.True(t, pollReq.ReturnImmediately)
	assert.Equal(t, []string{"jti-1", "jti-2"}, pollReq.Acks)
	require.Contains(t, pollReq.SetErrs, "jti-3")
	assert.Equal(t, "invalid_request", pollReq.SetErrs["jti-3"].Error)
}

func TestParsePollRequest_Empty(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/poll/test", strings.NewReader("{}"))

	pollReq, err := ParsePollRequest(req)
	require.NoError(t, err)
	require.NotNil(t, pollReq)
	assert.Equal(t, int32(0), pollReq.MaxEvents)
	assert.False(t, pollReq.ReturnImmediately)
	assert.Nil(t, pollReq.Acks)
}

func TestParsePollRequest_Invalid(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/poll/test", strings.NewReader("not json"))

	pollReq, err := ParsePollRequest(req)
	assert.Error(t, err)
	assert.Nil(t, pollReq)
}

func TestWritePollResponse_WithEvents(t *testing.T) {
	w := httptest.NewRecorder()
	WritePollResponse(w, PollResponse{
		Sets: map[string]string{
			"jti-1": "token-1",
			"jti-2": "token-2",
		},
		MoreAvailable: true,
	})

	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "application/json")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var pollResp PollResponse
	err = json.Unmarshal(body, &pollResp)
	require.NoError(t, err)
	assert.Len(t, pollResp.Sets, 2)
	assert.Equal(t, "token-1", pollResp.Sets["jti-1"])
	assert.True(t, pollResp.MoreAvailable)
}

func TestWritePollResponse_Empty(t *testing.T) {
	w := httptest.NewRecorder()
	WritePollResponse(w, PollResponse{})

	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var pollResp PollResponse
	err = json.Unmarshal(body, &pollResp)
	require.NoError(t, err)
	assert.NotNil(t, pollResp.Sets) // should be empty map, not null
	assert.Len(t, pollResp.Sets, 0)
	assert.False(t, pollResp.MoreAvailable)
}

// --- Receiver Tests ---

func TestPollRaw_WithEvents(t *testing.T) {
	serverResp := PollResponse{
		Sets: map[string]string{
			"jti-1": "token-string-1",
			"jti-2": "token-string-2",
		},
		MoreAvailable: false,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request body contains acks
		var reqBody PollRequest
		err := json.NewDecoder(r.Body).Decode(&reqBody)
		assert.NoError(t, err)
		assert.Equal(t, []string{"prev-jti-1"}, reqBody.Acks)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(serverResp)
	}))
	defer server.Close()

	resp, status, err := PollRaw(context.Background(), PollRequest{
		ReturnImmediately: true,
		Acks:              []string{"prev-jti-1"},
	}, ReceiverConfig{
		EndpointURL: server.URL,
	})

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	require.NotNil(t, resp)
	assert.Len(t, resp.Sets, 2)
	assert.False(t, resp.MoreAvailable)
}

func TestPollRaw_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(PollResponse{Sets: map[string]string{}})
	}))
	defer server.Close()

	resp, status, err := PollRaw(context.Background(), PollRequest{ReturnImmediately: true}, ReceiverConfig{
		EndpointURL: server.URL,
	})

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	require.NotNil(t, resp)
	assert.Empty(t, resp.Sets)
}

func TestPollRaw_AuthorizationHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer my-auth-token", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(PollResponse{Sets: map[string]string{}})
	}))
	defer server.Close()

	_, _, err := PollRaw(context.Background(), PollRequest{ReturnImmediately: true}, ReceiverConfig{
		EndpointURL:   server.URL,
		Authorization: "Bearer my-auth-token",
	})
	assert.NoError(t, err)
}

func TestPollRaw_HTTPError401(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	resp, status, err := PollRaw(context.Background(), PollRequest{ReturnImmediately: true}, ReceiverConfig{
		EndpointURL: server.URL,
	})

	assert.Nil(t, resp)
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Error(t, err)
}

func TestPollRaw_HTTPError403(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	resp, status, err := PollRaw(context.Background(), PollRequest{ReturnImmediately: true}, ReceiverConfig{
		EndpointURL: server.URL,
	})

	assert.Nil(t, resp)
	assert.Equal(t, http.StatusForbidden, status)
	assert.Error(t, err)
}

func TestPollRaw_HTTPError503(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	resp, status, err := PollRaw(context.Background(), PollRequest{ReturnImmediately: true}, ReceiverConfig{
		EndpointURL: server.URL,
	})

	assert.Nil(t, resp)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Error(t, err)
}

func TestPollRaw_ConnectionError(t *testing.T) {
	resp, status, err := PollRaw(context.Background(), PollRequest{ReturnImmediately: true}, ReceiverConfig{
		EndpointURL: "http://localhost:1", // unreachable
	})

	assert.Nil(t, resp)
	assert.Equal(t, 0, status)
	assert.Error(t, err)
}

func TestPoll_WithValidSETs(t *testing.T) {
	key := generateTestKey(t)
	jti1, token1 := createTestSET(t, "https://issuer.example.com", []string{"https://aud.example.com"}, key)
	jti2, token2 := createTestSET(t, "https://issuer.example.com", []string{"https://aud.example.com"}, key)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := PollResponse{
			Sets: map[string]string{
				jti1: token1,
				jti2: token2,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	parsed, status, err := Poll(context.Background(), PollRequest{ReturnImmediately: true}, ReceiverConfig{
		EndpointURL:       server.URL,
		ExpectedIssuer:    "https://issuer.example.com",
		ExpectedAudiences: []string{"https://aud.example.com"},
	})

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	require.NotNil(t, parsed)
	assert.Len(t, parsed.ParsedSETs, 2)
	assert.Empty(t, parsed.Errors)
	assert.Contains(t, parsed.ParsedSETs, jti1)
	assert.Contains(t, parsed.ParsedSETs, jti2)
}

func TestPoll_IssuerValidationError(t *testing.T) {
	key := generateTestKey(t)
	jti1, token1 := createTestSET(t, "https://wrong-issuer.example.com", nil, key)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := PollResponse{
			Sets: map[string]string{jti1: token1},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	parsed, _, err := Poll(context.Background(), PollRequest{ReturnImmediately: true}, ReceiverConfig{
		EndpointURL:    server.URL,
		ExpectedIssuer: "https://expected-issuer.example.com",
	})

	require.NoError(t, err)
	assert.Empty(t, parsed.ParsedSETs)
	require.Contains(t, parsed.Errors, jti1)
	assert.Equal(t, "invalid_issuer", parsed.Errors[jti1].Error)
}

func TestPoll_AudienceValidationError(t *testing.T) {
	key := generateTestKey(t)
	jti1, token1 := createTestSET(t, "https://issuer.example.com", []string{"https://wrong-aud.example.com"}, key)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := PollResponse{
			Sets: map[string]string{jti1: token1},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	parsed, _, err := Poll(context.Background(), PollRequest{ReturnImmediately: true}, ReceiverConfig{
		EndpointURL:       server.URL,
		ExpectedAudiences: []string{"https://expected-aud.example.com"},
	})

	require.NoError(t, err)
	assert.Empty(t, parsed.ParsedSETs)
	require.Contains(t, parsed.Errors, jti1)
	assert.Equal(t, "invalid_audience", parsed.Errors[jti1].Error)
}

func TestPoll_MalformedSET(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := PollResponse{
			Sets: map[string]string{
				"bad-jti": "not.a.valid.jwt",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	parsed, _, err := Poll(context.Background(), PollRequest{ReturnImmediately: true}, ReceiverConfig{
		EndpointURL: server.URL,
	})

	require.NoError(t, err)
	assert.Empty(t, parsed.ParsedSETs)
	require.Contains(t, parsed.Errors, "bad-jti")
	assert.Equal(t, "invalid_request", parsed.Errors["bad-jti"].Error)
}

func TestPoll_MixedValidAndInvalid(t *testing.T) {
	key := generateTestKey(t)
	goodJti, goodToken := createTestSET(t, "https://issuer.example.com", nil, key)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := PollResponse{
			Sets: map[string]string{
				goodJti:   goodToken,
				"bad-jti": "not.a.valid.jwt",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	parsed, _, err := Poll(context.Background(), PollRequest{ReturnImmediately: true}, ReceiverConfig{
		EndpointURL:    server.URL,
		ExpectedIssuer: "https://issuer.example.com",
	})

	require.NoError(t, err)
	assert.Len(t, parsed.ParsedSETs, 1)
	assert.Contains(t, parsed.ParsedSETs, goodJti)
	assert.Len(t, parsed.Errors, 1)
	assert.Contains(t, parsed.Errors, "bad-jti")
}

func TestPoll_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(PollResponse{Sets: map[string]string{}})
	}))
	defer server.Close()

	parsed, _, err := Poll(context.Background(), PollRequest{ReturnImmediately: true}, ReceiverConfig{
		EndpointURL: server.URL,
	})

	require.NoError(t, err)
	assert.Empty(t, parsed.ParsedSETs)
	assert.Empty(t, parsed.Errors)
}

func TestPoll_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	parsed, status, err := Poll(context.Background(), PollRequest{ReturnImmediately: true}, ReceiverConfig{
		EndpointURL: server.URL,
	})

	assert.Nil(t, parsed)
	assert.Equal(t, http.StatusForbidden, status)
	assert.Error(t, err)
}

func TestPollRaw_SetsJSONHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Contains(t, r.Header.Get("Accept"), "application/json")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(PollResponse{Sets: map[string]string{}})
	}))
	defer server.Close()

	_, _, err := PollRaw(context.Background(), PollRequest{ReturnImmediately: true}, ReceiverConfig{
		EndpointURL: server.URL,
	})
	assert.NoError(t, err)
}
