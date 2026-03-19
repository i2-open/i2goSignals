package goSsfUtils

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
)

func TestGetStreamConfig(t *testing.T) {
	expectedConfig := &model.StreamConfiguration{
		Iss: "test-iss",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/config", r.URL.Path)
		assert.Equal(t, "stream123", r.URL.Query().Get("stream_id"))
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(expectedConfig)
	}))
	defer ts.Close()

	server := &model.Server{
		ServerConfiguration: &model.TransmitterConfiguration{
			ConfigurationEndpoint: ts.URL + "/config",
		},
	}

	config, err := GetStreamConfig(context.Background(), ts.Client(), server, "stream123")
	assert.NoError(t, err)
	assert.Equal(t, expectedConfig.Iss, config.Iss)
}

func TestGetStreamStatus(t *testing.T) {
	expectedStatus := &model.StreamStatus{
		Status: "enabled",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/status", r.URL.Path)
		assert.Equal(t, "stream123", r.URL.Query().Get("stream_id"))
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(expectedStatus)
	}))
	defer ts.Close()

	server := &model.Server{
		ServerConfiguration: &model.TransmitterConfiguration{
			StatusEndpoint: ts.URL + "/status",
		},
	}

	status, err := GetStreamStatus(context.Background(), ts.Client(), server, "stream123")
	assert.NoError(t, err)
	assert.Equal(t, expectedStatus.Status, status.Status)
}

func TestGetVerificationEndpoint(t *testing.T) {
	expectedEndpoint := "https://example.com/verify"
	server := &model.Server{
		ServerConfiguration: &model.TransmitterConfiguration{
			VerificationEndpoint: expectedEndpoint,
		},
	}

	endpoint, err := GetVerificationEndpoint(context.Background(), http.DefaultClient, server)
	assert.NoError(t, err)
	assert.Equal(t, expectedEndpoint, endpoint)
}

func TestPostVerification(t *testing.T) {
	params := model.VerificationParameters{
		State: "test-state",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/verify", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var receivedParams model.VerificationParameters
		err := json.NewDecoder(r.Body).Decode(&receivedParams)
		assert.NoError(t, err)
		assert.Equal(t, params.State, receivedParams.State)

		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	err := PostVerification(context.Background(), ts.Client(), ts.URL+"/verify", params)
	assert.NoError(t, err)
}

func TestPostVerificationUnauthorized(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	err := PostVerification(context.Background(), ts.Client(), ts.URL+"/verify", model.VerificationParameters{})
	assert.Error(t, err)
	assert.Equal(t, "unauthorized", err.Error())
}

func TestAddStreamIdToUrl(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		streamId string
		expected string
	}{
		{
			name:     "no query",
			endpoint: "https://example.com/status",
			streamId: "stream1",
			expected: "https://example.com/status?stream_id=stream1",
		},
		{
			name:     "existing query, no stream_id",
			endpoint: "https://example.com/status?foo=bar",
			streamId: "stream1",
			expected: "https://example.com/status?foo=bar&stream_id=stream1",
		},
		{
			name:     "existing stream_id",
			endpoint: "https://example.com/status?stream_id=stream2",
			streamId: "stream1",
			expected: "https://example.com/status?stream_id=stream2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, AddStreamIdToUrl(tt.endpoint, tt.streamId))
		})
	}
}
