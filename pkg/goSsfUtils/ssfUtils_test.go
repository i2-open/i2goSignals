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
