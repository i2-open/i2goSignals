package test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStatusTrigger(t *testing.T) {
	instance, err := createServer(t, "test_status_trigger", true)
	assert.NoError(t, err)
	defer instance.app.Shutdown()

	// Try to call /status with a valid stream_id format but no token
	// This should at least match the route and return 401 or 403 (due to lack of auth)
	// instead of 404 (route not matched)

	streamID := "69609d349d081c37452228ce"
	req, _ := http.NewRequest(http.MethodGet, "http://"+instance.host+"/status?stream_id="+streamID, nil)

	resp, err := instance.client.Do(req)
	assert.NoError(t, err)

	// If it matches the route, it should call ValidateAuthorization which will return 401 because we have no token.
	// If it doesn't match the route, it will return 404.
	assert.NotEqual(t, http.StatusNotFound, resp.StatusCode, "Endpoint /status?stream_id=... should not return 404")
	streamID = "non-hex-id"
	req, _ = http.NewRequest(http.MethodGet, "http://"+instance.host+"/status?stream_id="+streamID, nil)
	resp, err = instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "Endpoint /status?stream_id=non-hex should now return 401 because of permissive regex")

	// Try with multiple query parameters
	// Reset streamID to valid one for this subtest
	streamID = "69609d349d081c37452228ce"
	req, _ = http.NewRequest(http.MethodGet, "http://"+instance.host+"/status?foo=bar&stream_id="+streamID, nil)
	resp, err = instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "Endpoint /status?foo=bar&stream_id=... should return 401")
}
