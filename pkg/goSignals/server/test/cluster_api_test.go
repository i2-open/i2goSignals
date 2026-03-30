package test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/stretchr/testify/assert"
)

func TestClusterWakeupAPI(t *testing.T) {
	// Set the secret for the test
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", "test-secret")

	instance, err := createServer(t, "cluster_api_test", true)
	if err != nil {
		t.Fatal(err)
	}
	defer instance.app.Shutdown()

	sid := "test-sid"
	mode := "push"

	// 1. Test valid wake-up
	token := authSupport.GenerateClusterToken("test-secret", sid, mode)
	wakeReq := map[string]string{
		"sid":  sid,
		"mode": mode,
	}
	body, _ := json.Marshal(wakeReq)

	req, _ := http.NewRequest(http.MethodPost, instance.ts.URL+"/_cluster/wake-transmitter", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)

	// 2. Test invalid token
	req, _ = http.NewRequest(http.MethodPost, instance.ts.URL+"/_cluster/wake-transmitter", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer invalid-token")
	resp, err = instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// 3. Test missing authorization
	req, _ = http.NewRequest(http.MethodPost, instance.ts.URL+"/_cluster/wake-transmitter", bytes.NewReader(body))
	resp, err = instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// 4. Test invalid body
	req, _ = http.NewRequest(http.MethodPost, instance.ts.URL+"/_cluster/wake-transmitter", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
