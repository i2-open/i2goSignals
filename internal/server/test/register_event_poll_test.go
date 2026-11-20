package test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegisteredTokenManagesAndPolls proves the single-token model the OpenID
// conformance suite uses in STATIC auth mode: one registered bearer carrying
// stream+event is sufficient to BOTH create/manage a poll stream AND poll it,
// using the registered token throughout (never the per-stream delivery token
// returned in the stream config).
//
// This is the end-to-end counterpart to the scope-mint unit tests and exercises
// the reconciliation of the old #140 divergence: before the fix, the registered
// management token carried stream only, so this poll returned 403.
func TestRegisteredTokenManagesAndPolls(t *testing.T) {
	t.Setenv("I2SIG_BOOTSTRAP_TOKEN", "")
	instance, err := createServer(t, "register_event_poll_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	// 1. Register a client requesting stream + event.
	status, token, roles := registerClientToken(t, instance, instance.iatToken,
		[]string{authSupport.ScopeStreamMgmt, authSupport.ScopeEventDelivery})
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, roles, authSupport.ScopeStreamMgmt)
	require.Contains(t, roles, authSupport.ScopeEventDelivery,
		"the registered token must carry event so it can poll")

	// 2. Create a poll stream using that token (stream-management capability).
	streamConfig := model.StreamConfiguration{
		Iss:             "DEFAULT",
		Aud:             []string{"https://receiver.example.com"},
		EventsRequested: []string{"*"},
		EventsSupported: []string{"*"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll},
		},
	}
	body, _ := json.Marshal(streamConfig)
	req, err := http.NewRequest(http.MethodPost, instance.ts.URL+"/stream", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := instance.client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var created model.StreamConfiguration
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	resp.Body.Close()
	require.NotEmpty(t, created.Id)

	// 3. Poll /poll/{id} with the SAME registered token (NOT the per-stream
	//    delivery token in created.Delivery). A freshly created stream defaults
	//    to enabled, so a 403 here would indicate an authorization failure.
	pollBody, _ := json.Marshal(map[string]any{"maxEvents": 10, "returnImmediately": true})
	pollReq, err := http.NewRequest(http.MethodPost, instance.ts.URL+"/poll/"+created.Id, bytes.NewReader(pollBody))
	require.NoError(t, err)
	pollReq.Header.Set("Authorization", "Bearer "+token)
	pollReq.Header.Set("Content-Type", "application/json")
	pollResp, err := instance.client.Do(pollReq)
	require.NoError(t, err)
	defer pollResp.Body.Close()
	assert.Equal(t, http.StatusOK, pollResp.StatusCode,
		"the registered stream+event token must be accepted at /poll (not 403)")
}
