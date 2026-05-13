package test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
)

func TestTriggerEventHandler(t *testing.T) {
	instance, err := createServer(t, "trigger_event_test", true)
	assert.NoError(t, err)
	defer instance.app.Shutdown()
	ts := instance.ts
	mgmtToken := instance.streamMgmtToken

	// 2. Create a stream to trigger events for via API
	regUrl := ts.URL + "/stream"
	streamConfig := model.StreamConfiguration{
		Iss:             instance.app.GetDefIssuer(),
		EventsRequested: []string{"https://schemas.openid.net/secevent/risc/event-type/account-disabled"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollTransmitMethod: &model.PollTransmitMethod{
				Method: model.DeliveryPoll,
			},
		},
	}
	regBytes, _ := json.Marshal(streamConfig)
	regReq, _ := http.NewRequest(http.MethodPost, regUrl, bytes.NewReader(regBytes))
	regReq.Header.Set("Content-Type", "application/json")
	regReq.Header.Set("Authorization", "Bearer "+mgmtToken)

	regResp, err := http.DefaultClient.Do(regReq)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusCreated, regResp.StatusCode)

	var createdStream model.StreamConfiguration
	err = json.NewDecoder(regResp.Body).Decode(&createdStream)
	assert.NoError(t, err)

	// 3. Trigger event
	triggerReq := map[string]interface{}{
		"stream_id":  createdStream.Id,
		"event_type": "https://schemas.openid.net/secevent/risc/event-type/account-disabled",
		"subject": map[string]interface{}{
			"format": "email",
			"email":  "user@example.com",
		},
	}
	body, _ := json.Marshal(triggerReq)

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/trigger-event", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+mgmtToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// 4. Verify event is in buffer (via poll)
	pollParams := model.PollParameters{ReturnImmediately: true}
	pollBody, _ := json.Marshal(pollParams)
	pollUrl := ts.URL + "/poll/" + createdStream.Id
	pollReq, _ := http.NewRequest(http.MethodPost, pollUrl, bytes.NewBuffer(pollBody))
	pollReq.Header.Set("Authorization", createdStream.Delivery.PollTransmitMethod.AuthorizationHeader)
	pollReq.Header.Set("Content-Type", "application/json")

	pollResp, err := http.DefaultClient.Do(pollReq)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, pollResp.StatusCode)

	var pollResult model.PollResponse
	err = json.NewDecoder(pollResp.Body).Decode(&pollResult)
	assert.NoError(t, err)
	assert.NotEmpty(t, pollResult.Sets)
}
