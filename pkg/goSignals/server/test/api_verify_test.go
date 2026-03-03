package test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSet/events"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type VerifySuite struct {
	suite.Suite
	instance *ssfInstance
}

func (suite *VerifySuite) SetupSuite() {
	instance, err := createServer(suite.T(), "verify_test", true)
	assert.NoError(suite.T(), err)
	suite.instance = instance
}

func (suite *VerifySuite) TearDownSuite() {
	if suite.instance != nil {
		suite.instance.app.Shutdown()
		suite.instance.ts.Close()
	}
}

func TestVerifySuite(t *testing.T) {
	suite.Run(t, new(VerifySuite))
}

func (suite *VerifySuite) TestTriggerVerification() {
	t := suite.T()
	instance := suite.instance

	// 1. Create a stream
	streamConfig := model.StreamConfiguration{
		Iss:             "DEFAULT",
		Aud:             []string{"https://receiver.example.com"},
		EventsSupported: []string{"https://schemas.openid.net/secevent/ssf/event-type/verification"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollTransmitMethod: &model.PollTransmitMethod{
				Method: model.DeliveryPoll,
			},
		},
	}

	body, _ := json.Marshal(streamConfig)
	req, _ := http.NewRequest(http.MethodPost, instance.ts.URL+"/stream", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+instance.streamMgmtToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var createdStream model.StreamConfiguration
	_ = json.NewDecoder(resp.Body).Decode(&createdStream)
	streamId := createdStream.Id

	// 2. Generate a token for this stream specifically if needed,
	// but the streamMgmtToken might already have access if it was created with the project ID.
	// Actually, the server implementation of VerificationRequest allows any token with ScopeEventDelivery or ScopeStreamMgmt.
	// ValidateAuthorization for /verification usually expects stream_id in the token or as a query param.

	// Create a token for this specific stream
	streamToken, err := instance.provider.GetAuthIssuer().IssueStreamToken(streamId, instance.projectId)
	assert.NoError(t, err)

	// 3. Trigger verification
	verifyReq := struct {
		StreamId string `json:"stream_id"`
		State    string `json:"state"`
	}{
		StreamId: streamId,
		State:    "test-state",
	}

	verifyBody, _ := json.Marshal(verifyReq)
	req, _ = http.NewRequest(http.MethodPost, instance.ts.URL+"/verify", bytes.NewBuffer(verifyBody))
	req.Header.Set("Authorization", "Bearer "+streamToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err = instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	// 4. Verify that an event was created
	// We can check the pending events for the stream
	jtis, _ := instance.provider.GetEventIds(streamId, model.PollParameters{MaxEvents: 10})
	assert.Len(t, jtis, 1)

	// Get the event and check its content
	event := instance.provider.GetEvent(jtis[0])
	assert.NotNil(t, event)
	assert.Contains(t, event.Events, "https://schemas.openid.net/secevent/ssf/event-type/verification")

	payload := event.Events["https://schemas.openid.net/secevent/ssf/event-type/verification"].(events.VerifyPayload)
	assert.Equal(t, "test-state", payload.State)
}

func (suite *VerifySuite) TestTriggerVerificationError() {
	t := suite.T()
	instance := suite.instance

	// 1. Invalid stream ID (404)
	verifyReq := struct {
		StreamId string `json:"stream_id"`
		State    string `json:"state"`
	}{
		StreamId: "non-existent-stream",
		State:    "test-state",
	}

	verifyBody, _ := json.Marshal(verifyReq)
	req, _ := http.NewRequest(http.MethodPost, instance.ts.URL+"/verify", bytes.NewBuffer(verifyBody))
	req.Header.Set("Authorization", "Bearer "+instance.streamMgmtToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	// 2. Malformed JSON (400)
	req, _ = http.NewRequest(http.MethodPost, instance.ts.URL+"/verify", bytes.NewBuffer([]byte("{invalid-json}")))
	req.Header.Set("Authorization", "Bearer "+instance.streamMgmtToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err = instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
