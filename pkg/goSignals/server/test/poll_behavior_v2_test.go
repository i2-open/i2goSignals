package test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type PollBehaviorSuite struct {
	suite.Suite
	instance *ssfInstance
	stream   model.StreamConfiguration
}

func (suite *PollBehaviorSuite) SetupSuite() {
	instance, err := createServer(suite.T(), "poll_behavior_test", true)
	assert.NoError(suite.T(), err)
	suite.instance = instance

	// Create a poll transmitter stream
	streamConfig := model.StreamConfiguration{
		Iss:             "DEFAULT",
		Aud:             []string{"https://receiver.example.com"},
		EventsSupported: []string{"*"},
		EventsRequested: []string{"*"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollTransmitMethod: &model.PollTransmitMethod{
				Method: model.DeliveryPoll,
			},
		},
	}

	stream, err := instance.CreateStream(streamConfig, authUtil.ConvertProject(instance.projectId))
	assert.NoError(suite.T(), err)
	state, err := instance.GetStreamState(stream.Id)
	assert.NoError(suite.T(), err)
	instance.app.EventRouter.UpdateStreamState(state)

	suite.stream = stream
}

func (suite *PollBehaviorSuite) TearDownSuite() {
	if suite.instance != nil {
		suite.instance.app.Shutdown()
		suite.instance.ts.Close()
	}
}

func TestPollBehaviorSuite(t *testing.T) {
	suite.Run(t, new(PollBehaviorSuite))
}

func (suite *PollBehaviorSuite) TestPollDisabledMode() {
	t := suite.T()
	suite.T().Setenv("POLL_SRV_BEHAVIOR", "MODE")

	// Set stream to disabled
	suite.instance.UpdateStreamStatus(suite.stream.Id, model.StreamStateDisable, "Testing disable")
	// Update router's view of the stream
	state, err := suite.instance.GetStreamState(suite.stream.Id)
	assert.NoError(suite.T(), err)
	suite.instance.app.EventRouter.UpdateStreamState(state)

	pollParams := model.PollParameters{ReturnImmediately: true}
	bodyBytes, _ := json.Marshal(pollParams)
	pollUrl := suite.instance.GetPollUrl(suite.stream)
	req, _ := http.NewRequest(http.MethodPost, pollUrl, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", suite.stream.Delivery.PollTransmitMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err := suite.instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func (suite *PollBehaviorSuite) TestPollPausedModeNoAcks() {
	t := suite.T()
	suite.T().Setenv("POLL_SRV_BEHAVIOR", "MODE")

	// Set stream to paused
	suite.instance.UpdateStreamStatus(suite.stream.Id, model.StreamStatePause, "Testing pause")
	// Update router's view of the stream
	state, err := suite.instance.GetStreamState(suite.stream.Id)
	assert.NoError(suite.T(), err)
	suite.instance.app.EventRouter.UpdateStreamState(state)

	pollParams := model.PollParameters{ReturnImmediately: true}
	bodyBytes, _ := json.Marshal(pollParams)
	pollUrl := suite.instance.GetPollUrl(suite.stream)
	req, _ := http.NewRequest(http.MethodPost, pollUrl, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", suite.stream.Delivery.PollTransmitMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err := suite.instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func (suite *PollBehaviorSuite) TestPollPausedModeWithAcks() {
	t := suite.T()
	suite.T().Setenv("POLL_SRV_BEHAVIOR", "MODE")

	// Set stream to paused
	suite.instance.UpdateStreamStatus(suite.stream.Id, model.StreamStatePause, "Testing pause")
	// Update router's view of the stream
	state, err := suite.instance.GetStreamState(suite.stream.Id)
	assert.NoError(suite.T(), err)
	suite.instance.app.EventRouter.UpdateStreamState(state)

	// Poll with an ACK (even if JTI is fake, it should trigger the 200 response instead of 503)
	pollParams := model.PollParameters{
		ReturnImmediately: true,
		Acks:              []string{"fake-jti"},
	}
	bodyBytes, _ := json.Marshal(pollParams)
	pollUrl := suite.instance.GetPollUrl(suite.stream)
	req, _ := http.NewRequest(http.MethodPost, pollUrl, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", suite.stream.Delivery.PollTransmitMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err := suite.instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var pollResp model.PollResponse
	_ = json.NewDecoder(resp.Body).Decode(&pollResp)
	assert.Empty(t, pollResp.Sets)
}

func (suite *PollBehaviorSuite) TestPollDisabledModeWithAcks() {
	t := suite.T()
	suite.T().Setenv("POLL_SRV_BEHAVIOR", "MODE")

	// Set stream to disabled
	suite.instance.UpdateStreamStatus(suite.stream.Id, model.StreamStateDisable, "Testing disable")
	// Update router's view of the stream
	state, err := suite.instance.GetStreamState(suite.stream.Id)
	assert.NoError(suite.T(), err)
	suite.instance.app.EventRouter.UpdateStreamState(state)

	// Poll with an ACK (should trigger 200 instead of 403)
	pollParams := model.PollParameters{
		ReturnImmediately: true,
		Acks:              []string{"fake-jti-disabled"},
	}
	bodyBytes, _ := json.Marshal(pollParams)
	pollUrl := suite.instance.GetPollUrl(suite.stream)
	req, _ := http.NewRequest(http.MethodPost, pollUrl, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", suite.stream.Delivery.PollTransmitMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err := suite.instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func (suite *PollBehaviorSuite) TestPollSetErrsProcessing() {
	t := suite.T()
	suite.T().Setenv("POLL_SRV_BEHAVIOR", "MODE")

	// Ensure stream is enabled
	suite.instance.UpdateStreamStatus(suite.stream.Id, model.StreamStateEnabled, "")
	state, err := suite.instance.GetStreamState(suite.stream.Id)
	assert.NoError(suite.T(), err)
	suite.instance.app.EventRouter.UpdateStreamState(state)

	// 1. Add an event
	sub := &goSet.EventSubject{
		SubjectIdentifier: *goSet.NewScimSubjectIdentifier("user-123"),
	}
	set := goSet.CreateSet(sub, suite.stream.Iss, suite.stream.Aud)
	set.AddEventPayload("https://schemas.openid.net/secevent/risc/event-type/account-disabled", map[string]interface{}{
		"reason": "test error",
	})
	jti := set.ID
	err = suite.instance.app.EventRouter.HandleEvent(&set, "", suite.stream.Id)
	assert.NoError(t, err)

	// 2. Poll it
	pollParams := model.PollParameters{ReturnImmediately: true}
	bodyBytes, _ := json.Marshal(pollParams)
	pollUrl := suite.instance.GetPollUrl(suite.stream)
	req, _ := http.NewRequest(http.MethodPost, pollUrl, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", suite.stream.Delivery.PollTransmitMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err := suite.instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var pollResp model.PollResponse
	_ = json.NewDecoder(resp.Body).Decode(&pollResp)
	assert.Contains(t, pollResp.Sets, jti)

	// 3. Send SetErr for this JTI
	pollParamsErr := model.PollParameters{
		ReturnImmediately: true,
		SetErrs: map[string]model.SetErrorType{
			jti: {Error: "invalid_request", Description: "test error"},
		},
	}
	bodyBytes, _ = json.Marshal(pollParamsErr)
	req, _ = http.NewRequest(http.MethodPost, pollUrl, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", suite.stream.Delivery.PollTransmitMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err = suite.instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// 4. Poll again - event should NOT be returned (removed from buffer)
	pollParamsFinal := model.PollParameters{ReturnImmediately: true}
	bodyBytes, _ = json.Marshal(pollParamsFinal)
	req, _ = http.NewRequest(http.MethodPost, pollUrl, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", suite.stream.Delivery.PollTransmitMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err = suite.instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var pollRespFinal model.PollResponse
	_ = json.NewDecoder(resp.Body).Decode(&pollRespFinal)
	assert.NotContains(t, pollRespFinal.Sets, jti, "Event reported with SetErr should be removed from buffer")
}

func (suite *PollBehaviorSuite) TestPollPausedWithSetErrs() {
	t := suite.T()
	suite.T().Setenv("POLL_SRV_BEHAVIOR", "MODE")

	// Set stream to paused
	suite.instance.UpdateStreamStatus(suite.stream.Id, model.StreamStatePause, "Testing pause")
	state, err := suite.instance.GetStreamState(suite.stream.Id)
	assert.NoError(suite.T(), err)
	suite.instance.app.EventRouter.UpdateStreamState(state)

	// Poll with a SetErr
	pollParams := model.PollParameters{
		ReturnImmediately: true,
		SetErrs: map[string]model.SetErrorType{
			"some-jti": {Error: "invalid_request", Description: "test"},
		},
	}
	bodyBytes, _ := json.Marshal(pollParams)
	pollUrl := suite.instance.GetPollUrl(suite.stream)
	req, _ := http.NewRequest(http.MethodPost, pollUrl, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", suite.stream.Delivery.PollTransmitMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err := suite.instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Should return 200 OK when SetErrs are present even if PAUSED")
}

func (suite *PollBehaviorSuite) TestPollDisabledWithSetErrs() {
	t := suite.T()
	suite.T().Setenv("POLL_SRV_BEHAVIOR", "MODE")

	// Set stream to disabled
	suite.instance.UpdateStreamStatus(suite.stream.Id, model.StreamStateDisable, "Testing disable")
	state, err := suite.instance.GetStreamState(suite.stream.Id)
	assert.NoError(suite.T(), err)
	suite.instance.app.EventRouter.UpdateStreamState(state)

	// Poll with a SetErr
	pollParams := model.PollParameters{
		ReturnImmediately: true,
		SetErrs: map[string]model.SetErrorType{
			"some-jti": {Error: "invalid_request", Description: "test"},
		},
	}
	bodyBytes, _ := json.Marshal(pollParams)
	pollUrl := suite.instance.GetPollUrl(suite.stream)
	req, _ := http.NewRequest(http.MethodPost, pollUrl, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", suite.stream.Delivery.PollTransmitMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err := suite.instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Should return 200 OK when SetErrs are present even if DISABLED")
}

func (suite *PollBehaviorSuite) TestPollAlwaysOnDisabled() {
	t := suite.T()
	suite.T().Setenv("POLL_SRV_BEHAVIOR", "ALWAYSON")

	// Set stream to disabled
	suite.instance.UpdateStreamStatus(suite.stream.Id, model.StreamStateDisable, "Testing disable")
	// Update router's view of the stream
	state, err := suite.instance.GetStreamState(suite.stream.Id)
	assert.NoError(suite.T(), err)
	suite.instance.app.EventRouter.UpdateStreamState(state)

	pollParams := model.PollParameters{ReturnImmediately: true}
	bodyBytes, _ := json.Marshal(pollParams)
	pollUrl := suite.instance.GetPollUrl(suite.stream)
	req, _ := http.NewRequest(http.MethodPost, pollUrl, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", suite.stream.Delivery.PollTransmitMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err := suite.instance.client.Do(req)
	assert.NoError(t, err)
	// In ALWAYSON and DISABLED, it should behave like PAUSED -> return 503 if no acks
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func (suite *PollBehaviorSuite) TestReceiverHandles403() {
	t := suite.T()

	// Mock a transmitter that returns 403
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	// Create a polling receiver stream pointing to our mock transmitter
	streamConfig := model.StreamConfiguration{
		Id:            "transmitter-403",
		Iss:           "transmitter-403.example.com",
		IssuerJWKSUrl: ts.URL + "/jwks",
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{
				Method:      model.ReceivePoll,
				EndpointUrl: ts.URL + "/poll",
				PollConfig:  &model.PollParameters{},
			},
		},
	}

	createdConfig, err := suite.instance.CreateStream(streamConfig, authUtil.ConvertProject(suite.instance.projectId))
	assert.NoError(t, err)
	state, _ := suite.instance.GetStreamState(createdConfig.Id)

	// Start receiver
	ps := suite.instance.app.HandleReceiver(state)
	assert.NotNil(t, ps)

	// Wait for receiver to poll and get 403
	time.Sleep(500 * time.Millisecond)

	// Check if stream is now DISABLED in provider
	updatedState, _ := suite.instance.GetStreamState(createdConfig.Id)
	assert.Equal(t, model.StreamStateDisable, updatedState.Status)
	assert.Contains(t, updatedState.ErrorMsg, "Stream disabled by transmitter")
}
