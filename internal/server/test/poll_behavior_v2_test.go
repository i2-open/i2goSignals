package test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
	suite.T().Setenv("I2SIG_POLL_RESPECT_STATUS", "true")

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
	suite.T().Setenv("I2SIG_POLL_RESPECT_STATUS", "true")

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
	suite.T().Setenv("I2SIG_POLL_RESPECT_STATUS", "true")

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
	suite.T().Setenv("I2SIG_POLL_RESPECT_STATUS", "true")

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
	suite.T().Setenv("I2SIG_POLL_RESPECT_STATUS", "true")

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
	suite.T().Setenv("I2SIG_POLL_RESPECT_STATUS", "true")

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
	suite.T().Setenv("I2SIG_POLL_RESPECT_STATUS", "true")

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
	suite.T().Setenv("I2SIG_POLL_RESPECT_STATUS", "false")

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

// Slice #68 regression: confirms the legacy POLL_SRV_BEHAVIOR=MODE and
// POLL_SRV_BEHAVIOR=ALWAYSON values translate to the same poll-transmitter
// behavior as the new boolean I2SIG_POLL_RESPECT_STATUS=true / false. Both
// configurations are exercised against the same disabled stream and must
// produce identical HTTP status codes.
func (suite *PollBehaviorSuite) TestPollSrvBehavior_LegacyTranslation() {
	t := suite.T()

	suite.instance.UpdateStreamStatus(suite.stream.Id, model.StreamStateDisable, "Testing legacy translation")
	state, err := suite.instance.GetStreamState(suite.stream.Id)
	assert.NoError(t, err)
	suite.instance.app.EventRouter.UpdateStreamState(state)

	doPoll := func() int {
		pollParams := model.PollParameters{ReturnImmediately: true}
		bodyBytes, _ := json.Marshal(pollParams)
		pollUrl := suite.instance.GetPollUrl(suite.stream)
		req, _ := http.NewRequest(http.MethodPost, pollUrl, bytes.NewReader(bodyBytes))
		req.Header.Set("Authorization", suite.stream.Delivery.PollTransmitMethod.AuthorizationHeader)
		req.Header.Set("Content-Type", "application/json")
		resp, err := suite.instance.client.Do(req)
		assert.NoError(t, err)
		return resp.StatusCode
	}

	// MODE → respect status: a DISABLED stream returns 403.
	suite.T().Setenv("I2SIG_POLL_RESPECT_STATUS", "")
	suite.T().Setenv("POLL_SRV_BEHAVIOR", "MODE")
	legacyMode := doPoll()
	suite.T().Setenv("POLL_SRV_BEHAVIOR", "")
	suite.T().Setenv("I2SIG_POLL_RESPECT_STATUS", "true")
	newTrue := doPoll()
	assert.Equal(t, legacyMode, newTrue, "POLL_SRV_BEHAVIOR=MODE must match I2SIG_POLL_RESPECT_STATUS=true")
	assert.Equal(t, http.StatusForbidden, legacyMode)

	// ALWAYSON → do not respect status: a DISABLED stream is treated as PAUSED → 503.
	suite.T().Setenv("I2SIG_POLL_RESPECT_STATUS", "")
	suite.T().Setenv("POLL_SRV_BEHAVIOR", "ALWAYSON")
	legacyAlwayson := doPoll()
	suite.T().Setenv("POLL_SRV_BEHAVIOR", "")
	suite.T().Setenv("I2SIG_POLL_RESPECT_STATUS", "false")
	newFalse := doPoll()
	assert.Equal(t, legacyAlwayson, newFalse, "POLL_SRV_BEHAVIOR=ALWAYSON must match I2SIG_POLL_RESPECT_STATUS=false")
	assert.Equal(t, http.StatusServiceUnavailable, legacyAlwayson)
}

func (suite *PollBehaviorSuite) TestReceiverHandles403() {
	t := suite.T()

	// With the bounded-403-retry behavior the first 403 no longer disables the
	// stream. Pin the retry limit to 1 so this test still exercises the
	// terminal-disable path.
	t.Setenv("I2SIG_POLL_FORBIDDEN_RETRY_LIMIT", "1")

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
	assert.Contains(t, updatedState.ErrorMsg, "Stream disabled after")
	assert.Contains(t, updatedState.ErrorMsg, "forbidden (403)")
}

func (suite *PollBehaviorSuite) TestReceiverRetriesOn403BeforeDisable() {
	t := suite.T()

	// Allow up to 3 forbidden attempts before disabling. With a short delay
	// and backoff factor, the test should observe at least one paused state
	// before the stream is ultimately disabled.
	t.Setenv("I2SIG_POLL_FORBIDDEN_RETRY_DELAY", "0.05") // 50ms base
	t.Setenv("I2SIG_POLL_FORBIDDEN_RETRY_LIMIT", "3")
	t.Setenv("I2SIG_POLL_RETRY_BACKOFF_FACTOR", "1.0") // disable exponential growth for predictability
	t.Setenv("I2SIG_POLL_RETRY_MAX_DELAY", "1.0")     // cap

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	streamConfig := model.StreamConfiguration{
		Id:            "transmitter-403-retry",
		Iss:           "transmitter-403-retry.example.com",
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

	ps := suite.instance.app.HandleReceiver(state)
	assert.NotNil(t, ps)

	// Within the first ~100ms we should see at least one retry (status paused
	// with a retry-attempt message), well before the limit of 3 is reached.
	sawPause := false
	for i := 0; i < 20; i++ {
		time.Sleep(25 * time.Millisecond)
		updatedState, _ := suite.instance.GetStreamState(createdConfig.Id)
		if updatedState != nil && updatedState.Status == model.StreamStatePause &&
			strings.Contains(updatedState.ErrorMsg, "forbidden response (403), retrying") {
			sawPause = true
			break
		}
	}
	assert.True(t, sawPause, "expected to observe a paused state with a 403 retry message during retries")

	// Eventually the stream must end up DISABLED with the diagnostic message.
	var finalState *model.StreamStateRecord
	for i := 0; i < 40; i++ {
		time.Sleep(50 * time.Millisecond)
		finalState, _ = suite.instance.GetStreamState(createdConfig.Id)
		if finalState != nil && finalState.Status == model.StreamStateDisable {
			break
		}
	}
	assert.NotNil(t, finalState)
	assert.Equal(t, model.StreamStateDisable, finalState.Status)
	assert.Contains(t, finalState.ErrorMsg, "Stream disabled after 3 forbidden (403)")
	assert.Contains(t, finalState.ErrorMsg, "scope")
}

