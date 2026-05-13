package test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type PollStateChangeSuite struct {
	suite.Suite
	instance *ssfInstance
	stream   model.StreamConfiguration
}

func (suite *PollStateChangeSuite) SetupSuite() {
	instance, err := createServer(suite.T(), "poll_state_change_test", true)
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

func (suite *PollStateChangeSuite) TearDownSuite() {
	if suite.instance != nil {
		suite.instance.app.Shutdown()
		suite.instance.ts.Close()
	}
}

func TestPollStateChangeSuite(t *testing.T) {
	suite.Run(t, new(PollStateChangeSuite))
}

func (suite *PollStateChangeSuite) TestPollTerminatesOnPause() {
	t := suite.T()

	// Ensure stream is enabled
	state, err := suite.instance.GetStreamState(suite.stream.Id)
	assert.NoError(t, err)
	state.Status = model.StreamStateEnabled
	suite.instance.app.EventRouter.UpdateStreamState(state)

	// Make a long poll request (ReturnImmediately=false)
	pollParams := model.PollParameters{
		ReturnImmediately: false,
		MaxEvents:         10,
		TimeoutSecs:       10, // 10 seconds timeout
	}

	bodyBytes, _ := json.Marshal(pollParams)
	pollUrl := suite.instance.GetPollUrl(suite.stream)
	req, _ := http.NewRequest(http.MethodPost, pollUrl, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", suite.stream.Delivery.PollTransmitMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/json")

	// Start timing
	start := time.Now()

	// Channel to receive the response
	respChan := make(chan *http.Response)
	errChan := make(chan error)

	go func() {
		resp, err := suite.instance.client.Do(req)
		if err != nil {
			errChan <- err
		} else {
			respChan <- resp
		}
	}()

	// Wait a bit to ensure it's blocked
	time.Sleep(1 * time.Second)

	// Now update the stream status to paused
	state, err = suite.instance.GetStreamState(suite.stream.Id)
	assert.NoError(t, err)
	state.Status = model.StreamStatePause
	suite.instance.app.EventRouter.UpdateStreamState(state)

	// Wait for the response
	select {
	case resp := <-respChan:
		elapsed := time.Since(start)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var pollResp model.PollResponse
		body, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		_ = json.Unmarshal(body, &pollResp)

		assert.Empty(t, pollResp.Sets)
		assert.Less(t, elapsed, 5*time.Second, "Long poll should have returned early due to pause")
	case err := <-errChan:
		t.Fatalf("Request failed: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("Timeout waiting for poll to return after pause")
	}
}

func (suite *PollStateChangeSuite) TestPollTerminatesOnDisable() {
	t := suite.T()

	// Re-enable the stream first
	state, err := suite.instance.GetStreamState(suite.stream.Id)
	assert.NoError(t, err)
	state.Status = model.StreamStateEnabled
	suite.instance.app.EventRouter.UpdateStreamState(state)

	// Make a long poll request
	pollParams := model.PollParameters{
		ReturnImmediately: false,
		MaxEvents:         10,
		TimeoutSecs:       10,
	}

	bodyBytes, _ := json.Marshal(pollParams)
	pollUrl := suite.instance.GetPollUrl(suite.stream)
	req, _ := http.NewRequest(http.MethodPost, pollUrl, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", suite.stream.Delivery.PollTransmitMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	respChan := make(chan *http.Response)
	errChan := make(chan error)

	go func() {
		resp, err := suite.instance.client.Do(req)
		if err != nil {
			errChan <- err
		} else {
			respChan <- resp
		}
	}()

	time.Sleep(1 * time.Second)

	// Now update the stream status to disabled
	state, err = suite.instance.GetStreamState(suite.stream.Id)
	assert.NoError(t, err)
	state.Status = model.StreamStateDisable
	suite.instance.app.EventRouter.UpdateStreamState(state)

	select {
	case resp := <-respChan:
		elapsed := time.Since(start)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Less(t, elapsed, 5*time.Second, "Long poll should have returned early due to disable")
	case err := <-errChan:
		t.Fatalf("Request failed: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("Timeout waiting for poll to return after disable")
	}
}
