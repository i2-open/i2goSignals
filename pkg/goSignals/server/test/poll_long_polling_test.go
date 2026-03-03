package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type LongPollSuite struct {
	suite.Suite
	instance *ssfInstance
	stream   model.StreamConfiguration
}

func (suite *LongPollSuite) SetupSuite() {
	instance, err := createServer(suite.T(), "long_poll_test", true)
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

	stream, _ := instance.provider.CreateStream(streamConfig, instance.projectId)
	state, _ := instance.provider.GetStreamState(stream.Id)
	instance.app.EventRouter.UpdateStreamState(state)

	suite.stream = stream
}

func (suite *LongPollSuite) TearDownSuite() {
	if suite.instance != nil {
		suite.instance.app.Shutdown()
		suite.instance.ts.Close()
	}
}

func (suite *LongPollSuite) TearDownTest() {
	if suite.instance != nil && suite.instance.app.EventRouter != nil {
		suite.instance.app.EventRouter.ResetStream(suite.stream.Id)
	}
}

func TestLongPollSuite(t *testing.T) {
	suite.Run(t, new(LongPollSuite))
}

// TestLongPollingWithTimeout tests ReturnImmediately=false with timeout per RFC8936
func (suite *LongPollSuite) TestLongPollingWithTimeout() {
	t := suite.T()

	// Make a long poll request (ReturnImmediately=false)
	pollParams := model.PollParameters{
		ReturnImmediately: false,
		MaxEvents:         10,
		TimeoutSecs:       2,
	}

	bodyBytes, _ := json.Marshal(pollParams)
	pollUrl := suite.instance.ts.URL + suite.stream.Delivery.PollTransmitMethod.EndpointUrl
	req, _ := http.NewRequest(http.MethodPost, pollUrl, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", suite.stream.Delivery.PollTransmitMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/json")

	// Start timing
	start := time.Now()

	resp, err := suite.instance.client.Do(req)
	assert.NoError(t, err)

	elapsed := time.Since(start)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var pollResp model.PollResponse
	body, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &pollResp)

	// Should return empty sets since no events were added
	assert.Empty(t, pollResp.Sets)
	assert.False(t, pollResp.MoreAvailable)

	// Should have waited (timeout), check elapsed time is reasonable (at least 1 second)
	// The default timeout in PollStreamHandler is typically 10 seconds or configurable
	assert.Greater(t, elapsed, 1*time.Second, "Long poll should wait before returning")
}

// TestMaxEventsLimit tests the MaxEvents parameter per RFC8936
func (suite *LongPollSuite) TestMaxEventsLimit() {
	t := suite.T()

	// Generate multiple events
	numEvents := 15
	for i := 0; i < numEvents; i++ {
		subject := &goSet.EventSubject{
			SubjectIdentifier: *goSet.NewScimSubjectIdentifier(fmt.Sprintf("/Users/maxevents-%d", i)),
		}
		set := goSet.CreateSet(subject, suite.stream.Iss, suite.stream.Aud)
		set.AddEventPayload("https://schemas.openid.net/secevent/risc/event-type/account-disabled", map[string]interface{}{
			"reason": fmt.Sprintf("test event %d", i),
		})
		_ = suite.instance.app.EventRouter.HandleEvent(&set, "", suite.stream.Id)
	}

	// Wait for events to be queued
	time.Sleep(100 * time.Millisecond)

	// Poll with MaxEvents=5
	pollParams := model.PollParameters{
		ReturnImmediately: true,
		MaxEvents:         5,
	}

	bodyBytes, _ := json.Marshal(pollParams)
	pollUrl := suite.instance.ts.URL + suite.stream.Delivery.PollTransmitMethod.EndpointUrl
	req, _ := http.NewRequest(http.MethodPost, pollUrl, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", suite.stream.Delivery.PollTransmitMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err := suite.instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var pollResp model.PollResponse
	body, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &pollResp)

	// Should return at most 5 events
	assert.LessOrEqual(t, len(pollResp.Sets), 5, "MaxEvents should limit returned SETs")
	assert.True(t, pollResp.MoreAvailable, "MoreAvailable should be true when events remain")
}

// TestCombinedAckAndPoll tests acknowledgement combined with polling per RFC8936
func (suite *LongPollSuite) TestCombinedAckAndPoll() {
	t := suite.T()

	// Generate an event
	subject := &goSet.EventSubject{
		SubjectIdentifier: *goSet.NewScimSubjectIdentifier("/Users/ackpoll-test"),
	}
	set := goSet.CreateSet(subject, suite.stream.Iss, suite.stream.Aud)
	set.AddEventPayload("https://schemas.openid.net/secevent/risc/event-type/account-disabled", map[string]interface{}{
		"reason": "ack test",
	})
	_ = suite.instance.app.EventRouter.HandleEvent(&set, "", suite.stream.Id)

	time.Sleep(100 * time.Millisecond)

	// First poll to get the event
	pollParams := model.PollParameters{
		ReturnImmediately: true,
		MaxEvents:         10,
	}

	bodyBytes, _ := json.Marshal(pollParams)
	pollUrl := suite.instance.ts.URL + suite.stream.Delivery.PollTransmitMethod.EndpointUrl
	req, _ := http.NewRequest(http.MethodPost, pollUrl, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", suite.stream.Delivery.PollTransmitMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err := suite.instance.client.Do(req)
	assert.NoError(t, err)

	var pollResp model.PollResponse
	body, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &pollResp)

	assert.NotEmpty(t, pollResp.Sets)
	jti := ""
	for j := range pollResp.Sets {
		jti = j
		break
	}

	// Generate another event
	subject2 := &goSet.EventSubject{
		SubjectIdentifier: *goSet.NewScimSubjectIdentifier("/Users/ackpoll-test2"),
	}
	set2 := goSet.CreateSet(subject2, suite.stream.Iss, suite.stream.Aud)
	set2.AddEventPayload("https://schemas.openid.net/secevent/risc/event-type/account-disabled", map[string]interface{}{
		"reason": "ack test 2",
	})
	_ = suite.instance.app.EventRouter.HandleEvent(&set2, "", suite.stream.Id)

	time.Sleep(100 * time.Millisecond)

	// Combined ACK + Poll: acknowledge first event and poll for new ones
	pollParams2 := model.PollParameters{
		ReturnImmediately: true,
		MaxEvents:         10,
		Acks:              []string{jti},
	}

	bodyBytes, _ = json.Marshal(pollParams2)
	pollUrl = suite.instance.ts.URL + suite.stream.Delivery.PollTransmitMethod.EndpointUrl
	req, _ = http.NewRequest(http.MethodPost, pollUrl, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", suite.stream.Delivery.PollTransmitMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err = suite.instance.client.Do(req)
	assert.NoError(t, err)

	var pollResp2 model.PollResponse
	body, _ = io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &pollResp2)

	// Should return the second event
	assert.NotEmpty(t, pollResp2.Sets)
	// The first event should not be returned again
	_, exists := pollResp2.Sets[jti]
	assert.False(t, exists, "Acknowledged event should not be returned")
}

// TestAcknowledgeOnly tests acknowledge-only request per RFC8936
func (suite *LongPollSuite) TestAcknowledgeOnly() {
	t := suite.T()

	// Generate an event
	subject := &goSet.EventSubject{
		SubjectIdentifier: *goSet.NewScimSubjectIdentifier("/Users/ackonly-test"),
	}
	set := goSet.CreateSet(subject, suite.stream.Iss, suite.stream.Aud)
	set.AddEventPayload("https://schemas.openid.net/secevent/risc/event-type/account-disabled", map[string]interface{}{
		"reason": "ack only test",
	})
	_ = suite.instance.app.EventRouter.HandleEvent(&set, "", suite.stream.Id)

	time.Sleep(100 * time.Millisecond)

	// First poll to get the event
	pollParams := model.PollParameters{
		ReturnImmediately: true,
		MaxEvents:         10,
	}

	bodyBytes, _ := json.Marshal(pollParams)
	pollUrl := suite.instance.ts.URL + suite.stream.Delivery.PollTransmitMethod.EndpointUrl
	req, _ := http.NewRequest(http.MethodPost, pollUrl, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", suite.stream.Delivery.PollTransmitMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err := suite.instance.client.Do(req)
	assert.NoError(t, err)

	var pollResp model.PollResponse
	body, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &pollResp)

	assert.NotEmpty(t, pollResp.Sets)
	jti := ""
	for j := range pollResp.Sets {
		jti = j
		break
	}

	// Acknowledge-only request (no new events to poll)
	pollParams2 := model.PollParameters{
		ReturnImmediately: true,
		MaxEvents:         10,
		Acks:              []string{jti},
	}

	bodyBytes, _ = json.Marshal(pollParams2)
	pollUrl = suite.instance.ts.URL + suite.stream.Delivery.PollTransmitMethod.EndpointUrl
	req, _ = http.NewRequest(http.MethodPost, pollUrl, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", suite.stream.Delivery.PollTransmitMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err = suite.instance.client.Do(req)
	assert.NoError(t, err)

	var pollResp2 model.PollResponse
	body, _ = io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &pollResp2)

	// Should return empty sets (acknowledge only)
	assert.Empty(t, pollResp2.Sets)
	assert.False(t, pollResp2.MoreAvailable)

	// Verify event was acknowledged (should not be returned in subsequent polls)
	pollParams3 := model.PollParameters{
		ReturnImmediately: true,
		MaxEvents:         10,
	}

	bodyBytes, _ = json.Marshal(pollParams3)
	pollUrl = suite.instance.ts.URL + suite.stream.Delivery.PollTransmitMethod.EndpointUrl
	req, _ = http.NewRequest(http.MethodPost, pollUrl, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", suite.stream.Delivery.PollTransmitMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err = suite.instance.client.Do(req)
	assert.NoError(t, err)

	var pollResp3 model.PollResponse
	body, _ = io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &pollResp3)

	_, exists := pollResp3.Sets[jti]
	assert.False(t, exists, "Acknowledged event should not be returned again")
}

// TestSetErrsReporting tests error reporting from receiver per RFC8936
func (suite *LongPollSuite) TestSetErrsReporting() {
	t := suite.T()

	// Generate an event
	subject := &goSet.EventSubject{
		SubjectIdentifier: *goSet.NewScimSubjectIdentifier("/Users/seterrs-test"),
	}
	set := goSet.CreateSet(subject, suite.stream.Iss, suite.stream.Aud)
	set.AddEventPayload("https://schemas.openid.net/secevent/risc/event-type/account-disabled", map[string]interface{}{
		"reason": "seterrs test",
	})
	_ = suite.instance.app.EventRouter.HandleEvent(&set, "", suite.stream.Id)

	time.Sleep(100 * time.Millisecond)

	// First poll to get the event
	pollParams := model.PollParameters{
		ReturnImmediately: true,
		MaxEvents:         10,
	}

	bodyBytes, _ := json.Marshal(pollParams)
	pollUrl := suite.instance.ts.URL + suite.stream.Delivery.PollTransmitMethod.EndpointUrl
	req, _ := http.NewRequest(http.MethodPost, pollUrl, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", suite.stream.Delivery.PollTransmitMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err := suite.instance.client.Do(req)
	assert.NoError(t, err)

	var pollResp model.PollResponse
	body, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &pollResp)

	assert.NotEmpty(t, pollResp.Sets)
	jti := ""
	for j := range pollResp.Sets {
		jti = j
		break
	}

	// Report error for this SET
	setErrs := make(map[string]model.SetErrorType)
	setErrs[jti] = model.SetErrorType{
		Error:       "invalid_request",
		Description: "Test error reporting",
	}

	pollParams2 := model.PollParameters{
		ReturnImmediately: true,
		MaxEvents:         10,
		SetErrs:           setErrs,
	}

	bodyBytes, _ = json.Marshal(pollParams2)
	pollUrl = suite.instance.ts.URL + suite.stream.Delivery.PollTransmitMethod.EndpointUrl
	req, _ = http.NewRequest(http.MethodPost, pollUrl, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", suite.stream.Delivery.PollTransmitMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err = suite.instance.client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Server should log the error (can't easily verify in test, but should not crash)
	// The event should be removed from the buffer (processed) per RFC8936
	pollParams3 := model.PollParameters{
		ReturnImmediately: true,
		MaxEvents:         10,
	}

	bodyBytes, _ = json.Marshal(pollParams3)
	pollUrl = suite.instance.ts.URL + suite.stream.Delivery.PollTransmitMethod.EndpointUrl
	req, _ = http.NewRequest(http.MethodPost, pollUrl, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", suite.stream.Delivery.PollTransmitMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err = suite.instance.client.Do(req)
	assert.NoError(t, err)

	var pollResp3 model.PollResponse
	body, _ = io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &pollResp3)

	// Event should NO LONGER be available (errors cause removal from buffer)
	_, exists := pollResp3.Sets[jti]
	assert.False(t, exists, "Event with error should be removed from buffer")
}

// TestPollAuthorizationFailure tests authorization failures per RFC8936
func (suite *LongPollSuite) TestPollAuthorizationFailure() {
	t := suite.T()

	// Test 1: No authorization header
	pollParams := model.PollParameters{
		ReturnImmediately: true,
	}

	bodyBytes, _ := json.Marshal(pollParams)
	pollUrl := suite.instance.ts.URL + suite.stream.Delivery.PollTransmitMethod.EndpointUrl
	req, _ := http.NewRequest(http.MethodPost, pollUrl, bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	resp, err := suite.instance.client.Do(req)
	assert.NoError(t, err)
	assert.NotEqual(t, http.StatusOK, resp.StatusCode, "Should fail without authorization")

	// Test 2: Invalid authorization token
	pollUrl = suite.instance.ts.URL + suite.stream.Delivery.PollTransmitMethod.EndpointUrl
	req, _ = http.NewRequest(http.MethodPost, pollUrl, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer invalid-token")
	req.Header.Set("Content-Type", "application/json")

	resp, err = suite.instance.client.Do(req)
	assert.NoError(t, err)
	assert.NotEqual(t, http.StatusOK, resp.StatusCode, "Should fail with invalid token")
}

// TestConcurrentLongPolls tests multiple concurrent long poll requests
func (suite *LongPollSuite) TestConcurrentLongPolls() {
	t := suite.T()

	var wg sync.WaitGroup
	numPollers := 3

	for i := 0; i < numPollers; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			pollParams := model.PollParameters{
				ReturnImmediately: false,
				MaxEvents:         5,
			}

			bodyBytes, _ := json.Marshal(pollParams)
			pollUrl := suite.instance.ts.URL + suite.stream.Delivery.PollTransmitMethod.EndpointUrl
			req, _ := http.NewRequest(http.MethodPost, pollUrl, bytes.NewReader(bodyBytes))
			req.Header.Set("Authorization", suite.stream.Delivery.PollTransmitMethod.AuthorizationHeader)
			req.Header.Set("Content-Type", "application/json")

			start := time.Now()
			resp, err := suite.instance.client.Do(req)
			elapsed := time.Since(start)

			assert.NoError(t, err, fmt.Sprintf("Poller %d failed", index))
			if resp != nil {
				assert.Equal(t, http.StatusOK, resp.StatusCode, fmt.Sprintf("Poller %d got wrong status", index))
			}
			assert.Greater(t, elapsed, 500*time.Millisecond, fmt.Sprintf("Poller %d didn't wait", index))
		}(i)
	}

	// Wait a bit, then generate an event
	time.Sleep(2 * time.Second)

	subject := &goSet.EventSubject{
		SubjectIdentifier: *goSet.NewScimSubjectIdentifier("/Users/concurrent-test"),
	}
	set := goSet.CreateSet(subject, suite.stream.Iss, suite.stream.Aud)
	set.AddEventPayload("https://schemas.openid.net/secevent/risc/event-type/account-disabled", map[string]interface{}{
		"reason": "concurrent test",
	})
	_ = suite.instance.app.EventRouter.HandleEvent(&set, "", suite.stream.Id)

	// Wait for all pollers to complete
	wg.Wait()
}
