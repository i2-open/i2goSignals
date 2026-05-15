package test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type RemoteAddressSuite struct {
	suite.Suite
	instance   *ssfInstance
	pushStream model.StreamConfiguration
	pollStream model.StreamConfiguration
}

func (suite *RemoteAddressSuite) SetupSuite() {
	instance, err := createServer(suite.T(), "remote_address_test", true)
	assert.NoError(suite.T(), err)
	suite.instance = instance

	// Push receiver stream for inbound push tests
	pushConfig := model.StreamConfiguration{
		Iss:             "DEFAULT",
		Aud:             []string{"https://receiver.example.com"},
		EventsSupported: []string{"*"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PushReceiveMethod: &model.PushReceiveMethod{
				Method: model.ReceivePush,
			},
		},
		RouteMode: model.RouteModeImport,
	}
	body, _ := json.Marshal(pushConfig)
	req, _ := http.NewRequest(http.MethodPost, instance.ts.URL+"/stream", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+instance.streamMgmtToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := instance.client.Do(req)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusCreated, resp.StatusCode)
	var created model.StreamConfiguration
	_ = json.NewDecoder(resp.Body).Decode(&created)
	suite.pushStream = created

	// Poll transmitter stream for inbound poll tests
	pollConfig := model.StreamConfiguration{
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
	body, _ = json.Marshal(pollConfig)
	req, _ = http.NewRequest(http.MethodPost, instance.ts.URL+"/stream", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+instance.streamMgmtToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err = instance.client.Do(req)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusCreated, resp.StatusCode)
	var createdPoll model.StreamConfiguration
	_ = json.NewDecoder(resp.Body).Decode(&createdPoll)
	suite.pollStream = createdPoll
}

func (suite *RemoteAddressSuite) TearDownSuite() {
	if suite.instance != nil {
		suite.instance.app.Shutdown()
		suite.instance.ts.Close()
	}
}

func TestRemoteAddressSuite(t *testing.T) {
	suite.Run(t, new(RemoteAddressSuite))
}

// sendValidPush signs a SET with the DEFAULT key and POSTs it to the stream's push endpoint.
func (suite *RemoteAddressSuite) sendValidPush(stream model.StreamConfiguration, extraHeaders map[string]string) *http.Response {
	subject := &goSet.EventSubject{
		SubjectIdentifier: goSet.SubjectIdentifier{
			Format:                    "scim",
			UniformResourceIdentifier: goSet.UniformResourceIdentifier{Uri: "/Users/remote-addr-test"},
		},
	}
	set := goSet.CreateSet(subject, stream.Iss, stream.Aud)
	set.AddEventPayload("https://schemas.openid.net/secevent/risc/event-type/account-disabled", map[string]interface{}{})
	privKey, _ := suite.instance.GetPrivateKey("DEFAULT")
	tokenString, _ := set.JWS(jwt.SigningMethodRS256, privKey)

	endpoint := suite.instance.GetPushUrl(stream)
	req, _ := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(tokenString))
	req.Header.Set("Authorization", stream.Delivery.PushReceiveMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/secevent+jwt")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	resp, _ := suite.instance.client.Do(req)
	return resp
}

// TestInboundPushPopulatesRemoteAddress: valid push sets RemoteAddress.IP and Protocol.
func (suite *RemoteAddressSuite) TestInboundPushPopulatesRemoteAddress() {
	t := suite.T()

	resp := suite.sendValidPush(suite.pushStream, nil)
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)

	state, err := suite.instance.GetStreamState(suite.pushStream.Id)
	require.NoError(t, err)
	require.NotNil(t, state.RemoteAddress, "RemoteAddress should be set after successful push")
	assert.NotEmpty(t, state.RemoteAddress.IP, "RemoteAddress.IP should be non-empty")
	assert.Equal(t, "http", state.RemoteAddress.Protocol, "Protocol should be 'http' for plain HTTP")
	assert.Empty(t, state.RemoteAddress.Forwarded, "Forwarded should be empty when no proxy headers")
}

// TestInboundPushXForwardedFor: push with X-Forwarded-For header sets RemoteAddress.Forwarded.
func (suite *RemoteAddressSuite) TestInboundPushXForwardedFor() {
	t := suite.T()

	resp := suite.sendValidPush(suite.pushStream, map[string]string{
		"X-Forwarded-For": "203.0.113.1, 198.51.100.2",
	})
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)

	state, err := suite.instance.GetStreamState(suite.pushStream.Id)
	require.NoError(t, err)
	require.NotNil(t, state.RemoteAddress)
	assert.Equal(t, "203.0.113.1, 198.51.100.2", state.RemoteAddress.Forwarded)
}

// TestInboundPushSamePeerNoChange: two pushes from the same peer leave RemoteAddress.IP unchanged.
func (suite *RemoteAddressSuite) TestInboundPushSamePeerNoChange() {
	t := suite.T()

	suite.sendValidPush(suite.pushStream, nil)

	state1, err := suite.instance.GetStreamState(suite.pushStream.Id)
	require.NoError(t, err)
	require.NotNil(t, state1.RemoteAddress)
	firstIP := state1.RemoteAddress.IP

	suite.sendValidPush(suite.pushStream, nil)

	state2, err := suite.instance.GetStreamState(suite.pushStream.Id)
	require.NoError(t, err)
	require.NotNil(t, state2.RemoteAddress)
	assert.Equal(t, firstIP, state2.RemoteAddress.IP, "RemoteAddress should not change for the same peer")
}

// TestInboundPollPopulatesRemoteAddress: valid poll request sets RemoteAddress.
func (suite *RemoteAddressSuite) TestInboundPollPopulatesRemoteAddress() {
	t := suite.T()

	pollParams := model.PollParameters{ReturnImmediately: true}
	body, _ := json.Marshal(pollParams)
	pollUrl := suite.instance.GetPollUrl(suite.pollStream)
	req, _ := http.NewRequest(http.MethodPost, pollUrl, bytes.NewReader(body))
	req.Header.Set("Authorization", suite.pollStream.Delivery.PollTransmitMethod.AuthorizationHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err := suite.instance.client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	state, err := suite.instance.GetStreamState(suite.pollStream.Id)
	require.NoError(t, err)
	require.NotNil(t, state.RemoteAddress, "RemoteAddress should be set after successful poll")
	assert.NotEmpty(t, state.RemoteAddress.IP)
	assert.Equal(t, "http", state.RemoteAddress.Protocol)
}

// TestOutboundPushCapturesRemoteAddress: after outbound push to mock server, RemoteAddress reflects it.
func (suite *RemoteAddressSuite) TestOutboundPushCapturesRemoteAddress() {
	t := suite.T()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer mockServer.Close()

	streamConfig := model.StreamConfiguration{
		Iss:             suite.instance.app.GetDefIssuer(),
		Aud:             []string{"https://mock-receiver.example.com"},
		EventsSupported: []string{"*"},
		EventsRequested: []string{"*"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PushTransmitMethod: &model.PushTransmitMethod{
				Method:      model.DeliveryPush,
				EndpointUrl: mockServer.URL + "/push",
			},
		},
	}

	atx := authUtil.AuthContext{ProjectId: suite.instance.projectId}
	created, err := suite.instance.CreateStream(streamConfig, &atx)
	require.NoError(t, err)

	state, err := suite.instance.GetStreamState(created.Id)
	require.NoError(t, err)
	suite.instance.app.EventRouter.UpdateStreamState(state)

	subject := &goSet.EventSubject{
		SubjectIdentifier: goSet.SubjectIdentifier{
			Format:                    "scim",
			UniformResourceIdentifier: goSet.UniformResourceIdentifier{Uri: "/Users/outbound-push-test"},
		},
	}
	set := goSet.CreateSet(subject, created.Iss, created.Aud)
	set.AddEventPayload("https://schemas.openid.net/secevent/risc/event-type/account-disabled", map[string]interface{}{})
	err = suite.instance.app.EventRouter.HandleEvent(&set, "", created.Id)
	require.NoError(t, err)

	assert.Eventually(t, func() bool {
		st, e := suite.instance.GetStreamState(created.Id)
		return e == nil && st != nil && st.RemoteAddress != nil && st.RemoteAddress.IP != ""
	}, 3*time.Second, 100*time.Millisecond, "RemoteAddress should be set after outbound push")

	finalState, err := suite.instance.GetStreamState(created.Id)
	require.NoError(t, err)
	require.NotNil(t, finalState.RemoteAddress)
	assert.Contains(t, finalState.RemoteAddress.IP, "127.0.0.1", "Should reflect mock server loopback address")
	assert.Empty(t, finalState.RemoteAddress.Forwarded, "Forwarded should be empty for outbound connections")
}

// TestListStreamStatesReturnsRemoteAddress: GET /states should include remote_address after a push.
func (suite *RemoteAddressSuite) TestListStreamStatesReturnsRemoteAddress() {
	t := suite.T()

	resp := suite.sendValidPush(suite.pushStream, nil)
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)

	state, err := suite.instance.GetStreamState(suite.pushStream.Id)
	require.NoError(t, err)
	require.NotNil(t, state.RemoteAddress, "precondition: provider read should have RemoteAddress")

	listReq, _ := http.NewRequest(http.MethodGet, suite.instance.ts.URL+"/states", nil)
	listReq.Header.Set("Authorization", "Bearer "+suite.instance.streamMgmtToken)
	listResp, err := suite.instance.client.Do(listReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, listResp.StatusCode)

	rawBody, _ := io.ReadAll(listResp.Body)

	var states []map[string]any
	require.NoError(t, json.Unmarshal(rawBody, &states))

	var found map[string]any
	for _, s := range states {
		if s["id"] == suite.pushStream.Id {
			found = s
			break
		}
	}
	require.NotNil(t, found, "stream should appear in /states list")

	remote, ok := found["remote_address"]
	require.True(t, ok, "remote_address key must be present in /states JSON")
	require.NotNil(t, remote, "remote_address should not be nil in /states JSON")
}

// TestOutboundPollCapturesRemoteAddress: after outbound poll from mock transmitter, RemoteAddress reflects it.
func (suite *RemoteAddressSuite) TestOutboundPollCapturesRemoteAddress() {
	t := suite.T()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"sets":{},"moreAvailable":false}`))
	}))
	defer mockServer.Close()

	t.Setenv("I2SIG_POLL_RETRY_BASE_DELAY", "0.05")
	t.Setenv("I2SIG_POLL_RETRY_MAX_DELAY", "0.1")

	streamConfig := model.StreamConfiguration{
		Iss: "mock-transmitter",
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{
				Method:      model.ReceivePoll,
				EndpointUrl: mockServer.URL + "/poll",
				PollConfig: &model.PollParameters{
					ReturnImmediately: true,
				},
			},
		},
	}

	atx := authUtil.AuthContext{ProjectId: suite.instance.projectId}
	created, err := suite.instance.CreateStream(streamConfig, &atx)
	require.NoError(t, err)

	streamState, err := suite.instance.GetStreamState(created.Id)
	require.NoError(t, err)
	ps := suite.instance.app.HandleReceiver(streamState)
	require.NotNil(t, ps)

	assert.Eventually(t, func() bool {
		st, e := suite.instance.GetStreamState(created.Id)
		return e == nil && st != nil && st.RemoteAddress != nil && st.RemoteAddress.IP != ""
	}, 3*time.Second, 100*time.Millisecond, "RemoteAddress should be set after outbound poll")

	finalState, err := suite.instance.GetStreamState(created.Id)
	require.NoError(t, err)
	require.NotNil(t, finalState.RemoteAddress)
	assert.Contains(t, finalState.RemoteAddress.IP, "127.0.0.1", "Should reflect mock server loopback address")
	assert.Empty(t, finalState.RemoteAddress.Forwarded, "Forwarded should be empty for outbound connections")
}
