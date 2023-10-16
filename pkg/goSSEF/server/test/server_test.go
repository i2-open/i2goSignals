package test

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/independentid/i2goSignals/internal/authUtil"
	"github.com/independentid/i2goSignals/internal/model"
	"github.com/independentid/i2goSignals/internal/providers/dbProviders/mongo_provider"
	ssef "github.com/independentid/i2goSignals/pkg/goSSEF/server"
	"github.com/independentid/i2goSignals/pkg/goSet"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

var TestDbUrl = "mongodb://root:dockTest@mongo1:30001,mongo2:30002,mongo3:30003/?retryWrites=true&replicaSet=dbrs&readPreference=primary&serverSelectionTimeoutMS=5000&connectTimeoutMS=10000&authSource=admin&authMechanism=SCRAM-SHA-256"

var testLog = log.New(os.Stdout, "TEST: ", log.Ldate|log.Ltime)

type ssfInstance struct {
	server          *http.Server
	client          *http.Client
	provider        *mongo_provider.MongoProvider
	stream          model.StreamConfiguration
	app             ssef.SignalsApplication
	streamToken     string
	streamMgmtToken string
	iatToken        string
	projectId       string
	startTime       *time.Time
}

type ServerSuite struct {
	suite.Suite
	servers []*ssfInstance
}

func TestServer(t *testing.T) {
	serverSuite := ServerSuite{}

	testLog.Println("NOTE: This test will generate a series of Prometheus duplicate collector registration errors. This is due to the test environment only.")
	instances := make([]*ssfInstance, 2)

	testLog.Println("** Starting SSF1...")
	instance, err := createServer("ssf1")
	if err != nil {
		testLog.Printf("Error starting %s: %s", "ssf1", err.Error())
	}
	assert.NotEqualf(t, instance.projectId, "", "Check project id is not empty")

	instances[0] = instance
	testLog.Println("** Starting SSF2...")
	instance, err = createServer("ssf2")
	if err != nil {
		testLog.Printf("Error starting %s: %s", "ssf2", err.Error())
	}
	instances[1] = instance

	serverSuite.servers = instances
	testLog.Println("** Setup Complete **")

	suite.Run(t, &serverSuite)

	testLog.Println("** Shutting down test servers.. ")
	for i := 1; i > -1; i-- {
		instance := serverSuite.servers[i]
		testLog.Printf("** Shutting down server %s...", instance.provider.Name())
		instance.app.Shutdown()
		time.Sleep(time.Second)
	}
	testLog.Println("** TEST COMPLETE **")
}

func createServer(dbName string) (*ssfInstance, error) {
	var err error
	var instance ssfInstance
	mongo, err := mongo_provider.Open(TestDbUrl, dbName)
	if err != nil {
		testLog.Println("Mongo client error: " + err.Error())
		return nil, err
	}

	_ = mongo.ResetDb(true)

	listener, _ := net.Listen("tcp", "localhost:0")

	signalsApplication := ssef.StartServer(listener.Addr().String(), &*mongo, "")
	instance.app = *signalsApplication
	instance.server = signalsApplication.Server
	instance.client = &http.Client{}
	instance.provider = mongo
	nowTime := time.Now()
	instance.startTime = &nowTime

	instance.iatToken, err = instance.provider.GetAuthIssuer().IssueProjectIat(nil)
	if err != nil {
		fmt.Printf("Error creating iat: %s", err.Error())
	}
	eat, err := instance.provider.GetAuthIssuer().ParseAuthToken(instance.iatToken)
	if err != nil {
		fmt.Printf("Error parsing iat: %s", err.Error())
	}

	clientToken, err := instance.provider.GetAuthIssuer().IssueStreamClientToken(model.SsfClient{
		Id:            primitive.ObjectID{},
		ProjectIds:    []string{eat.ProjectId},
		AllowedScopes: []string{authUtil.ScopeStreamAdmin, authUtil.ScopeStreamMgmt},
		Email:         "test@test.com",
		Description:   "server test",
	}, eat.ProjectId, true)
	instance.streamMgmtToken = clientToken

	instance.projectId = eat.ProjectId

	go func() {
		_ = signalsApplication.Server.Serve(listener)
	}()
	return &instance, nil
}

func (suite *ServerSuite) SetupTest() {
	// log.Println("TEST!")
}

func (suite *ServerSuite) TearDownTest() {

}

// Test1_Certificate loads the servers default certificate in a couple of ways and attempts to parse it.
func (suite *ServerSuite) Test1_Certificate() {
	serverUrl := fmt.Sprintf("http://%s/jwks.json", suite.servers[0].server.Addr)
	resp, err := http.Get(serverUrl)
	if err != nil {
		testLog.Println(err.Error())
	}
	body, _ := io.ReadAll(resp.Body)
	assert.NotNil(suite.T(), body, "A certificate was returned.")

	var rawJson json.RawMessage
	_ = rawJson.UnmarshalJSON(body)

	issPub, err := keyfunc.NewJSON(rawJson)
	assert.NoError(suite.T(), err, "No error parsing well known issuer")
	assert.Equal(suite.T(), "DEFAULT", issPub.KIDs()[0], "Kid is DEFAULT")
	issPub2, err := keyfunc.Get(serverUrl, keyfunc.Options{})
	assert.NoError(suite.T(), err, "Keyfunc retrieval had no error")

	assert.Equal(suite.T(), body, issPub2.RawJWKS(), "Check JWKS issuers are equal")

	serverUrl = fmt.Sprintf("http://%s/jwks/DEFAULT", suite.servers[0].server.Addr)
	issPub3, err := keyfunc.Get(serverUrl, keyfunc.Options{})
	assert.NoError(suite.T(), err, "Check no error keyfunc retrieval of /jwks/issuer")
	assert.Equal(suite.T(), body, issPub3.RawJWKS(), "Check JWKS issuers are equal")
}

func (suite *ServerSuite) Test2_WellKnownConfigs() {
	serverUrl := fmt.Sprintf("http://%s/.well-known/ssf-configuration", suite.servers[0].server.Addr)
	resp, err := http.Get(serverUrl)
	if err != nil {
		testLog.Println(err.Error())
	}
	body, _ := io.ReadAll(resp.Body)
	var config model.TransmitterConfiguration
	err = json.Unmarshal(body, &config)
	assert.NoError(suite.T(), err, "Configuration parsed and returned")

	verifyUrlString := fmt.Sprintf("http://%s/verification", suite.servers[0].server.Addr)
	assert.Equal(suite.T(), verifyUrlString, config.VerificationEndpoint, "Confirm baseurl to verify url calculation correct")
	streamUrlString := fmt.Sprintf("http://%s/stream", suite.servers[0].server.Addr)
	assert.Equal(suite.T(), streamUrlString, config.ConfigurationEndpoint, "Configuration endpoint matches")
	assert.Equal(suite.T(), "DEFAULT", config.Issuer, "Selected issuer matched")
}

// Test3_StreamConfig Tests the following sequence
// 0. Retrieves well-known endpoint configuration
// 1. Creates a "default" stream (Polling transmitter) and checks it has the correct default settings
// 2. Retrieves the configuration via GET to the Stream endpoint
// 3. Deletes the stream from step 1
// 4. Create a Push Receiver stream using default issuer (no issuer jwksurl)
// 5. Delete the stream from step 4
func (suite *ServerSuite) Test3_StreamConfig() {

	// Step 0.

	testLog.Println("0. Retrieving well-known configuration...")
	serverUrl := fmt.Sprintf("http://%s/.well-known/ssf-configuration", suite.servers[0].server.Addr)
	resp, err := http.Get(serverUrl)
	if err != nil {
		testLog.Println(err.Error())
	}
	body, _ := io.ReadAll(resp.Body)
	var config model.TransmitterConfiguration
	err = json.Unmarshal(body, &config)

	// Step 1.

	testLog.Println("1. Testing creation of default stream...")

	regUrl := config.ConfigurationEndpoint

	// Create a default polling transmitter stream using the default issuer
	regConfigRequest := model.StreamConfiguration{
		Aud:       []string{"test"},
		RouteMode: model.RouteModePublish,
	}
	method := &model.PollTransmitMethod{Method: model.DeliveryPoll}

	regConfigRequest.Delivery = &model.OneOfStreamConfigurationDelivery{PollTransmitMethod: method}

	regBytes, err := json.Marshal(regConfigRequest)

	req, err := http.NewRequest(http.MethodPost, regUrl, bytes.NewReader(regBytes))
	req.Header.Add("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+suite.servers[0].streamMgmtToken)
	resp, err = suite.servers[0].client.Do(req)
	assert.NoError(suite.T(), err, "Registration error")
	assert.Equal(suite.T(), 200, resp.StatusCode, "Reg response status 200 returned check")
	body, _ = io.ReadAll(resp.Body)
	var configResponse model.StreamConfiguration
	err = json.Unmarshal(body, &configResponse)
	assert.NoError(suite.T(), err, "Registration response parse error")

	assert.Equal(suite.T(), model.DeliveryPoll, configResponse.Delivery.GetMethod(), "Check the default Delivery Poll is set")
	assert.Equal(suite.T(), "DEFAULT", configResponse.Iss, "Check default issuer is set")
	assert.NotEmpty(suite.T(), configResponse.Delivery.PollTransmitMethod.AuthorizationHeader, "Authorization empty error")

	// Step 2.

	testLog.Println("2. Retrieving configuration using GET...")

	// Check that the same configuration is returned via GET to stream endpoint
	streamUrl := fmt.Sprintf("%s?stream_id=%s", config.ConfigurationEndpoint, configResponse.Id)
	getReq, err := http.NewRequest(http.MethodGet, streamUrl, nil)
	getReq.Header.Set("Authorization", "Bearer "+suite.servers[0].streamMgmtToken)
	resp, err = suite.servers[0].client.Do(getReq)
	assert.NoError(suite.T(), err, "Should be no error on GET")
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode, "Should be ok")
	body, _ = io.ReadAll(resp.Body)
	var getConfig model.StreamConfiguration
	err = json.Unmarshal(body, &getConfig)
	assert.NoError(suite.T(), err, "Get config data unmarshall error check")
	assert.Equal(suite.T(), configResponse.Id, getConfig.Id, "Check configs are the same id")

	// Step 3.

	testLog.Println("3. Deleting stream from step 1...")

	req, err = http.NewRequest(http.MethodDelete, streamUrl, nil)

	// First try with the wrong authorization
	req.Header.Set("Authorization", configResponse.Delivery.PollTransmitMethod.AuthorizationHeader)
	resp, err = suite.servers[0].client.Do(req)
	assert.NoError(suite.T(), err, "Should be no error despite authorization fail")
	assert.Equal(suite.T(), resp.StatusCode, http.StatusUnauthorized, "Should be unauthorized")

	// Now re-run it with stream mgmt token
	req.Header.Set("Authorization", "Bearer "+suite.servers[0].streamMgmtToken)
	resp, err = suite.servers[0].client.Do(req)
	assert.NoError(suite.T(), err, "Stream should be successfully deleted")
	assert.Equal(suite.T(), resp.StatusCode, http.StatusOK, "Should be OK status")

	// Step 4.

	testLog.Println("4. Testing creation of incoming push stream...")

	reg2 := model.StreamConfiguration{
		Iss:             "DEFAULT",
		Aud:             []string{"test2"},
		EventsRequested: []string{"*"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PushReceiveMethod: &model.PushReceiveMethod{
				Method: model.ReceivePush,
			},
		},
		RouteMode: model.RouteModeImport,
	}

	regBytes, _ = json.Marshal(reg2)
	req, _ = http.NewRequest(http.MethodPost, regUrl, bytes.NewReader(regBytes))
	req.Header.Set("Authorization", "Bearer "+suite.servers[0].streamMgmtToken)

	resp, err = suite.servers[0].client.Do(req)
	assert.NoError(suite.T(), err, "Registration request error")

	body, _ = io.ReadAll(resp.Body)
	var registration2 model.StreamConfiguration
	err = json.Unmarshal(body, &registration2)
	assert.NoError(suite.T(), err, "Registration response parse error")

	assert.Equal(suite.T(), model.ReceivePush, registration2.Delivery.GetMethod(), "Stream is inbound push")
	assert.NotEmpty(suite.T(), registration2.Delivery.PushReceiveMethod.AuthorizationHeader, "Auth empty error")

	// Calculate the predicated push URL and compare
	pushUrlString := fmt.Sprintf("http://%s/events/%s", suite.servers[0].server.Addr, registration2.Id)
	assert.Equal(suite.T(), pushUrlString, registration2.Delivery.PushReceiveMethod.EndpointUrl, "Confirm PUSH URL calculation correct")

	// Step 5.
	testLog.Println("5. Delete incoming stream")
	streamUrl = fmt.Sprintf("%s?stream_id=%s", config.ConfigurationEndpoint, registration2.Id)
	req, err = http.NewRequest(http.MethodDelete, streamUrl, nil)
	req.Header.Set("Authorization", "Bearer "+suite.servers[0].streamMgmtToken)
	resp, err = suite.servers[0].client.Do(req)
	assert.NoError(suite.T(), err, "Stream delete request ok")
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode, "Delete return status 200")
}

// Test4_StreamUpdate checks the stream configuration update functionality via HTTP PUT.
func (suite *ServerSuite) Test4_StreamUpdate() {
	// TODO should be no existing streams???

	testLog.Println("Creating Test Polling Transmitter Stream...")
	transConfig := model.StreamConfiguration{
		Aud: []string{"test.example.com"},
		Iss: "DEFAULT",
	}

	method := &model.PollTransmitMethod{Method: model.DeliveryPoll}

	transConfig.Delivery = &model.OneOfStreamConfigurationDelivery{PollTransmitMethod: method}

	config, _ := suite.servers[0].provider.CreateStream(transConfig, suite.servers[0].projectId)
	streamToken := config.Delivery.PollTransmitMethod.AuthorizationHeader

	suite.servers[0].streamToken = streamToken
	suite.servers[0].stream = config

	suite.servers[0].stream.EventsRequested = suite.servers[0].stream.EventsSupported
	streamUrl := fmt.Sprintf("http://%s/stream?stream_id=%s", suite.servers[0].server.Addr, suite.servers[0].stream.Id)

	// check that the delivery structure was serialized and deserialized correctly
	assert.NotNil(suite.T(), config.Delivery, "Delivery is not null")
	assert.NotNil(suite.T(), config.Delivery.PollTransmitMethod, "Poll delivery is defined")
	assert.Equal(suite.T(), 0, len(config.EventsDelivered), "No events to be delivered")

	testLog.Println("Updating stream with PUT to request all events supported...")
	// enable all events
	config.EventsRequested = config.EventsSupported // request all events

	// Do PUT to update
	bodyBytes, err := json.MarshalIndent(config, "", " ")
	assert.NoError(suite.T(), err, "JSON Marshalling error")
	req, err := http.NewRequest(http.MethodPut, streamUrl, bytes.NewReader(bodyBytes))
	assert.NoError(suite.T(), err, "no request builder error")
	req.Header.Set("Authorization", "Bearer "+suite.servers[0].streamMgmtToken)
	resp, err := suite.servers[0].client.Do(req)
	assert.NoError(suite.T(), err, "Update request successful")
	assert.NotNil(suite.T(), resp, "Response is not null")

	var configResp model.StreamConfiguration
	body, err := io.ReadAll(resp.Body)
	assert.NoError(suite.T(), err, "No error reading config response body")
	err = json.Unmarshal(body, &configResp)
	assert.NoError(suite.T(), err, "No error parsing config response body")

	assert.Equal(suite.T(), len(config.EventsRequested), len(configResp.EventsDelivered), "Configuration set successfully")

	testLog.Println("Removing update test stream")
	req, err = http.NewRequest(http.MethodDelete, streamUrl, nil)
	req.Header.Set("Authorization", "Bearer "+suite.servers[0].streamMgmtToken)
	resp, err = suite.servers[0].client.Do(req)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode, "Check delete ok")
}

// Test5_PollStreamDelivery sets up a polling delivery stream between SSF1 and SSF2 and tests an event can be transferred
func (suite *ServerSuite) Test5_PollStreamDelivery() {

	// Start server 2 and hopefully it polls!
	suite.setUpPollStreamConnection()

	rcvState, err := suite.servers[1].app.Provider.GetStreamState(suite.servers[1].stream.Id)
	assert.NoError(suite.T(), err, "Stream should be defined")
	assert.Equal(suite.T(), model.StreamStateEnabled, rcvState.Status, "Stream is active")

	testLog.Println("Generating event on SSF1...")
	jti, err := suite.generateEvent(suite.servers[0].stream)
	assert.NoError(suite.T(), err, "No error generating event")
	// time.Sleep(2 * time.Second)
	testLog.Println("Looking for event on SSF2...")
	var event *model.EventRecord
	event = suite.servers[1].provider.GetEventRecord(jti)
	for i := 0; i < 5 && event == nil; i++ {
		time.Sleep(time.Millisecond * 500)
		testLog.Println("WAITING for event " + jti)
		event = suite.servers[1].provider.GetEventRecord(jti)
	}
	assert.NotNil(suite.T(), event, "Event should be received")

	app1 := suite.servers[0].app
	pushCnt1 := int(testutil.ToFloat64(app1.Stats.PubPushCnt))
	pollCnt1 := int(testutil.ToFloat64(app1.Stats.PubPollCnt))
	rcvPushCnt1 := int(testutil.ToFloat64(app1.Stats.RcvPushCnt))
	rcrPollCnt1 := int(testutil.ToFloat64(app1.Stats.RcvPollCnt))
	testLog.Println(fmt.Sprintf("S|R PUSH[%d|%d] POLL[%d|%d]", pushCnt1, rcvPushCnt1, pollCnt1, rcrPollCnt1))
	assert.Equal(suite.T(), 0, pushCnt1, "Should be no PUSH servers")
	// Includes the original from Test 3 plus the new one
	assert.Equal(suite.T(), 1, pollCnt1, "Should be 2 POLL server")

	// time.Sleep(5 * time.Second)
}

/*
Test6_ResetStream tests the time reset functionality which causes the server to go through prior events and re-add them
to the stream
*/
func (suite *ServerSuite) Test6_ResetStream() {
	outboundStreamConfig := suite.servers[0].stream

	// Kill the polling client on SSF2
	ssf2Stream := suite.servers[1].stream.Id
	suite.servers[1].app.ClosePollReceiver(ssf2Stream)
	suite.servers[1].app.EventRouter.RemoveStream(ssf2Stream)
	_ = suite.servers[1].provider.DeleteStream(ssf2Stream)

	// Check that there are no pending events
	jtis, more := suite.servers[0].app.Provider.GetEventIds(suite.servers[0].stream.Id, model.PollParameters{ReturnImmediately: true})
	assert.False(suite.T(), more, "Should be no more events")
	assert.Len(suite.T(), jtis, 0, "No event jtis returned")

	// Add an extra event for a total of 2 events. This event will be deleted and re-added so no duplicates!
	jtiNew, err := suite.generateEvent(suite.servers[0].stream)

	// reset the stream on SSF1 to beginning of startup
	outboundStreamConfig.ResetDate = suite.servers[0].startTime

	testLog.Println("Resetting stream to beginning")
	// Post the new config with reset request to the handler
	streamUrl := fmt.Sprintf("http://%s/stream?stream_id=%s", suite.servers[0].server.Addr, outboundStreamConfig.Id)
	bodyBytes, err := json.MarshalIndent(outboundStreamConfig, "", " ")
	assert.NoError(suite.T(), err, "JSON Marshalling error")
	req, err := http.NewRequest(http.MethodPut, streamUrl, bytes.NewReader(bodyBytes))
	assert.NoError(suite.T(), err, "no request builder error")
	req.Header.Set("Authorization", "Bearer "+suite.servers[0].streamMgmtToken)
	resp, err := suite.servers[0].client.Do(req)
	assert.NoError(suite.T(), err, "Update request successful")
	assert.NotNil(suite.T(), resp, "Response is not null")

	var configResp model.StreamConfiguration
	body, err := io.ReadAll(resp.Body)
	assert.NoError(suite.T(), err, "No error reading config response body")
	err = json.Unmarshal(body, &configResp)
	assert.NoError(suite.T(), err, "No error parsing config response body")
	assert.Nil(suite.T(), configResp.ResetDate, "Reset date should be nil")
	assert.Equal(suite.T(), "", configResp.ResetJti, "JTI should be empty")

	// Check that there are pending events
	jtis, more = suite.servers[0].app.Provider.GetEventIds(suite.servers[0].stream.Id, model.PollParameters{ReturnImmediately: true})
	assert.False(suite.T(), more, "Should be no more events")
	assert.Len(suite.T(), jtis, 2, "No event jtis returned")
	assert.Equal(suite.T(), jtiNew, jtis[1], "The new event should be second")

	ssf1Stream := suite.servers[0].stream.Id
	suite.servers[0].app.EventRouter.RemoveStream(ssf1Stream)
	_ = suite.servers[0].provider.DeleteStream(ssf1Stream)
}

// Test7_PushStreamDelivery sets up a push stream from SSF1 to SSF2 and then send test events
func (suite *ServerSuite) Test7_PushStreamDelivery() {
	testLog.Println("Setting up Push Receiver on SSF2")
	baseUrl := fmt.Sprintf("http://%s/stream", suite.servers[1].server.Addr)
	base, _ := url.Parse(baseUrl)
	base0Url := fmt.Sprintf("http://%s/stream", suite.servers[0].server.Addr)
	base0, _ := url.Parse(base0Url)
	jwksUrl, _ := url.Parse("/jwks/DEFAULT")
	jwksIssuer := base0.ResolveReference(jwksUrl)

	delivery := &model.PushReceiveMethod{
		Method: model.ReceivePush,
	}
	reg := model.StreamConfiguration{
		Aud:             []string{"test.example.com"},
		Iss:             "DEFAULT",
		Delivery:        &model.OneOfStreamConfigurationDelivery{PushReceiveMethod: delivery},
		EventsRequested: []string{"*"},
		IssuerJWKSUrl:   jwksIssuer.String(),
		RouteMode:       model.RouteModeImport,
	}
	stream, err := suite.servers[1].provider.CreateStream(reg, "DEFAULT")
	assert.Nil(suite.T(), err, "No errors on stream creation")
	state, _ := suite.servers[1].provider.GetStreamState(stream.Id)
	suite.servers[1].app.EventRouter.UpdateStreamState(state)

	streamToken1 := stream.Delivery.PushReceiveMethod.AuthorizationHeader
	suite.servers[1].stream = stream
	suite.servers[1].streamToken = streamToken1

	testLog.Println("Setting up Push Transmitter on SSF1")

	target, _ := url.Parse(stream.Delivery.PushReceiveMethod.EndpointUrl)
	eventUrl := base.ResolveReference(target)

	delivery2 := &model.PushTransmitMethod{
		Method:              model.DeliveryPush,
		EndpointUrl:         eventUrl.String(),
		AuthorizationHeader: streamToken1,
	}
	regPush := model.StreamConfiguration{
		Aud:             []string{"test.example.com"},
		Iss:             "DEFAULT",
		Delivery:        &model.OneOfStreamConfigurationDelivery{PushTransmitMethod: delivery2},
		EventsRequested: stream.EventsDelivered,
	}

	stream, err = suite.servers[0].provider.CreateStream(regPush, "DEFAULT")
	assert.Nil(suite.T(), err, "No errors on stream creation")
	state, _ = suite.servers[0].provider.GetStreamState(stream.Id)
	suite.servers[0].app.EventRouter.UpdateStreamState(state)

	suite.servers[0].stream = stream
	suite.servers[0].streamToken = ""

	testLog.Println("Push Stream Configured")

	testLog.Println("Generating event on SSF1...")
	jti, err := suite.generateEvent(suite.servers[0].stream)
	assert.NoError(suite.T(), err, "No error generating event")
	// time.Sleep(2 * time.Second)
	testLog.Println("Looking for event on SSF2...")
	var event *model.EventRecord
	event = suite.servers[1].provider.GetEventRecord(jti)
	for i := 0; i < 5 && event == nil; i++ {
		time.Sleep(time.Millisecond * 250)
		testLog.Println("WAITING for event " + jti)
		event = suite.servers[1].provider.GetEventRecord(jti)
	}
	assert.NotNil(suite.T(), event, "Event should be received")

	app1 := suite.servers[0].app
	pushCnt1 := int(testutil.ToFloat64(app1.Stats.PubPushCnt))
	pollCnt1 := int(testutil.ToFloat64(app1.Stats.PubPollCnt))
	rcvPushCnt1 := int(testutil.ToFloat64(app1.Stats.RcvPushCnt))
	rcrPollCnt1 := int(testutil.ToFloat64(app1.Stats.RcvPollCnt))
	testLog.Println(fmt.Sprintf("S|R PUSH[%d|%d] POLL[%d|%d]", pushCnt1, rcvPushCnt1, pollCnt1, rcrPollCnt1))
	assert.Equal(suite.T(), 1, pushCnt1, "Should be 1 PUSH servers")

	assert.Equal(suite.T(), 0, pollCnt1, "Should be 1 POLL server")

	testLog.Println("Resetting streams")
	suite.resetStreams(suite.servers[1].stream.Id, suite.servers[0].stream.Id)
	// time.Sleep(5 * time.Second)
}

/*
Test8_Prometheus checks that the prometheus stats counters are working and the counters are correct
TODO: Need to check gauges for current stream counts
*/
func (suite *ServerSuite) Test8_Prometheus() {
	app1 := suite.servers[0].app
	app2 := suite.servers[1].app

	metricName := "goSignals_router_events"
	outCounters1 := testutil.CollectAndCount(app1.Stats.EventsOut, metricName+"_out")
	inCounters1 := testutil.CollectAndCount(app1.Stats.EventsIn, metricName+"_in")
	// fmt.Println(fmt.Sprintf("SSF1 Counters in: %d, out: %d", inCounters1, outCounters1))
	assert.Equal(suite.T(), 2, outCounters1, "Two (one for PUSH and POLL) event out counter registered")
	assert.Equal(suite.T(), 2, inCounters1, "Two (one for PUSH and POLL) event in counter registered")

	// Test the counters for PUSH Transfer
	label := prometheus.Labels{
		"type": model.EventScimCreateFull,
		"iss":  "DEFAULT",
		"tfr":  "PUSH",
	}
	var outCnt1, inCnt1 int

	cnt1, err := app1.Stats.EventsOut.GetMetricWith(label)
	if err != nil {
		testLog.Println(err.Error())
		return
	}
	in1, err := app1.Stats.EventsIn.GetMetricWith(label)
	if err != nil {
		testLog.Println(err.Error())
		return
	}

	if cnt1 != nil {
		outCnt1 = int(testutil.ToFloat64(cnt1))
		inCnt1 = int(testutil.ToFloat64(in1))
	}
	testLog.Println(fmt.Sprintf("SSF1 Event PUSH Count in: %v, out: %v", inCnt1, outCnt1))
	assert.Equal(suite.T(), 1, inCnt1, "SSF1 should have 1 PUSH inbound events")
	assert.Equal(suite.T(), 1, outCnt1, "SSF1 should have 1 PUSH outbound events")

	// Test the counters for PULL transfer
	label = prometheus.Labels{
		"type": model.EventScimCreateFull,
		"iss":  "DEFAULT",
		"tfr":  "POLL",
	}
	cnt1, err = app1.Stats.EventsOut.GetMetricWith(label)
	if err != nil {
		testLog.Println(err.Error())
		return
	}
	in1, err = app1.Stats.EventsIn.GetMetricWith(label)
	if err != nil {
		testLog.Println(err.Error())
		return
	}

	if cnt1 != nil {
		outCnt1 = int(testutil.ToFloat64(cnt1))
		inCnt1 = int(testutil.ToFloat64(in1))
	}
	testLog.Println(fmt.Sprintf("SSF1 Event POLL Count in: %v, out: %v", inCnt1, outCnt1))
	// should be 1 from test 5 plus 1 from test 6
	assert.Equal(suite.T(), 2, inCnt1, "SSF1 should have 2 POLL inbound events")
	assert.Equal(suite.T(), 1, outCnt1, "SSF1 should have 1 POLL outbound events")

	// Now look at SSF2
	var inCnt2, outCnt2 int
	label = prometheus.Labels{
		"type": model.EventScimCreateFull,
		"iss":  "DEFAULT",
		"tfr":  "PUSH",
	}

	cnt2, err := app2.Stats.EventsOut.GetMetricWith(label)
	if err != nil {
		testLog.Println(err.Error())
		return
	}
	in2, err := app2.Stats.EventsIn.GetMetricWith(label)
	if err != nil {
		testLog.Println(err.Error())
		return
	}

	if cnt2 != nil {
		outCnt2 = int(testutil.ToFloat64(cnt2))
		inCnt2 = int(testutil.ToFloat64(in2))
	}
	testLog.Println(fmt.Sprintf("SSF2 Event PUSH Count in: %v, out: %v", inCnt2, outCnt2))
	assert.Equal(suite.T(), 1, inCnt2, "SSF2 should have 1 PUSH inbound events")
	assert.Equal(suite.T(), 0, outCnt2, "SSF2 should have NO outbound events")

	pushCnt1 := int(testutil.ToFloat64(app1.Stats.PubPushCnt))
	pollCnt1 := int(testutil.ToFloat64(app1.Stats.PubPollCnt))
	rcvPushCnt1 := int(testutil.ToFloat64(app1.Stats.RcvPushCnt))
	rcrPollCnt1 := int(testutil.ToFloat64(app1.Stats.RcvPollCnt))

	testLog.Println(fmt.Sprintf("S|R PUSH[%d|%d] POLL[%d|%d]", pushCnt1, rcvPushCnt1, pollCnt1, rcrPollCnt1))
	assert.Equal(suite.T(), 0, pushCnt1, "Should be no PUSH servers")
	assert.Equal(suite.T(), 0, pollCnt1, "Should be no POLL server")
}

func (suite *ServerSuite) Test9_CreateIssuerKey() {
	testLog.Println("Creating new issuer key..")
	issuer := "example.com"
	baseUrl := fmt.Sprintf("http://%s/jwks/%s", suite.servers[0].server.Addr, issuer)

	req, _ := http.NewRequest(http.MethodPost, baseUrl, nil)
	resp, err := suite.servers[0].client.Do(req)

	assert.Equal(suite.T(), http.StatusForbidden, resp.StatusCode, "Check forbidden without authorization")

	req.Header.Set("Authorization", "Bearer "+suite.servers[0].streamMgmtToken)
	resp, err = suite.servers[0].client.Do(req)
	assert.NoError(suite.T(), err, "No error generating key")
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode, "Check status ok result")

	body, _ := io.ReadAll(resp.Body)
	assert.NotNil(suite.T(), body, "Check a request body was returned.")

	block, _ := pem.Decode(body)

	pkcs8PrivateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key := pkcs8PrivateKey.(*rsa.PrivateKey)
	assert.NoError(suite.T(), err, "private key decoded")

	testLog.Println("Creating and signing event with new key")
	subject := &goSet.EventSubject{
		SubjectIdentifier: goSet.SubjectIdentifier{
			Format:                    "scim",
			UniformResourceIdentifier: goSet.UniformResourceIdentifier{Uri: "?Users/1234"},
		},
	}
	set := goSet.CreateSet(subject, "example.com", []string{"someAudience"})
	payloadClaims := map[string]interface{}{
		"aClaim": "aValue",
	}

	set.AddEventPayload("uri:testEvent", payloadClaims)

	val, err := set.JWS(jwt.SigningMethodRS256, key)

	assert.NoError(suite.T(), err, "key was signed!")
	assert.NotNil(suite.T(), val, "Signed value returned")
	testLog.Println("Signed event: \n" + val)
}

func (suite *ServerSuite) resetStreams(ssf2Stream, ssf1Stream string) {
	suite.servers[1].app.ClosePollReceiver(ssf2Stream)
	suite.servers[1].app.EventRouter.RemoveStream(ssf2Stream)
	_ = suite.servers[1].provider.DeleteStream(ssf2Stream)

	suite.servers[0].app.EventRouter.RemoveStream(ssf1Stream)
	_ = suite.servers[0].provider.DeleteStream(ssf1Stream)
}

func (suite *ServerSuite) setUpPollStreamConnection() {
	testLog.Println("  initializing poll transmitter on SSF1...")
	// Create a polling transmitter stream`
	transConfig := model.StreamConfiguration{
		Aud:             []string{"test.example.com"},
		Iss:             "DEFAULT",
		EventsRequested: []string{"*"},
	}

	method := &model.PollTransmitMethod{Method: model.DeliveryPoll}

	transConfig.Delivery = &model.OneOfStreamConfigurationDelivery{PollTransmitMethod: method}

	stream, _ := suite.servers[0].provider.CreateStream(transConfig, suite.servers[0].projectId)
	state, _ := suite.servers[0].provider.GetStreamState(stream.Id)
	suite.servers[0].app.EventRouter.UpdateStreamState(state)
	streamToken := stream.Delivery.PollTransmitMethod.AuthorizationHeader

	suite.servers[0].streamToken = streamToken
	suite.servers[0].stream = stream

	testLog.Println("  initializing poll receiver on SSF2...")
	// Use the polling transmitter information to base the receiver on

	baseUrl := fmt.Sprintf("http://%s/stream", suite.servers[0].server.Addr)
	base, _ := url.Parse(baseUrl)
	target, _ := url.Parse(stream.Delivery.PollTransmitMethod.EndpointUrl)
	targetJwks, _ := url.Parse(stream.IssuerJWKSUrl)
	issuerJwks := base.ResolveReference(targetJwks)
	eventUrl := base.ResolveReference(target)
	authorizationHeader := suite.servers[0].stream.Delivery.PollTransmitMethod.AuthorizationHeader
	if !strings.Contains(strings.ToLower(authorizationHeader), "bearer ") {
		authorizationHeader = "Bearer " + authorizationHeader
	}

	req := model.StreamConfiguration{
		Aud: []string{"test.example.com"},
		Iss: stream.Iss,
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{
				Method:              model.ReceivePoll,
				EndpointUrl:         eventUrl.String(),
				AuthorizationHeader: authorizationHeader,
				PollConfig: &model.PollParameters{
					MaxEvents:         5,
					ReturnImmediately: false,
					TimeoutSecs:       10,
				},
			},
		},
		EventsRequested: stream.EventsDelivered,
		IssuerJWKSUrl:   issuerJwks.String(),
		RouteMode:       model.RouteModeImport,
	}

	baseUrl2 := fmt.Sprintf("http://%s/stream", suite.servers[1].server.Addr)
	regBytes, _ := json.Marshal(req)
	reqCreate, _ := http.NewRequest(http.MethodPost, baseUrl2, bytes.NewReader(regBytes))
	reqCreate.Header.Set("Authorization", "Bearer "+suite.servers[1].streamMgmtToken)

	resp, err := suite.servers[1].client.Do(reqCreate)
	assert.NoError(suite.T(), err, "Check no http error on polling stream create")
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode, "Check status accepted")

	respBytes, _ := io.ReadAll(resp.Body)
	var pstream model.StreamConfiguration

	err = json.Unmarshal(respBytes, &pstream)
	assert.NoError(suite.T(), err, "Check no error parsing stream configuration for polling stream")
	suite.servers[1].stream = pstream

}

func (suite *ServerSuite) generateEvent(stream model.StreamConfiguration) (string, error) {
	subject := &goSet.EventSubject{

		SubjectIdentifier: *goSet.NewScimSubjectIdentifier("/Users/44f6142df96bd6ab61e7521d9").AddExternalId("jdoe"),
	}

	event := goSet.CreateSet(subject, stream.Iss, stream.Aud)

	payloadClaims := map[string]interface{}{
		"data": map[string]interface{}{
			"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
			"emails": []map[string]string{
				{"type": "work", "value": "jdoe@example.com"},
			},
			"userName": "jdoe",
			"name":     map[string]string{"givenName": "John", "familyName": "Doe"},
		},
	}

	streamIds := make([]string, 1)
	streamIds[0] = stream.Id
	event.AddEventPayload(model.EventScimCreateFull, payloadClaims)

	return event.ID, suite.servers[0].app.EventRouter.HandleEvent(&event, "", stream.Id)
}
