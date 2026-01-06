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
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/model"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	ssef "github.com/i2-open/i2goSignals/pkg/goSignals/server"
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
	ts              *httptest.Server
	host            string
	client          *http.Client
	provider        dbProviders.DbProviderInterface
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

	testLog.Println("Tests must be completed in order. Tests may not be run individually as each test builds on previous state.")
	testLog.Println("By default, tests are run against a mock provider. Set environment variable TEST_MONGO_CLUSTER to true to test against docker-compose mongo cluster")

	testLog.Println("NOTE: This test will generate a series of Prometheus duplicate collector registration errors. This is due to the test environment only.")
	instances := make([]*ssfInstance, 2)

	testLog.Println("** Starting GoSignals (ssf1)...")
	instance, err := createServer(t, "ssf1", true) // Reset DB for first instance
	if err != nil {
		testLog.Printf("Error starting %s: %s", "ssf1", err.Error())
	}
	assert.NotEqualf(t, instance.projectId, "", "Check project id is not empty")

	instances[0] = instance
	testLog.Println("** Starting GoSignals (ssf2)...")
	instance, err = createServer(t, "ssf2", false) // Don't reset DB for second instance (shared storage)
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
		if instance.ts != nil {
			instance.ts.Close()
		}
		instance.app.Shutdown()
		time.Sleep(time.Second)
	}
	testLog.Println("** TEST COMPLETE **")
}

func createServer(t *testing.T, dbName string, resetDb bool) (*ssfInstance, error) {
	t.Helper()
	var err error
	var instance ssfInstance

	dbUrl := "mockdb:"
	if os.Getenv("TEST_MONGO_CLUSTER") != "" {
		dbUrl = TestDbUrl
	}
	// mongo, err := mongo_provider.Open(TestDbUrl, dbName)
	mongo, err := dbProviders.OpenProvider(dbUrl, dbName)
	if err != nil {
		t.Error("Mongo client error: " + err.Error())
		return nil, err
	}

	if resetDb {
		_ = mongo.ResetDb(true)
	}

	// Build application and wrap with httptest.Server
	app := ssef.NewApplication(mongo, "")
	ts := httptest.NewServer(app.Handler)
	instance.ts = ts
	instance.app = *app
	u, _ := url.Parse(ts.URL)
	instance.host = u.Host
	// Set BaseUrl on app for any logic that depends on it
	app.BaseUrl, _ = url.Parse(ts.URL + "/")
	instance.client = ts.Client()
	instance.provider = mongo
	nowTime := time.Now()
	instance.startTime = &nowTime

	instance.iatToken, err = instance.provider.GetAuthIssuer().IssueProjectIat(nil)
	if err != nil {
		t.Logf("Error creating iat: %s\n", err.Error())
	}
	eat, err := instance.provider.GetAuthIssuer().ParseAuthToken(instance.iatToken)
	if err != nil {
		t.Logf("Error parsing iat: %s\n", err.Error())
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

	return &instance, nil
}

func (suite *ServerSuite) TearDownTest() {
	// Wait for tests to settle (database updates to complete
	time.Sleep(500 * time.Millisecond)
}

// Test1_Certificate loads the servers default certificate in a couple of ways and attempts to parse it.
func (suite *ServerSuite) Test1_Certificate() {
	serverUrl := fmt.Sprintf("http://%s/jwks.json", suite.servers[0].host)
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

	serverUrl = fmt.Sprintf("http://%s/jwks/DEFAULT", suite.servers[0].host)
	issPub3, err := keyfunc.Get(serverUrl, keyfunc.Options{})
	assert.NoError(suite.T(), err, "Check no error keyfunc retrieval of /jwks/issuer")
	assert.Equal(suite.T(), body, issPub3.RawJWKS(), "Check JWKS issuers are equal")
}

func (suite *ServerSuite) Test2_WellKnownConfigs() {
	serverUrl := fmt.Sprintf("http://%s/.well-known/ssf-configuration", suite.servers[0].host)
	resp, err := http.Get(serverUrl)
	if err != nil {
		testLog.Println(err.Error())
	}
	body, _ := io.ReadAll(resp.Body)
	var config model.TransmitterConfiguration
	err = json.Unmarshal(body, &config)
	assert.NoError(suite.T(), err, "Configuration parsed and returned")

	verifyUrlString := fmt.Sprintf("http://%s/verification", suite.servers[0].host)
	assert.Equal(suite.T(), verifyUrlString, config.VerificationEndpoint, "Confirm baseurl to verify url calculation correct")
	streamUrlString := fmt.Sprintf("http://%s/stream", suite.servers[0].host)
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
	serverUrl := fmt.Sprintf("http://%s/.well-known/ssf-configuration", suite.servers[0].host)
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

	suite.servers[0].stream = configResponse

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

	suite.servers[0].stream = registration2

	assert.Equal(suite.T(), model.ReceivePush, registration2.Delivery.GetMethod(), "Stream is inbound push")
	assert.NotEmpty(suite.T(), registration2.Delivery.PushReceiveMethod.AuthorizationHeader, "Auth empty error")

	// Calculate the predicated push URL and compare
	pushUrlString := fmt.Sprintf("http://%s/events/%s", suite.servers[0].host, registration2.Id)
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
	streamUrl := fmt.Sprintf("http://%s/stream?stream_id=%s", suite.servers[0].host, suite.servers[0].stream.Id)

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
	// time.Sleep(2 * time.Second)
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
	streamUrl := fmt.Sprintf("http://%s/stream?stream_id=%s", suite.servers[0].host, outboundStreamConfig.Id)
	bodyBytes, err := json.MarshalIndent(outboundStreamConfig, "", " ")
	assert.NoError(suite.T(), err, "JSON Marshalling error")
	req, err := http.NewRequest(http.MethodPut, streamUrl, bytes.NewReader(bodyBytes))
	assert.NoError(suite.T(), err, "no request builder error")
	req.Header.Set("Authorization", "Bearer "+suite.servers[0].streamMgmtToken)
	resp, err := suite.servers[0].client.Do(req)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode, "Check reset stream ok")
	assert.NoError(suite.T(), err, "Update request successful")
	assert.NotNil(suite.T(), resp, "Response is not null")

	var configResp model.StreamConfiguration
	body, err := io.ReadAll(resp.Body)
	assert.NoError(suite.T(), err, "No error reading config response body")
	err = json.Unmarshal(body, &configResp)
	assert.NoError(suite.T(), err, "No error parsing config response body")
	assert.Nil(suite.T(), configResp.ResetDate, "Reset date should be nil")
	assert.Equal(suite.T(), "", configResp.ResetJti, "JTI should be empty")

	/*
	   time.Sleep(time.Millisecond * 500)
	   // After PUT reset request
	   require.Eventually(suite.T(), func() bool {
	       jtis, more := suite.servers[0].app.Provider.GetEventIds(
	           suite.servers[0].stream.Id,
	           model.PollParameters{ReturnImmediately: true},
	       )
	       if more {
	           log.Println("More should not be true")
	           return false
	       }
	       log.Printf("Received %d events.\n", len(jtis))
	       return len(jtis) == 2
	   }, 5*time.Second, 100*time.Millisecond, "expected two pending events after reset")
	*/

	// Check that there are pending events
	time.Sleep(time.Millisecond * 1500)
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
	baseUrl := fmt.Sprintf("http://%s/stream", suite.servers[1].host)
	base, _ := url.Parse(baseUrl)
	base0Url := fmt.Sprintf("http://%s/stream", suite.servers[0].host)
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
	time.Sleep(500 * time.Millisecond) // await processing (for reliable testing)
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

	assert.Equal(suite.T(), 0, pollCnt1, "Should be 0 POLL server")

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

	metricName := "goSignals_router_events"
	outCounters1 := testutil.CollectAndCount(app1.Stats.EventsOut, metricName+"_out")
	inCounters1 := testutil.CollectAndCount(app1.Stats.EventsIn, metricName+"_in")
	testLog.Printf("SSF1 Counters in: %d, out: %d\n", inCounters1, outCounters1)

	// Since we added stream_id label, the cardinality changed but the fact that metrics are recorded remains.
	assert.Greater(suite.T(), inCounters1, 0, "Should have some inbound events")
	assert.Greater(suite.T(), outCounters1, 0, "Should have some outbound events")

	pushCnt1 := int(testutil.ToFloat64(app1.Stats.PubPushCnt))
	pollCnt1 := int(testutil.ToFloat64(app1.Stats.PubPollCnt))
	rcvPushCnt1 := int(testutil.ToFloat64(app1.Stats.RcvPushCnt))
	rcrPollCnt1 := int(testutil.ToFloat64(app1.Stats.RcvPollCnt))

	testLog.Println(fmt.Sprintf("S|R PUSH[%d|%d] POLL[%d|%d]", pushCnt1, rcvPushCnt1, pollCnt1, rcrPollCnt1))

	testLog.Println("Prometheus test complete.")
}

func (suite *ServerSuite) getMetricValue(app ssef.SignalsApplication, vec *prometheus.CounterVec, tfr string, streamID string) int {
	label := prometheus.Labels{
		"type":      model.EventScimCreateFull,
		"iss":       "DEFAULT",
		"tfr":       tfr,
		"stream_id": streamID,
	}
	m, err := vec.GetMetricWith(label)
	if err == nil && m != nil {
		return int(testutil.ToFloat64(m))
	}
	return 0
}

func (suite *ServerSuite) Test9_CreateIssuerKey() {
	testLog.Println("Creating new issuer key..")
	issuer := "example.com"
	baseUrl := fmt.Sprintf("http://%s/jwks/%s", suite.servers[0].host, issuer)

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

	baseUrl := fmt.Sprintf("http://%s/stream", suite.servers[0].host)
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

	baseUrl2 := fmt.Sprintf("http://%s/stream", suite.servers[1].host)
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
