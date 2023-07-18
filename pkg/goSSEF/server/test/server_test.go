package test

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"i2goSignals/internal/model"
	"i2goSignals/internal/providers/dbProviders/mongo_provider"
	ssef "i2goSignals/pkg/goSSEF/server"
	"i2goSignals/pkg/goSet"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// var TestDbUrl = "mongodb+srv://ssftester:u3NPH9GtTGS7VlhO@ssf-cluster.d0dnw23.mongodb.net/?retryWrites=true&w=majority"

var TestDbUrl = "mongodb://root:dockTest@mongo1:30001,mongo2:30002,mongo3:30003/?retryWrites=true&replicaSet=dbrs&readPreference=primary&serverSelectionTimeoutMS=5000&connectTimeoutMS=10000&authSource=admin&authMechanism=SCRAM-SHA-256"

var testLog = log.New(os.Stdout, "TEST: ", log.Ldate|log.Ltime)

type ssfInstance struct {
	server      *http.Server
	client      *http.Client
	provider    *mongo_provider.MongoProvider
	stream      model.StreamConfiguration
	app         ssef.SignalsApplication
	streamToken string
	startTime   *time.Time
}

type ServerSuite struct {
	suite.Suite
	servers []*ssfInstance
}

func TestServer(t *testing.T) {
	serverSuite := ServerSuite{}

	fmt.Println("NOTE: This test will generate a series of Prometheus duplicate collector registration errors. This is due to the test environment only.")
	instances := make([]*ssfInstance, 2)

	testLog.Println("** Starting SSF1...")
	instance, err := createServer("ssf1")
	if err != nil {
		testLog.Printf("Error starting %s: %s", "ssf1", err.Error())
	}

	req := model.RegisterParameters{
		Audience: []string{"test.example.com"},
		Method:   model.DeliveryPoll,
	}
	stream, _ := instance.provider.CreateStream(req, "DEFAULT")
	streamToken, err := instance.provider.IssueStreamToken(stream)

	instance.streamToken = streamToken
	instance.stream = stream

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
	assert.NoError(suite.T(), err, "No error parsing wellknown issuer")
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
	serverUrl := fmt.Sprintf("http://%s/.well-known/sse-configuration", suite.servers[0].server.Addr)
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

func (suite *ServerSuite) Test3_StreamConfig() {
	fmt.Println("Retrieving well-known configuration...")
	serverUrl := fmt.Sprintf("http://%s/.well-known/sse-configuration", suite.servers[0].server.Addr)
	resp, err := http.Get(serverUrl)
	if err != nil {
		testLog.Println(err.Error())
	}
	body, _ := io.ReadAll(resp.Body)
	var config model.TransmitterConfiguration
	err = json.Unmarshal(body, &config)

	fmt.Println("Testing creation of default stream...")

	regUrl := fmt.Sprintf("http://%s/register", suite.servers[0].server.Addr)
	reg := model.RegisterParameters{Audience: []string{"test"}}
	regBytes, err := json.Marshal(reg)

	resp, err = http.Post(regUrl, "application/json; charset=UTF-8", bytes.NewReader(regBytes))
	assert.NoError(suite.T(), err, "Registration error")
	body, _ = io.ReadAll(resp.Body)
	var registration model.RegisterResponse
	err = json.Unmarshal(body, &registration)
	assert.NoError(suite.T(), err, "Registration response parse error")

	assert.NotEmpty(suite.T(), registration.Token, "Token empty error")

	streamUrl := fmt.Sprintf("http://%s/stream", suite.servers[0].server.Addr)
	req, err := http.NewRequest(http.MethodDelete, streamUrl, nil)
	req.Header.Set("Authorization", "Bearer "+registration.Token)
	resp, err = suite.servers[0].client.Do(req)
	assert.NoError(suite.T(), err, "Stream should be successfully deleted")

	fmt.Println("Testing creation of incoming push stream...")
	var inbound bool = true
	reg2 := model.RegisterParameters{
		Audience:  []string{"test2"},
		Issuer:    "DEFAULT",
		Inbound:   &inbound,
		Method:    model.DeliveryPush,
		RouteMode: model.RouteModeImport,
		EventUris: []string{"*"},
	}
	regBytes, _ = json.Marshal(reg2)
	resp, err = http.Post(regUrl, "application/json; charset=UTF-8", bytes.NewReader(regBytes))

	body, _ = io.ReadAll(resp.Body)
	var registration2 model.RegisterResponse
	err = json.Unmarshal(body, &registration2)
	assert.NoError(suite.T(), err, "Registration response parse error")

	assert.NotEmpty(suite.T(), registration2.Token, "Token empty error")
	assert.Equal(suite.T(), true, *registration2.Inbound, "Stream is inbound")

	pushUrlString := fmt.Sprintf("http://%s/events", suite.servers[0].server.Addr)
	assert.Equal(suite.T(), pushUrlString, registration2.PushUrl, "Confirm PUSH URL calculation correct")

	req, err = http.NewRequest(http.MethodDelete, streamUrl, nil)
	req.Header.Set("Authorization", "Bearer "+registration2.Token)
	resp, err = suite.servers[0].client.Do(req)
	assert.NoError(suite.T(), err, "Stream should be successfully deleted")
}

func (suite *ServerSuite) Test4_StreamManagement() {

	suite.servers[0].stream.EventsRequested = suite.servers[0].stream.EventsSupported
	streamUrl := fmt.Sprintf("http://%s/stream", suite.servers[0].server.Addr)

	req, err := http.NewRequest("GET", streamUrl, nil)
	assert.NoError(suite.T(), err, "no request builder error")
	req.Header.Set("Authorization", "Bearer "+suite.servers[0].streamToken)
	resp, err := suite.servers[0].client.Do(req)
	assert.NoError(suite.T(), err, "Get stream should have no error")

	var config model.StreamConfiguration
	body, err := io.ReadAll(resp.Body)
	assert.NoError(suite.T(), err, "Stream config body response read")
	err = json.Unmarshal(body, &config)
	assert.NoError(suite.T(), err, "Stream configuration parsed")

	// check that the delivery structure was serialized and deserialized correctly
	assert.NotNil(suite.T(), config.Delivery, "Delivery is not null")
	assert.NotNil(suite.T(), config.Delivery.PollDeliveryMethod, "Poll delivery is defined")
	assert.Equal(suite.T(), 0, len(config.EventsDelivered), "No events to be delivered")

	config.EventsRequested = config.EventsSupported // request all events

	bodyBytes, err := json.MarshalIndent(config, "", " ")
	assert.NoError(suite.T(), err, "JSON Marshalling error")
	req, err = http.NewRequest("POST", streamUrl, bytes.NewReader(bodyBytes))
	assert.NoError(suite.T(), err, "no request builder error")
	req.Header.Set("Authorization", "Bearer "+suite.servers[0].streamToken)
	resp, err = suite.servers[0].client.Do(req)
	assert.NoError(suite.T(), err, "Update request successful")
	assert.NotNil(suite.T(), resp, "Response is not null")

	var configResp model.StreamConfiguration
	body, err = io.ReadAll(resp.Body)
	assert.NoError(suite.T(), err, "No error reading config response body")
	err = json.Unmarshal(body, &configResp)
	assert.NoError(suite.T(), err, "No error parsing config response body")

	assert.Equal(suite.T(), len(config.EventsRequested), len(configResp.EventsDelivered), "Configuration set successfully")

	// save the updated state locally for the next tests
	suite.servers[0].stream = configResp
}

func (suite *ServerSuite) Test5a_PollStreamDelivery() {

	// Start server 2 and hopefully it polls!
	suite.setUpPollReceiverStream()

	rcvState, err := suite.servers[1].app.Provider.GetStreamState(suite.servers[1].stream.Id)
	assert.NoError(suite.T(), err, "Stream should be defined")
	assert.Equal(suite.T(), model.StreamStateActive, rcvState.Status, "Stream is active")

	testLog.Println("Doing an update to activate the POP client")
	config := suite.servers[1].stream
	bodyBytes, err := json.MarshalIndent(config, "", " ")
	assert.NoError(suite.T(), err, "JSON Marshalling error")

	streamUrl := fmt.Sprintf("http://%s/stream", suite.servers[1].server.Addr)
	req, err := http.NewRequest("POST", streamUrl, bytes.NewReader(bodyBytes))
	assert.NoError(suite.T(), err, "no request builder error")
	req.Header.Set("Authorization", "Bearer "+suite.servers[1].streamToken)

	resp, err := suite.servers[1].client.Do(req)
	assert.NoError(suite.T(), err, "Update request successful")
	assert.NotNil(suite.T(), resp, "Response is not null")

	var confgResp model.StreamConfiguration
	body, err := io.ReadAll(resp.Body)
	assert.NoError(suite.T(), err, "Check error reading config response body")
	err = json.Unmarshal(body, &confgResp)
	assert.NoError(suite.T(), err, "Check error parsing config response body")

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
	fmt.Println(fmt.Sprintf("S|R PUSH[%d|%d] POLL[%d|%d]", pushCnt1, rcvPushCnt1, pollCnt1, rcrPollCnt1))
	assert.Equal(suite.T(), 0, pushCnt1, "Should be no PUSH servers")
	// Includes the original from Test 3 plus the new one
	assert.Equal(suite.T(), 1, pollCnt1, "Should be 2 POLL server")

	// time.Sleep(5 * time.Second)
}

/*
Test5b_ResetStream tests the time reset functionality which causes the server to go through prior events and re-add them
to the stream
*/
func (suite *ServerSuite) Test5b_ResetStream() {
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

	// let's add an extra event so we have 2. This event will be deleted and re-added so no duplicates!
	jtiNew, err := suite.generateEvent(suite.servers[0].stream)

	// reset the stream on SSF1 to beginning of startup
	outboundStreamConfig.ResetDate = suite.servers[0].startTime

	testLog.Println("Resetting stream to beginning")
	// Post the new config with reset request to the handler
	streamUrl := fmt.Sprintf("http://%s/stream", suite.servers[0].server.Addr)
	bodyBytes, err := json.MarshalIndent(outboundStreamConfig, "", " ")
	assert.NoError(suite.T(), err, "JSON Marshalling error")
	req, err := http.NewRequest("POST", streamUrl, bytes.NewReader(bodyBytes))
	assert.NoError(suite.T(), err, "no request builder error")
	req.Header.Set("Authorization", "Bearer "+suite.servers[0].streamToken)
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

func (suite *ServerSuite) Test6_PushStreamDelivery() {
	testLog.Println("Setting up Push Receiver on SSF2")
	baseUrl := fmt.Sprintf("http://%s/stream", suite.servers[1].server.Addr)
	base, _ := url.Parse(baseUrl)
	base0Url := fmt.Sprintf("http://%s/stream", suite.servers[0].server.Addr)
	base0, _ := url.Parse(base0Url)
	jwksUrl, _ := url.Parse("/jwks/DEFAULT")
	jwksIssuer := base0.ResolveReference(jwksUrl)

	boolTrue := true
	reg := model.RegisterParameters{
		Audience:      []string{"test.example.com"},
		Issuer:        "DEFAULT",
		Inbound:       &boolTrue,
		Method:        model.DeliveryPush,
		RouteMode:     model.RouteModeImport,
		EventUris:     mongo_provider.GetSupportedEvents(),
		IssuerJWKSUrl: jwksIssuer.String(),
	}

	stream, err := suite.servers[1].provider.CreateStream(reg, "DEFAULT")
	assert.Nil(suite.T(), err, "No errors on stream creation")
	// state, _ := suite.servers[1].provider.GetStreamState(stream.Id)
	// suite.servers[1].app.HandleClientPollReceiver(state)

	streamToken1, _ := suite.servers[1].provider.IssueStreamToken(stream)
	suite.servers[1].stream = stream
	suite.servers[1].streamToken = streamToken1

	testLog.Println("Setting up Push Transmitter on SSF1")

	target, _ := url.Parse(stream.Delivery.PushDeliveryMethod.EndpointUrl)
	eventUrl := base.ResolveReference(target)
	reg = model.RegisterParameters{
		Audience:  []string{"test.example.com"},
		Issuer:    "DEFAULT",
		Method:    model.DeliveryPush,
		EventUris: mongo_provider.GetSupportedEvents(),
		EventUrl:  eventUrl.String(),
		EventAuth: streamToken1,
	}
	stream, err = suite.servers[0].provider.CreateStream(reg, "DEFAULT")
	assert.Nil(suite.T(), err, "No errors on stream creation")
	// state, _ := suite.servers[0].provider.GetStreamState(stream.Id)

	streamToken0, _ := suite.servers[0].provider.IssueStreamToken(stream)
	suite.servers[0].stream = stream
	suite.servers[0].streamToken = streamToken0

	testLog.Println("Push Stream Configured")

	// Now update stream to make it active
	config := suite.servers[0].stream

	testLog.Println("Updating SSF1 stream to make it active...")
	// Select all events
	config.EventsRequested = config.EventsSupported

	bodyBytes, err := json.MarshalIndent(config, "", " ")
	assert.NoError(suite.T(), err, "JSON Marshalling error")

	streamUrl := fmt.Sprintf("http://%s/stream", suite.servers[0].server.Addr)
	req, err := http.NewRequest("POST", streamUrl, bytes.NewReader(bodyBytes))
	assert.NoError(suite.T(), err, "no request builder error")
	req.Header.Set("Authorization", "Bearer "+suite.servers[0].streamToken)

	resp, err := suite.servers[0].client.Do(req)
	assert.NoError(suite.T(), err, "Update request successful")
	assert.NotNil(suite.T(), resp, "Response is not null")

	var confgResp model.StreamConfiguration
	body, err := io.ReadAll(resp.Body)
	assert.NoError(suite.T(), err, "Check error reading config response body")
	err = json.Unmarshal(body, &confgResp)
	assert.NoError(suite.T(), err, "Check error parsing config response body")

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
	fmt.Println(fmt.Sprintf("S|R PUSH[%d|%d] POLL[%d|%d]", pushCnt1, rcvPushCnt1, pollCnt1, rcrPollCnt1))
	assert.Equal(suite.T(), 1, pushCnt1, "Should be 1 PUSH servers")

	assert.Equal(suite.T(), 0, pollCnt1, "Should be 1 POLL server")

	testLog.Println("Resetting streams")
	suite.resetStreams(suite.servers[1].stream.Id, suite.servers[0].stream.Id)
	// time.Sleep(5 * time.Second)
}

/*
Test7_Prometheus checks that the prometheus stats counters are working and the counters are correct
TODO: Need to check guages for current stream counts
*/
func (suite *ServerSuite) Test7_Prometheus() {
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
		"type": "urn:ietf:params:event:SCIM:prov:create",
		"iss":  "DEFAULT",
		"tfr":  "PUSH",
	}
	var outCnt1, inCnt1 int

	cnt1, err := app1.Stats.EventsOut.GetMetricWith(label)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	in1, err := app1.Stats.EventsIn.GetMetricWith(label)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	if cnt1 != nil {
		outCnt1 = int(testutil.ToFloat64(cnt1))
		inCnt1 = int(testutil.ToFloat64(in1))
	}
	fmt.Println(fmt.Sprintf("SSF1 Event PUSH Count in: %v, out: %v", inCnt1, outCnt1))
	assert.Equal(suite.T(), 1, inCnt1, "SSF1 should have 1 PUSH inbound events")
	assert.Equal(suite.T(), 1, outCnt1, "SSF1 should have 1 PUSH outbound events")

	// Test the counters for PULL transfer
	label = prometheus.Labels{
		"type": "urn:ietf:params:event:SCIM:prov:create",
		"iss":  "DEFAULT",
		"tfr":  "POLL",
	}
	cnt1, err = app1.Stats.EventsOut.GetMetricWith(label)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	in1, err = app1.Stats.EventsIn.GetMetricWith(label)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	if cnt1 != nil {
		outCnt1 = int(testutil.ToFloat64(cnt1))
		inCnt1 = int(testutil.ToFloat64(in1))
	}
	fmt.Println(fmt.Sprintf("SSF1 Event POLL Count in: %v, out: %v", inCnt1, outCnt1))
	// should be 1 from test 5a plus 1 from 5b
	assert.Equal(suite.T(), 2, inCnt1, "SSF1 should have 2 POLL inbound events")
	assert.Equal(suite.T(), 1, outCnt1, "SSF1 should have 1 POLL outbound events")

	// Now look at SSF2
	var inCnt2, outCnt2 int
	label = prometheus.Labels{
		"type": "urn:ietf:params:event:SCIM:prov:create",
		"iss":  "DEFAULT",
		"tfr":  "PUSH",
	}

	cnt2, err := app2.Stats.EventsOut.GetMetricWith(label)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	in2, err := app2.Stats.EventsIn.GetMetricWith(label)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	if cnt2 != nil {
		outCnt2 = int(testutil.ToFloat64(cnt2))
		inCnt2 = int(testutil.ToFloat64(in2))
	}
	fmt.Println(fmt.Sprintf("SSF2 Event PUSH Count in: %v, out: %v", inCnt2, outCnt2))
	assert.Equal(suite.T(), 1, inCnt2, "SSF2 should have 1 PUSH inbound events")
	assert.Equal(suite.T(), 0, outCnt2, "SSF2 should have NO outbound events")

	pushCnt1 := int(testutil.ToFloat64(app1.Stats.PubPushCnt))
	pollCnt1 := int(testutil.ToFloat64(app1.Stats.PubPollCnt))
	rcvPushCnt1 := int(testutil.ToFloat64(app1.Stats.RcvPushCnt))
	rcrPollCnt1 := int(testutil.ToFloat64(app1.Stats.RcvPollCnt))

	fmt.Println(fmt.Sprintf("S|R PUSH[%d|%d] POLL[%d|%d]", pushCnt1, rcvPushCnt1, pollCnt1, rcrPollCnt1))
	assert.Equal(suite.T(), 0, pushCnt1, "Should be no PUSH servers")
	assert.Equal(suite.T(), 0, pollCnt1, "Should be no POLL server")
}

func (suite *ServerSuite) Test8_CreateIssuerKey() {
	testLog.Println("Creating new issuer key..")
	issuer := "example.com"
	baseUrl := fmt.Sprintf("http://%s/jwks/%s", suite.servers[0].server.Addr, issuer)

	req, _ := http.NewRequest(http.MethodPost, baseUrl, nil)
	resp, err := suite.servers[0].client.Do(req)
	assert.NoError(suite.T(), err, "No error generating key")
	assert.NotNil(suite.T(), resp, "A response was returned from issue key")

	body, _ := io.ReadAll(resp.Body)
	assert.NotNil(suite.T(), body, "A certificate was returned.")

	block, _ := pem.Decode(body)

	pkcs8PrivateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key := pkcs8PrivateKey.(*rsa.PrivateKey)
	assert.NoError(suite.T(), err, "private key decoded")

	fmt.Println("Creating and signing event with new key")
	subject := &goSet.EventSubject{
		SubjectIdentifier: goSet.SubjectIdentifier{
			Format:                    "scim",
			UniformResourceIdentifier: goSet.UniformResourceIdentifier{Uri: "?Users/1234"},
		},
	}
	set := goSet.CreateSet(subject, "example.com", []string{"someaudience"})
	payload_claims := map[string]interface{}{
		"aclaim": "avalue",
	}

	set.AddEventPayload("uri:testevent", payload_claims)

	val, err := set.JWS(jwt.SigningMethodRS256, key)

	assert.NoError(suite.T(), err, "key was signed!")
	assert.NotNil(suite.T(), val, "Signed value returned")
	fmt.Println("Signed event: \n" + val)
}

func (suite *ServerSuite) resetStreams(ssf2Stream, ssf1Stream string) {
	suite.servers[1].app.ClosePollReceiver(ssf2Stream)
	suite.servers[1].app.EventRouter.RemoveStream(ssf2Stream)
	_ = suite.servers[1].provider.DeleteStream(ssf2Stream)

	suite.servers[0].app.EventRouter.RemoveStream(ssf1Stream)
	_ = suite.servers[0].provider.DeleteStream(ssf1Stream)
}

func (suite *ServerSuite) setUpPollReceiverStream() {
	boolTrue := true
	stream := suite.servers[0].stream
	baseUrl := fmt.Sprintf("http://%s/stream", suite.servers[0].server.Addr)
	base, _ := url.Parse(baseUrl)
	target, _ := url.Parse(stream.Delivery.PollDeliveryMethod.EndpointUrl)
	targetJwks, _ := url.Parse(stream.IssuerJWKSUrl)
	issuerJwks := base.ResolveReference(targetJwks)
	eventUrl := base.ResolveReference(target)
	token := suite.servers[0].streamToken
	if !strings.Contains(strings.ToLower(token), "bearer ") {
		token = "Bearer " + token
	}
	req := model.RegisterParameters{
		Audience:      []string{"test.example.com"},
		Inbound:       &boolTrue,
		Method:        model.DeliveryPoll,
		RouteMode:     model.RouteModeImport,
		EventUrl:      eventUrl.String(),
		EventAuth:     token,
		EventUris:     stream.EventsSupported,
		IssuerJWKSUrl: issuerJwks.String(),
	}
	stream, _ = suite.servers[1].provider.CreateStream(req, "DEFAULT")
	state, _ := suite.servers[1].provider.GetStreamState(stream.Id)
	fmt.Println(fmt.Sprintf("StreamID [%s], StateID [%s]", stream.Id, state.StreamConfiguration.Id))
	suite.servers[1].app.HandleClientPollReceiver(state)
	streamToken, _ := suite.servers[1].provider.IssueStreamToken(stream)
	suite.servers[1].stream = stream
	suite.servers[1].streamToken = streamToken
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
	event.AddEventPayload("urn:ietf:params:event:SCIM:prov:create", payloadClaims)

	return event.ID, suite.servers[0].app.EventRouter.HandleEvent(&event, stream.Id)
}
