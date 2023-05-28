package test

import (
	"bytes"
	"encoding/json"
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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
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
}

type ServerSuite struct {
	suite.Suite
	servers []*ssfInstance
}

func TestServer(t *testing.T) {
	serverSuite := ServerSuite{}

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

	signalsApplication := ssef.StartServer(listener.Addr().String(), &*mongo)
	instance.app = *signalsApplication
	instance.server = signalsApplication.Server
	instance.client = &http.Client{}
	instance.provider = mongo

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
	url := fmt.Sprintf("http://%s/jwks.json", suite.servers[0].server.Addr)
	resp, err := http.Get(url)
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
	issPub2, err := keyfunc.Get(url, keyfunc.Options{})
	assert.NoError(suite.T(), err, "Keyfunc retrieval had no error")

	assert.Equal(suite.T(), body, issPub2.RawJWKS(), "Check JWKS issuers are equal")

	url = fmt.Sprintf("http://%s/jwks/DEFAULT", suite.servers[0].server.Addr)
	issPub3, err := keyfunc.Get(url, keyfunc.Options{})
	assert.NoError(suite.T(), err, "Check no error keyfunc retrieval of /jwks/issuer")
	assert.Equal(suite.T(), body, issPub3.RawJWKS(), "Check JWKS issuers are equal")
}

func (suite *ServerSuite) Test2_WellKnownConfigs() {
	url := fmt.Sprintf("http://%s/.well-known/sse-configuration", suite.servers[0].server.Addr)
	resp, err := http.Get(url)
	if err != nil {
		testLog.Println(err.Error())
	}
	body, _ := io.ReadAll(resp.Body)
	var config model.TransmitterConfiguration
	err = json.Unmarshal(body, &config)
	assert.NoError(suite.T(), err, "Configuration parsed and returned")

	assert.Equal(suite.T(), suite.servers[0].app.HostName+"/stream", config.ConfigurationEndpoint, "Configuration endpoint matches")
	assert.Equal(suite.T(), "DEFAULT", config.Issuer, "Default issuer matched")
}

func (suite *ServerSuite) Test3_StreamConfig() {
	url := fmt.Sprintf("http://%s/.well-known/sse-configuration", suite.servers[0].server.Addr)
	resp, err := http.Get(url)
	if err != nil {
		testLog.Println(err.Error())
	}
	body, _ := io.ReadAll(resp.Body)
	var config model.TransmitterConfiguration
	err = json.Unmarshal(body, &config)

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

	var confgResp model.StreamConfiguration
	body, err = io.ReadAll(resp.Body)
	assert.NoError(suite.T(), err, "No error reading config response body")
	err = json.Unmarshal(body, &confgResp)
	assert.NoError(suite.T(), err, "No error parsing config response body")

	assert.Equal(suite.T(), len(config.EventsRequested), len(confgResp.EventsDelivered), "Configuration set successfully")

	// save the updated state locally for the next tests
	suite.servers[0].stream = confgResp
}

func (suite *ServerSuite) Test5_PopStreamDelivery() {

	// Start server 2 and hopefully it polls!
	suite.setUpPopReceiverStream()

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

	testLog.Println("Resetting streams")
	suite.resetStreams(suite.servers[1].stream.Id, suite.servers[1].stream.Id)
	// time.Sleep(5 * time.Second)
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

	testLog.Println("Resetting streams")
	suite.resetStreams(suite.servers[1].stream.Id, suite.servers[1].stream.Id)
	// time.Sleep(5 * time.Second)
}

/*
Test7_Prometheus checks that the prometheus stats counters are working and the counters are correct
TODO: Need to check guages for current stream counts
*/
func (suite *ServerSuite) Test7_Prometheus() {
	app1 := suite.servers[0].app
	app2 := suite.servers[1].app

	metricName := app1.Name() + "_goSignals_events"
	outCounters1 := testutil.CollectAndCount(app1.EventsOut, metricName+"_out")
	inCounters1 := testutil.CollectAndCount(app1.EventsIn, metricName+"_in")
	// fmt.Println(fmt.Sprintf("SSF1 Counters in: %d, out: %d", inCounters1, outCounters1))
	assert.Equal(suite.T(), 1, outCounters1, "One event out counter registered")
	assert.Equal(suite.T(), 1, inCounters1, "One event in counter registered")

	outCnt1 := int(testutil.ToFloat64(app1.EventsOut))
	inCnt1 := int(testutil.ToFloat64(app1.EventsIn))
	fmt.Println(fmt.Sprintf("SSF1 Event Count in: %v, out: %v", inCnt1, outCnt1))
	assert.Equal(suite.T(), 2, inCnt1, "SSF1 should have 2 inbound events")
	assert.Equal(suite.T(), 2, outCnt1, "SSF1 should have 2 outbound events")

	outCnt2 := int(testutil.ToFloat64(app2.EventsOut))
	inCnt2 := int(testutil.ToFloat64(app2.EventsIn))
	fmt.Println(fmt.Sprintf("SSF2 Event Count in: %v, out: %v", inCnt2, outCnt2))
	assert.Equal(suite.T(), 2, inCnt2, "SSF2 should have 2 inbound events")
	assert.Equal(suite.T(), 0, outCnt2, "SSF2 should have NO outbound events")

}

func collectAndCount(counter prometheus.Counter, metric_name string) int {
	return testutil.CollectAndCount(counter, metric_name)

}

func (suite *ServerSuite) resetStreams(streamReceive, streamSend string) {
	suite.servers[1].app.ClosePollReceiver(streamReceive)
	suite.servers[1].app.EventRouter.RemoveStream(streamReceive)
	suite.servers[1].provider.DeleteStream(streamReceive)

	suite.servers[0].app.EventRouter.RemoveStream(streamSend)
	suite.servers[0].provider.DeleteStream(streamSend)
}

func (suite *ServerSuite) setUpPopReceiverStream() {
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
