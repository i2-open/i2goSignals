package test

import (
	"bytes"
	"context"
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
	"testing"

	"github.com/MicahParks/keyfunc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

var TestDbUrl = "mongodb://root:dockTest@mongo1:30001,mongo2:30002,mongo3:30003/?retryWrites=true&replicaSet=dbrs&readPreference=primary&serverSelectionTimeoutMS=5000&connectTimeoutMS=10000&authSource=admin&authMechanism=SCRAM-SHA-256"

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

	log.Println("** Starting SSF1...")
	instance, err := createServer("ssf1")
	if err != nil {
		log.Printf("Error starting %s: %s", "ssf1", err.Error())
	}
	instances[0] = instance
	log.Println("** Starting SSF2...")
	instance, err = createServer("ssf2")
	if err != nil {
		log.Printf("Error starting %s: %s", "ssf1", err.Error())
	}
	instances[1] = instance
	serverSuite.servers = instances
	log.Println("** Setup Compelete **")

	suite.Run(t, &serverSuite)

	log.Println("** Shutting down test servers.. ")
	for _, instance := range serverSuite.servers {
		log.Printf("** Shutting down server %s...", instance.provider.Name())
		_ = instance.server.Shutdown(context.Background())
		instance.provider.Close()
	}
	log.Println("** TEST COMPLETE **")
}

func createServer(dbName string) (*ssfInstance, error) {
	var err error
	var instance ssfInstance
	mongo, err := mongo_provider.Open(TestDbUrl, dbName)
	if err != nil {
		fmt.Println("Mongo client error: " + err.Error())
		return nil, err
	}

	mongo.ResetDb(true)

	req := model.RegisterParameters{
		Audience: []string{"test.example.com"},
	}
	stream, _ := mongo.CreateStream(req, dbName)
	streamToken, err := mongo.IssueStreamToken(stream)
	if err != nil {
		return nil, err
	}

	instance.provider = mongo
	instance.streamToken = streamToken
	instance.stream = stream

	listener, _ := net.Listen("tcp", "localhost:0")
	signalsApplication := ssef.StartServer(listener.Addr().String(), instance.provider)
	instance.app = *signalsApplication
	instance.server = signalsApplication.Server
	instance.client = &http.Client{}

	go func() {
		signalsApplication.Server.Serve(listener)
	}()
	return &instance, nil
}

func (suite *ServerSuite) SetupTest() {
	log.Println("TEST!")
}

func (suite *ServerSuite) TearDownTest() {

}

func (suite *ServerSuite) Test1_Certificate() {
	url := fmt.Sprintf("http://%s/jwks.json", suite.servers[0].server.Addr)
	resp, err := http.Get(url)
	if err != nil {
		log.Println(err.Error())
	}
	body, _ := io.ReadAll(resp.Body)
	assert.NotNil(suite.T(), body, "A certificate was returned.")

	var rawJson json.RawMessage
	rawJson.UnmarshalJSON(body)

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
		log.Println(err.Error())
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
		log.Println(err.Error())
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
}

func (suite *ServerSuite) generateEvent(stream model.StreamConfiguration) {
	subject := &goSet.EventSubject{

		SubjectIdentifier: *goSet.NewScimSubjectIdentifier("/Users/44f6142df96bd6ab61e7521d9").AddExternalId("jdoe"),
	}

	event := goSet.CreateSetForStream(subject, stream)

	payload_claims := map[string]interface{}{
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
	event.AddEventPayload("urn:ietf:params:event:SCIM:prov:create", payload_claims)

	suite.servers[0].provider.AddEvent(&event, false)
}
