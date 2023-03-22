package test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"i2goSignals/internal/model"
	"i2goSignals/internal/providers/dbProviders"
	"i2goSignals/internal/providers/dbProviders/mongo_provider"
	ssef "i2goSignals/pkg/goSSEF/server"
	"io"
	"log"
	"net"
	"net/http"
	"testing"

	"github.com/MicahParks/keyfunc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type ServerSuite struct {
	suite.Suite
	server      *http.Server
	provider    dbProviders.DbProviderInterface
	stream      model.StreamConfiguration
	app         ssef.SignalsApplication
	streamToken string
}

func TestServer(t *testing.T) {

	suite.Run(t, new(ServerSuite))

}

func (suite *ServerSuite) SetupTest() {

	var err error
	mongo, err := mongo_provider.Open("mongodb://root:dockTest@0.0.0.0:8880")
	if err != nil {
		fmt.Println("Mongo client error: " + err.Error())
		return
	}

	mongo.ResetDb(true)

	req := model.RegisterParameters{
		Audience: []string{"test.example.com"},
	}
	stream, _ := mongo.RegisterStreamIssuer(req, "test.com")
	streamToken, err := mongo.IssueStreamToken(stream)
	if err != nil {
		suite.Fail("Received error generating test token: " + err.Error())
	}

	var dbProv dbProviders.DbProviderInterface
	dbProv = mongo
	suite.provider = dbProv
	suite.streamToken = streamToken
	suite.stream = stream

	listener, _ := net.Listen("tcp", "localhost:0")
	signalsApplication := ssef.StartServer(listener.Addr().String(), suite.provider)
	suite.app = *signalsApplication
	suite.server = signalsApplication.Server

	go func() {
		signalsApplication.Server.Serve(listener)
	}()

}

func (suite *ServerSuite) TearDownTest() {
	log.Println("Shutting down test server and provider.")
	_ = suite.server.Shutdown(context.Background())

	suite.provider.Close()
}

func (suite *ServerSuite) Test1_Certificate() {
	url := fmt.Sprintf("http://%s/jwks.json", suite.server.Addr)
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

	url = fmt.Sprintf("http://%s/jwks/DEFAULT", suite.server.Addr)
	issPub3, err := keyfunc.Get(url, keyfunc.Options{})
	assert.NoError(suite.T(), err, "Check no error keyfunc retrieval of /jwks/issuer")
	assert.Equal(suite.T(), body, issPub3.RawJWKS(), "Check JWKS issuers are equal")
}

func (suite *ServerSuite) Test2_WellKnownConfigs() {
	url := fmt.Sprintf("http://%s/.well-known/sse-configuration", suite.server.Addr)
	resp, err := http.Get(url)
	if err != nil {
		log.Println(err.Error())
	}
	body, _ := io.ReadAll(resp.Body)
	var config model.TransmitterConfiguration
	err = json.Unmarshal(body, &config)
	assert.NoError(suite.T(), err, "Configuration parsed and returned")

	assert.Equal(suite.T(), suite.app.HostName+"/stream", config.ConfigurationEndpoint, "Configuration endpoint matches")
	assert.Equal(suite.T(), "DEFAULT", config.Issuer, "Default issuer matched")
}

func (suite *ServerSuite) Test3_StreamConfig() {
	url := fmt.Sprintf("http://%s/.well-known/sse-configuration", suite.server.Addr)
	resp, err := http.Get(url)
	if err != nil {
		log.Println(err.Error())
	}
	body, _ := io.ReadAll(resp.Body)
	var config model.TransmitterConfiguration
	err = json.Unmarshal(body, &config)

	regUrl := fmt.Sprintf("http://%s/register", suite.server.Addr)
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
