package test

import (
	"fmt"
	model "i2goSignals/internal/model"
	"i2goSignals/internal/providers/dbProviders/mongo_provider"
	"i2goSignals/pkg/goSet"
	"log"
	"os"
	"testing"

	"github.com/MicahParks/keyfunc"
	"github.com/stretchr/testify/assert"
)

type testData struct {
	provider    mongo_provider.MongoProvider
	stream      model.StreamConfiguration
	streamToken string
}

var data testData

func TestMain(m *testing.M) {
	var err error
	provider, err := mongo_provider.Open("mongodb://root:dockTest@0.0.0.0:8880")
	if err != nil {
		fmt.Println("Mongo client error: " + err.Error())
		return
	}

	provider.ResetDb(true)

	req := model.RegisterParameters{
		Audience: []string{"test.example.com"},
	}
	stream, _ := provider.RegisterStreamIssuer(req, "test.com")
	streamToken, err := provider.IssueStreamToken(stream)
	if err != nil {
		log.Println("Received error generating test token")
		ShutDown()
		os.Exit(-1)
	}
	data = testData{
		provider:    *provider,
		stream:      stream,
		streamToken: streamToken,
	}

	code := m.Run()

	ShutDown()

	os.Exit(code)
}

func ShutDown() {
	data.provider.Close()
}

func TestStreamConfig(t *testing.T) {
	assert.Equal(t, mongo_provider.CDbName, data.provider.Name(data.streamToken), "Confirm name is set")

	configs := data.provider.ListStreams()
	assert.Equal(t, 1, len(configs), "should be one registered")

	assert.Equal(t, data.stream.Id, configs[0].Id, "should be the same data.stream id")

	events := data.provider.GetEventIds(data.stream.Id, 5)
	assert.Equal(t, 0, len(events), "should be no events")

	id := data.stream.Id
	theConfig, err := data.provider.GetStream(id)
	assert.NoError(t, err, "Should be able to locate config id "+id)
	assert.Equal(t, id, theConfig.Id, "Retrieved config id matches")
}

func TestEvents(t *testing.T) {
	streams := make([]string, 1)
	streams[0] = data.stream.Id

	generateEvent(streams)

	// Check Events by data.stream id
	eventIds := data.provider.GetEventIds(data.stream.Id, 5)
	assert.Equal(t, 1, len(eventIds), "should be 1 event")

	// Check event collection (all data.streams)
	events := data.provider.GetEvents(eventIds)
	assert.Equal(t, 1, len(*events), "Should be 1 event")

	// Acknowledge should transfer pending event to acked event leaving no pending events
	data.provider.AckEvent(eventIds[0], data.stream.Id)

	nextIds := data.provider.GetEventIds(data.stream.Id, 5)
	assert.Equal(t, 0, len(nextIds), "Should be no pending events")

}

func TestStreams(t *testing.T) {
	streams := make([]string, 1)
	streams[0] = data.stream.Id
	generateEvent(streams)
	generateEvent(streams)
	generateEvent(streams)
	generateEvent(streams)
	generateEvent(streams)
	generateEvent(streams)

}

func generateEvent(ids []string) {
	subject := &goSet.EventSubject{
		SubjectIdentifier: *goSet.NewScimSubjectIdentifier("/Users/1234").AddUsername("huntp").AddEmail("phil.hunt@hexa.org"),
	}
	test1 := goSet.CreateSetForStream(subject, data.stream)
	payload_claims := map[string]interface{}{
		"aclaim": "avalue",
	}
	test1.AddEventPayload("uri:testevent", payload_claims)

	data.provider.AddEvent(&test1, ids)
}

func TestIssuerKeys(t *testing.T) {
	issuer := "i2test.example.org"
	key := data.provider.CreateIssuerJwkKeyPair(issuer)
	assert.NotNil(t, key, "Should be a key returned")

	keyRetrieved, err := data.provider.GetIssuerJWKS(issuer)
	assert.NoError(t, err, "Should be no error")
	assert.Equal(t, key, keyRetrieved, "Should be same key")

	keyFail, err := data.provider.GetIssuerJWKS("should.fail")
	assert.Error(t, err, "No key found for: should.fail")
	assert.Nil(t, keyFail, "Shoudl be no key returned")

	issPubJson := data.provider.GetPublicTransmitterJWKS(issuer)
	assert.NotNil(t, issPubJson, "Check public key returned")
	jwtbytes, err := issPubJson.MarshalJSON()

	log.Printf("\nIusser JWKS JSON:\n%v\n", string(jwtbytes))

	issPub, err := keyfunc.NewJSON(*issPubJson)
	assert.NoError(t, err, "No error parsing json into JWKS")
	assert.Contains(t, issPub.KIDs(), issuer, "Confirm issuer present")

}

func TestReceiverKeys(t *testing.T) {
	err := data.provider.StoreReceiverKey(data.stream.Id, "example.org", "https://example.org/jwksKey")
	assert.NoError(t, err)

	jwkrec := data.provider.GetReceiverKey(data.stream.Id)

	assert.NotNil(t, jwkrec)

	assert.Equal(t, "example.org", jwkrec.Aud)

	res := data.provider.GetReceiverKey("dummy")
	assert.Nil(t, res)
}
