package test

import (
	"fmt"
	"i2goSignals/internal/model"
	"i2goSignals/internal/providers/dbProviders/mongo_provider"
	"i2goSignals/pkg/goSet"
	"log"
	"os"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/stretchr/testify/assert"
)

type testData struct {
	provider    mongo_provider.MongoProvider
	stream      model.StreamConfiguration
	streamToken string
}

func (t *testData) InitStream(events []string) {
	req := model.RegisterParameters{
		Audience: []string{"test.example.com"},
	}
	t.stream, _ = t.provider.CreateStream(req, "test.com")
	t.streamToken, _ = t.provider.IssueStreamToken(t.stream)

	if len(events) > 0 {
		t.stream.EventsRequested = events
		result, err := t.provider.UpdateStream(t.stream.Id, t.stream)
		if err != nil {
			log.Println("ERROR: " + err.Error())
		}
		t.stream = *result
	}

}

var TestDbUrl = "mongodb://root:dockTest@mongo1:30001,mongo2:30002,mongo3:30003/?retryWrites=true&replicaSet=dbrs&readPreference=primary&serverSelectionTimeoutMS=5000&connectTimeoutMS=10000&authSource=admin&authMechanism=SCRAM-SHA-256"

var data testData

func TestMain(m *testing.M) {
	var err error
	provider, err := mongo_provider.Open(TestDbUrl, "")
	if err != nil {
		fmt.Println("Mongo client error: " + err.Error())
		return
	}

	_ = provider.ResetDb(true)

	if err != nil {
		log.Println("Received error generating test token")
		ShutDown()
		os.Exit(-1)
	}
	data = testData{
		provider: *provider,
	}
	data.InitStream([]string{"*"})

	code := m.Run()

	ShutDown()

	os.Exit(code)
}

func ShutDown() {
	_ = data.provider.Close()
}

func TestStreamConfig(t *testing.T) {
	assert.Equal(t, mongo_provider.CDbName, data.provider.Name(), "Confirm name is set")

	configs := data.provider.ListStreams()
	assert.Equal(t, 1, len(configs), "should be one registered")

	assert.Equal(t, data.stream.Id, configs[0].Id, "should be the same data.stream id")
	assert.Equal(t, 14, len(configs[0].EventsDelivered), "Should be 14 events configured for delivery")
	events, _ := data.provider.GetEventIds(data.stream.Id, model.PollParameters{
		MaxEvents: 5, ReturnImmediately: true,
	})
	assert.Equal(t, 0, len(events), "should be no events")

	id := data.stream.Id
	theConfig, err := data.provider.GetStream(id)
	assert.NoError(t, err, "Should be able to locate config id "+id)
	assert.Equal(t, id, theConfig.Id, "Retrieved config id matches")
}

func TestEvents(t *testing.T) {
	streams := make([]string, 1)
	streams[0] = data.stream.Id

	generateEvent()

	// Check Events by data.stream id
	eventIds, _ := data.provider.GetEventIds(data.stream.Id, model.PollParameters{MaxEvents: 5, ReturnImmediately: true})
	assert.Equal(t, 1, len(eventIds), "should be 1 event")

	if len(eventIds) == 0 {
		return
	}
	// Check event collection (all data.streams)
	events := data.provider.GetEvents(eventIds)
	assert.Equal(t, 1, len(events), "Should be 1 event")

	// Acknowledge should transfer pending event to acked event leaving no pending events
	data.provider.AckEvent(eventIds[0], data.stream.Id)

	nextIds, _ := data.provider.GetEventIds(data.stream.Id, model.PollParameters{MaxEvents: 5, ReturnImmediately: true})
	assert.Equal(t, 0, len(nextIds), "Should be no pending events")

	generateEvent()
	generateEvent()
	generateEvent()
	generateEvent()
	generateEvent()
	generateEvent()

	nextIds, _ = data.provider.GetEventIds(data.stream.Id, model.PollParameters{MaxEvents: 5, ReturnImmediately: true})
	assert.Equal(t, 5, len(nextIds), "Should be 5 max events")
	ackEvents(nextIds)

	finalIds, _ := data.provider.GetEventIds(data.stream.Id, model.PollParameters{MaxEvents: 5, ReturnImmediately: true})
	assert.Equal(t, 1, len(finalIds), "should be 1 event")
	data.provider.AckEvent(finalIds[0], data.stream.Id)
}

func TestPolling(t *testing.T) {
	streams := make([]string, 1)
	streams[0] = data.stream.Id

	go generateEventsOverTime()

	eventIds, _ := data.provider.GetEventIds(data.stream.Id, model.PollParameters{MaxEvents: 2, ReturnImmediately: false, TimeoutSecs: 15})
	count := len(eventIds)
	log.Printf("Total events returned from first get: %v", count)
	assert.Truef(t, count > 0, "Should be at least 1 event (actual: %v)", count)
	ackEvents(eventIds)

	events := eventIds
	callCount := 0
	for len(events) < 10 && callCount < 6 {
		log.Println("\nPolling for next events...")
		nextIds, _ := data.provider.GetEventIds(data.stream.Id, model.PollParameters{MaxEvents: 100, ReturnImmediately: false, TimeoutSecs: 5})
		events = append(events, nextIds...)
		callCount++
		log.Printf("...\tPoll# %v, received %v events\n", callCount, len(nextIds))
		ackEvents(nextIds)
	}

	assert.Truef(t, callCount < 6, "Too many calls required")
	assert.Equal(t, 10, len(events), "Should be 10 total events")

	sets := data.provider.GetEvents(events)

	assert.Equal(t, len(events), len(sets), "Sets return matches getevents")
	tokenRef := sets[0]
	set := *tokenRef
	assert.Equal(t, data.stream.Iss, set.Issuer, "Issuer is matched")
}

func ackEvents(ids []string) {
	for _, id := range ids {
		if id != "" {
			data.provider.AckEvent(id, data.stream.Id)
		}
	}
}

func TestStreams(t *testing.T) {
	streams := make([]string, 1)
	streams[0] = data.stream.Id
	generateEvent()
	generateEvent()
	generateEvent()
	generateEvent()
	generateEvent()
	generateEvent()

}

func generateEventsOverTime() {
	for i := 0; i < 5; i++ {
		time.Sleep(2 * time.Second)
		log.Println(" ... adding 2 events")
		generateEvent()
		generateEvent()
	}
	log.Println("*** event generation complete ***")
}

func generateEvent() {
	subject := &goSet.EventSubject{
		SubjectIdentifier: *goSet.NewScimSubjectIdentifier("/Users/1234").AddUsername("huntp").AddEmail("phil.hunt@hexa.org"),
	}
	test1 := goSet.CreateSet(subject, data.stream.Iss, data.stream.Aud)
	payloadClaims := map[string]interface{}{
		"aclaim": "avalue",
	}
	test1.AddEventPayload("https://schemas.openid.net/secevent/sse/event-type/verification", payloadClaims)

	data.provider.AddEvent(&test1, "", "")

	state, _ := data.provider.GetStreamState(data.stream.Id)

	data.provider.AddEventToStream(test1.ID, state.Id)
}

func TestIssuerKeys(t *testing.T) {
	issuer := "i2test.example.org"
	key := data.provider.CreateIssuerJwkKeyPair(issuer)
	assert.NotNil(t, key, "Should be a key returned")

	keyRetrieved, err := data.provider.GetIssuerPrivateKey(issuer)
	assert.NoError(t, err, "Should be no error")
	assert.Equal(t, key, keyRetrieved, "Should be same key")

	keyFail, err := data.provider.GetIssuerPrivateKey("should.fail")
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

func TestStreamManagement(t *testing.T) {
	sid := data.stream.Id
	orig := data.stream
	config := model.StreamConfiguration{
		Id:              sid,
		Iss:             "bleh",
		Aud:             []string{"test"},
		EventsRequested: []string{"abc"},
		Delivery:        orig.Delivery,
		Format:          orig.Format,
	}

	_, err := data.provider.UpdateStream("1234", config)
	assert.Error(t, err, "not found")

	res, err := data.provider.UpdateStream(sid, config)
	assert.NoError(t, err, "Update should have no error")
	assert.Equal(t, orig.Aud, res.Aud, "Audience should not change")
	assert.Equal(t, orig.Iss, res.Iss, "Issuer should not change")
	assert.Equal(t, []string{"abc"}, res.EventsRequested, "Event should be abc")
	assert.Equal(t, 0, len(res.EventsDelivered), "Should be no delivered events")

	res.EventsRequested = res.EventsSupported // request all events
	res2, err := data.provider.UpdateStream(sid, *res)
	assert.NoError(t, err, "2nd Update should have no error")
	assert.Equal(t, res.EventsSupported, res2.EventsDelivered, "All events enabled")

	err = data.provider.DeleteStream(data.stream.Id)
	assert.NoError(t, err, "Delete should be successful")

	supportedEvents := mongo_provider.GetSupportedEvents()
	data.InitStream(supportedEvents)
	assert.Equal(t, len(supportedEvents), len(data.stream.EventsDelivered), "All events enabled")
}
