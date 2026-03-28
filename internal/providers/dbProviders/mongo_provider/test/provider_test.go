package test

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/mongo_provider"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/suite"
)

type MongoProviderSuite struct {
	suite.Suite
	provider    mongo_provider.MongoProvider
	stream      model.StreamConfiguration
	projectIat  string
	streamToken string
	mgmtToken   string
	project     string
	auth        *authUtil.AuthIssuer
}

func (s *MongoProviderSuite) SetupSuite() {
	s.T().Helper()
	provider, err := mongo_provider.Open(TestDbUrl, "")
	if err != nil {
		s.T().Skip("Mongo client error: " + err.Error())
		return
	}

	if err := provider.Check(); err != nil {
		s.T().Skip("Mongo Server not available: " + err.Error())
		return
	}

	if provider != nil {
		err = provider.ResetDb(true)
		if err != nil {
			s.FailNow("Received error generating test token: " + err.Error())
		}

		s.provider = *provider
		s.auth = provider.GetAuthIssuer()

		s.InitStream([]string{"*"})
	}

}

func (s *MongoProviderSuite) TearDownSuite() {
	_ = s.provider.Close()
}

func (s *MongoProviderSuite) InitStream(events []string) {
	var err error

	// Create a polling transmitter stream
	req := model.StreamConfiguration{
		Aud: []string{"test.example.com"},
		Iss: "test.com",
	}

	method := &model.PollTransmitMethod{Method: model.DeliveryPoll}

	req.Delivery = &model.OneOfStreamConfigurationDelivery{PollTransmitMethod: method}

	iat, err := s.auth.IssueProjectIat(nil)
	if err != nil {
		s.FailNow(err.Error())
	}
	s.projectIat = iat

	tkn, err := s.auth.ParseAuthToken(s.projectIat)
	if err != nil {
		s.FailNow(err.Error())
	}
	if tkn == nil {
		s.FailNow("ERROR: Stream initialization: IAT token is nil")
	}
	s.project = tkn.ProjectId

	if len(events) > 0 {
		req.EventsRequested = events
	}
	s.stream, _ = s.provider.CreateStream(req, authUtil.ConvertProject(s.project))
}

func TestMongoProvider(t *testing.T) {
	suite.Run(t, new(MongoProviderSuite))
}

var TestDbUrl = "mongodb://root:dockTest@mongo1:30001,mongo2:30002,mongo3:30003/?retryWrites=true&replicaSet=dbrs&readPreference=primary&serverSelectionTimeoutMS=5000&connectTimeoutMS=10000&authSource=admin&authMechanism=SCRAM-SHA-256"

func (s *MongoProviderSuite) TestA_ClientReg() {
	// Get an initial registration token
	var err error

	client := model.SsfClient{
		ProjectIds:    []string{s.project},
		Email:         "admin@example.com",
		Description:   "this is a test",
		AllowedScopes: []string{authSupport.ScopeStreamMgmt, authSupport.ScopeEventDelivery},
	}

	resp := s.provider.RegisterClient(client, s.project)
	s.NotNil(resp, "Client registration response return check")
	s.mgmtToken = resp.Token
	tkn, err := s.auth.ParseAuthToken(s.mgmtToken)
	s.Nil(err, "taken parse check")
	s.NotNil(tkn, "mgmt token is valid check")

	s.streamToken, err = s.auth.IssueStreamToken(s.stream.Id, s.project)
	s.Nil(err, "issue stream token error check")
}

// TestB_StreamConfig tests the provider to list streams, verifies configuration, and basic get events functionality
func (s *MongoProviderSuite) TestB_StreamConfig() {
	s.Equal(mongo_provider.CDbName, s.provider.Name(), "Confirm name is set")

	configs := s.provider.ListStreams()
	s.Equal(1, len(configs), "should be one registered")

	s.Equal(s.stream.Id, configs[0].Id, "should be the same s.stream id")
	s.Equal(26, len(configs[0].EventsDelivered), "Should be 26 events configured for delivery")
	events, _ := s.provider.GetEventIds(s.stream.Id, model.PollParameters{
		MaxEvents: 5, ReturnImmediately: true,
	})
	s.Equal(0, len(events), "should be no events")

	id := s.stream.Id
	theConfig, err := s.provider.GetStream(id)
	s.NoError(err, "Should be able to locate config id "+id)
	s.Equal(id, theConfig.Id, "Retrieved config id matches")
}

// TestC_PollEvents tests that the Polling transmitter receives the events being added. For this test
// short polling (return immediately) is used
func (s *MongoProviderSuite) TestC_PollEvents() {
	streams := make([]string, 1)
	streams[0] = s.stream.Id

	s.generateEvent()

	// Check Events by s.stream id
	eventIds, _ := s.provider.GetEventIds(s.stream.Id, model.PollParameters{MaxEvents: 5, ReturnImmediately: true})
	s.Equal(1, len(eventIds), "should be 1 event")

	if len(eventIds) == 0 {
		return
	}
	// Check event collection (all s.streams)
	events := s.provider.GetEvents(eventIds)
	s.Equal(1, len(events), "Should be 1 event")

	// Acknowledge should transfer pending event to acked event leaving no pending events
	_ = s.provider.AckEvent(eventIds[0], s.stream.Id, 0)

	nextIds, _ := s.provider.GetEventIds(s.stream.Id, model.PollParameters{MaxEvents: 5, ReturnImmediately: true})
	s.Equal(0, len(nextIds), "Should be no pending events")

	s.generateEvent()
	s.generateEvent()
	s.generateEvent()
	s.generateEvent()
	s.generateEvent()
	s.generateEvent()

	nextIds, _ = s.provider.GetEventIds(s.stream.Id, model.PollParameters{MaxEvents: 5, ReturnImmediately: true})
	s.Equal(5, len(nextIds), "Should be 5 max events")
	s.ackEvents(nextIds)

	finalIds, _ := s.provider.GetEventIds(s.stream.Id, model.PollParameters{MaxEvents: 5, ReturnImmediately: true})
	s.Equal(1, len(finalIds), "should be 1 event")
	_ = s.provider.AckEvent(finalIds[0], s.stream.Id, 0)
}

// TestD_PollingCycle starts an independent thread that generates events over time. The test goes through repeat
// polling cycles to test long polling and other features.
func (s *MongoProviderSuite) TestD_PollingCycle() {
	// streams := make([]string, 1)
	// streams[0] = s.stream.Id

	// Generate a sequence of events with 2 sec delay between pairs of events
	go s.generateEventsOverTime()

	var eventIds []string
	s.Eventually(func() bool {
		eventIds, _ = s.provider.GetEventIds(s.stream.Id, model.PollParameters{MaxEvents: 2, ReturnImmediately: true})
		return len(eventIds) > 0
	}, 15*time.Second, 500*time.Millisecond)

	count := len(eventIds)
	log.Printf("Total events returned from first get: %v", count)
	s.Truef(count > 0, "Should be at least 1 event (actual: %v)", count)
	s.ackEvents(eventIds)

	events := eventIds
	callCount := 0
	for len(events) < 10 && callCount < 30 {
		log.Println("\nPolling for next events...")
		nextIds, _ := s.provider.GetEventIds(s.stream.Id, model.PollParameters{MaxEvents: 100, ReturnImmediately: true})
		if len(nextIds) == 0 {
			time.Sleep(1 * time.Second)
			continue
		}
		events = append(events, nextIds...)
		callCount++
		log.Printf("...\tPoll# %v, received %v events\n", callCount, len(nextIds))
		s.ackEvents(nextIds)
	}

	s.Truef(callCount < 30, "Too many calls required")
	s.Equal(10, len(events), "Should be 10 total events")

	if len(events) == 0 {
		s.FailNow("No events collected")
	}

	sets := s.provider.GetEvents(events)

	s.Equal(len(events), len(sets), "Sets return matches GetEvents")
	tokenRef := sets[0]
	set := *tokenRef
	s.Equal(s.stream.Iss, set.Issuer, "Issuer is matched")
}

func (s *MongoProviderSuite) ackEvents(ids []string) {
	for _, id := range ids {
		if id != "" {
			_ = s.provider.AckEvent(id, s.stream.Id, 0)
		}
	}
}

func (s *MongoProviderSuite) TestE_Streams() {
	// streams := make([]string, 1)
	// streams[0] = s.stream.Id
	s.generateEvent()
	s.generateEvent()
	s.generateEvent()
	s.generateEvent()
	s.generateEvent()
	s.generateEvent()

}

func (s *MongoProviderSuite) generateEventsOverTime() {
	for i := 0; i < 5; i++ {
		time.Sleep(2 * time.Second)
		log.Println(" ... adding 2 events")
		s.generateEvent()
		s.generateEvent()
	}
	log.Println("*** event generation complete ***")
}

func (s *MongoProviderSuite) generateEvent() {
	subject := &goSet.EventSubject{
		SubjectIdentifier: *goSet.NewScimSubjectIdentifier("/Users/1234").AddUsername("hunt").AddEmail("phil.hunt@hexa.org"),
	}
	test1 := goSet.CreateSet(subject, s.stream.Iss, s.stream.Aud)
	payloadClaims := map[string]interface{}{
		"aClaim": "aValue",
	}
	test1.AddEventPayload("https://schemas.openid.net/secevent/sse/event-type/verification", payloadClaims)

	_, _ = s.provider.AddEvent(&test1, "", "")

	state, _ := s.provider.GetStreamState(s.stream.Id)

	_ = s.provider.AddEventToStream(test1.ID, state.Id)
}

func (s *MongoProviderSuite) TestF1_IssuerKeys() {
	issuer := "i2test.example.org"
	key, err := s.provider.CreateKeyPair(issuer, "sig", "")
	s.NoError(err)
	s.NotNil(key, "Should be a key returned")

	keyRetrieved, err := s.provider.GetPrivateKey(issuer)
	s.NoError(err, "Should be no error")
	s.NotNil(keyRetrieved)
	s.True(key.Equal(keyRetrieved), "Should be same key")

	keyFail, err := s.provider.GetPrivateKey("should.fail")
	s.Error(err, "No key found for: should.fail")
	s.Nil(keyFail, "Should be no key returned")

	issPubJson := s.provider.GetPublicJWKS(issuer)
	s.NotNil(issPubJson, "Check public key returned")
	jwtBytes, err := issPubJson.MarshalJSON()

	log.Printf("\nIusser JWKS JSON:\n%v\n", string(jwtBytes))

	s.NotNil(issPubJson, "Check public key returned")
	if issPubJson != nil {
		issPub, err := keyfunc.NewJSON(*issPubJson)
		s.NoError(err, "No error parsing json into JWKS")
		s.Contains(issPub.KIDs(), issuer, "Confirm issuer present")
	}

	keys := s.provider.ListKeyNames()
	s.Len(keys, 2, "Should be 2 keys")
	s.Contains(keys, issuer, "Confirm issuer i2test.example.org present")
	s.Contains(keys, "DEFAULT", "Confirm issuer DEFAULT present")

}

func (s *MongoProviderSuite) TestF2_AddIssuerKey() {
	issuer := "addkey-test.example.org"
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Test adding private key
	err := s.provider.AddKey(issuer, "sig", "key-1", privateKey, nil, "")
	s.NoError(err)

	keyRetrieved, err := s.provider.GetPrivateKey(issuer)
	s.NoError(err)
	s.NotNil(keyRetrieved)
	s.True(privateKey.Equal(keyRetrieved))

	// Test adding only public key
	issuerPub := "addkey-pub.example.org"
	err = s.provider.AddKey(issuerPub, "sig", "key-pub", nil, &privateKey.PublicKey, "")
	s.NoError(err)

	issPubJson := s.provider.GetPublicJWKS(issuerPub)
	s.NotNil(issPubJson)
	if issPubJson != nil {
		issPub, err := keyfunc.NewJSON(*issPubJson)
		s.NoError(err)
		s.Contains(issPub.KIDs(), "key-pub")
	}

	// Verify private key is NOT there
	keyFail, err := s.provider.GetPrivateKey(issuerPub)
	s.Error(err)
	s.Nil(keyFail)
}

func (s *MongoProviderSuite) TestG_ReceiverKeys() {
	err := s.provider.StoreExternalKey("example.org", s.stream.Id, "sig", "https://example.org/jwksKey")
	s.NoError(err)

	jwkRecord := s.provider.GetKeyByStreamID(s.stream.Id)

	s.NotNil(jwkRecord)

	s.Equal("example.org", jwkRecord.KeyName)

	res := s.provider.GetKeyByStreamID("dummy")
	s.Nil(res)
}

// TestH_StreamManagement tests the ability to update streams and delete them
func (s *MongoProviderSuite) TestH_StreamManagement() {
	sid := s.stream.Id
	orig := s.stream
	config := model.StreamConfiguration{
		Id:              sid,
		Iss:             "meh",
		Aud:             []string{"test"},
		EventsRequested: []string{"abc"},
		Delivery:        orig.Delivery,
		Format:          orig.Format,
	}

	_, err := s.provider.UpdateStream("1234", s.project, config)
	s.Error(err, "not found")

	res, err := s.provider.UpdateStream(sid, s.project, config)
	s.NoError(err, "Update should have no error")
	s.Equal(orig.Aud, res.Aud, "Audience should not change")
	s.Equal(orig.Iss, res.Iss, "Issuer should not change")
	s.Equal([]string{"abc"}, res.EventsRequested, "Event should be abc")
	s.Equal(0, len(res.EventsDelivered), "Should be no delivered events")

	res.EventsRequested = res.EventsSupported // request all events
	res2, err := s.provider.UpdateStream(sid, s.project, *res)
	s.NoError(err, "2nd Update should have no error")
	s.Equal(res.EventsSupported, res2.EventsDelivered, "All events enabled")

	err = s.provider.DeleteStream(s.stream.Id)
	s.NoError(err, "Delete should be successful")

	supportedEvents := model.GetSupportedEvents()
	s.InitStream(supportedEvents)
	s.Equal(len(supportedEvents), len(s.stream.EventsDelivered), "All events enabled")
}
