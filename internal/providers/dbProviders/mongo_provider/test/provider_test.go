package test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"log"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/mongo_provider"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/suite"
)

type MongoProviderSuite struct {
	suite.Suite
	provider    *mongo_provider.MongoProvider
	stream      model.StreamConfiguration
	projectIat  string
	streamToken string
	mgmtToken   string
	project     string
	auth        *authSupport.AuthIssuer
}

func (s *MongoProviderSuite) SetupSuite() {
	s.T().Helper()
	setMongoResumeFileTempDir(s.T())
	provider, err := mongo_provider.Open(mongoURL(), "")
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

		s.provider = provider
		s.auth = provider.GetKeyService().GetAuthIssuer()

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
	authCtx := authSupport.ConvertProject(s.project)
	ctx := context.WithValue(context.Background(), authSupport.AuthContextKey, authCtx)
	s.stream, _ = s.provider.GetStreamService().CreateStream(ctx, model.StreamStateRecord{StreamConfiguration: req}, authCtx.ProjectId, nil)
}

func TestMongoProvider(t *testing.T) {
	suite.Run(t, new(MongoProviderSuite))
}

func (s *MongoProviderSuite) TestA_ClientReg() {
	// Get an initial registration token
	var err error

	client := model.SsfClient{
		ProjectIds:    []string{s.project},
		Email:         "admin@example.com",
		Description:   "this is a test",
		AllowedScopes: []string{authSupport.ScopeStreamMgmt, authSupport.ScopeEventDelivery},
	}

	resp := s.provider.GetClientService().RegisterClient(context.Background(), client, s.project, "")
	s.NotNil(resp, "Client registration response return check")
	s.mgmtToken = resp.Token
	tkn, err := s.auth.ParseAuthToken(s.mgmtToken)
	s.Nil(err, "taken parse check")
	s.NotNil(tkn, "mgmt token is valid check")

	s.streamToken, err = s.auth.IssueStreamToken(s.stream.Id, s.project, nil)
	s.Nil(err, "issue stream token error check")
}

// TestB_StreamConfig tests the provider to list streams, verifies configuration, and basic get events functionality
func (s *MongoProviderSuite) TestB_StreamConfig() {
	s.Equal(mongo_provider.CDbName, s.provider.Name(), "Confirm name is set")

	configs := s.provider.GetStreamService().ListStreams(context.Background())
	s.Equal(1, len(configs), "should be one registered")

	s.Equal(s.stream.Id, configs[0].Id, "should be the same s.stream id")
	s.Equal(26, len(configs[0].EventsDelivered), "Should be 26 events configured for delivery")
	events, _ := s.provider.GetEventService().GetEventIds(context.Background(), s.stream.Id, model.PollParameters{
		MaxEvents: 5, ReturnImmediately: true,
	})
	s.Equal(0, len(events), "should be no events")

	id := s.stream.Id
	theConfig, err := s.provider.GetStreamService().GetStream(context.Background(), id)
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
	eventIds, _ := s.provider.GetEventService().GetEventIds(context.Background(), s.stream.Id, model.PollParameters{MaxEvents: 5, ReturnImmediately: true})
	s.Equal(1, len(eventIds), "should be 1 event")

	if len(eventIds) == 0 {
		return
	}
	// Check event collection (all s.streams)
	events := s.provider.GetEventService().GetEvents(context.Background(), eventIds)
	s.Equal(1, len(events), "Should be 1 event")

	// Acknowledge should transfer pending event to acked event leaving no pending events
	_ = s.provider.GetEventService().AckEvent(context.Background(), eventIds[0], s.stream.Id, 0)

	nextIds, _ := s.provider.GetEventService().GetEventIds(context.Background(), s.stream.Id, model.PollParameters{MaxEvents: 5, ReturnImmediately: true})
	s.Equal(0, len(nextIds), "Should be no pending events")

	s.generateEvent()
	s.generateEvent()
	s.generateEvent()
	s.generateEvent()
	s.generateEvent()
	s.generateEvent()

	nextIds, _ = s.provider.GetEventService().GetEventIds(context.Background(), s.stream.Id, model.PollParameters{MaxEvents: 5, ReturnImmediately: true})
	s.Equal(5, len(nextIds), "Should be 5 max events")
	s.ackEvents(nextIds)

	finalIds, _ := s.provider.GetEventService().GetEventIds(context.Background(), s.stream.Id, model.PollParameters{MaxEvents: 5, ReturnImmediately: true})
	s.Equal(1, len(finalIds), "should be 1 event")
	_ = s.provider.GetEventService().AckEvent(context.Background(), finalIds[0], s.stream.Id, 0)
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
		eventIds, _ = s.provider.GetEventService().GetEventIds(context.Background(), s.stream.Id, model.PollParameters{MaxEvents: 2, ReturnImmediately: true})
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
		nextIds, _ := s.provider.GetEventService().GetEventIds(context.Background(), s.stream.Id, model.PollParameters{MaxEvents: 100, ReturnImmediately: true})
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

	sets := s.provider.GetEventService().GetEvents(context.Background(), events)

	s.Equal(len(events), len(sets), "Sets return matches GetEvents")
	tokenRef := sets[0]
	set := *tokenRef
	s.Equal(s.stream.Iss, set.Issuer, "Issuer is matched")
}

func (s *MongoProviderSuite) ackEvents(ids []string) {
	for _, id := range ids {
		if id != "" {
			_ = s.provider.GetEventService().AckEvent(context.Background(), id, s.stream.Id, 0)
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

	_, _ = s.provider.GetEventService().AddEvent(context.Background(), &test1, "", "")

	state, _ := s.provider.GetStreamService().GetStreamState(context.Background(), s.stream.Id)

	_ = s.provider.GetEventService().AddEventToStream(context.Background(), test1.ID, state.Id.Hex())
}

func (s *MongoProviderSuite) TestF1_IssuerKeys() {
	issuer := "i2test.example.org"
	key, err := s.provider.GetKeyService().CreateKeyPair(context.Background(), issuer, "sig", "")
	s.NoError(err)
	s.NotNil(key, "Should be a key returned")

	keyRetrieved, err := s.provider.GetKeyService().GetPrivateKey(context.Background(), issuer)
	s.NoError(err, "Should be no error")
	s.NotNil(keyRetrieved)
	s.True(key.Equal(keyRetrieved), "Should be same key")

	keyFail, err := s.provider.GetKeyService().GetPrivateKey(context.Background(), "should.fail")
	s.Error(err, "No key found for: should.fail")
	s.Nil(keyFail, "Should be no key returned")

	issPubJson := s.provider.GetKeyService().GetPublicJWKS(context.Background(), issuer)
	s.NotNil(issPubJson, "Check public key returned")
	jwtBytes, err := issPubJson.MarshalJSON()

	log.Printf("\nIusser JWKS JSON:\n%v\n", string(jwtBytes))

	s.NotNil(issPubJson, "Check public key returned")
	if issPubJson != nil {
		issPub, err := keyfunc.NewJSON(*issPubJson)
		s.NoError(err, "No error parsing json into JWKS")
		s.Contains(issPub.KIDs(), issuer, "Confirm issuer present")
	}

	keys, _ := s.provider.GetKeyService().ListKeyNames(context.Background())
	s.Len(keys, 2, "Should be 2 keys")
	s.Contains(keys, issuer, "Confirm issuer i2test.example.org present")
	s.Contains(keys, "DEFAULT", "Confirm issuer DEFAULT present")

}

func (s *MongoProviderSuite) TestF2_AddIssuerKey() {
	issuer := "addkey-test.example.org"
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Test adding private key
	err := s.provider.GetKeyService().AddKey(context.Background(), issuer, "sig", "key-1", privateKey, nil, "")
	s.NoError(err)

	keyRetrieved, err := s.provider.GetKeyService().GetPrivateKey(context.Background(), issuer)
	s.NoError(err)
	s.NotNil(keyRetrieved)
	s.True(privateKey.Equal(keyRetrieved))

	// Test adding only public key
	issuerPub := "addkey-pub.example.org"
	err = s.provider.GetKeyService().AddKey(context.Background(), issuerPub, "sig", "key-pub", nil, &privateKey.PublicKey, "")
	s.NoError(err)

	issPubJson := s.provider.GetKeyService().GetPublicJWKS(context.Background(), issuerPub)
	s.NotNil(issPubJson)
	if issPubJson != nil {
		issPub, err := keyfunc.NewJSON(*issPubJson)
		s.NoError(err)
		s.Contains(issPub.KIDs(), "key-pub")
	}

	// Verify private key is NOT there
	keyFail, err := s.provider.GetKeyService().GetPrivateKey(context.Background(), issuerPub)
	s.Error(err)
	s.Nil(keyFail)
}

func (s *MongoProviderSuite) TestG_ReceiverKeys() {
	err := s.provider.GetKeyService().StoreExternalKey(context.Background(), "example.org", nil, s.stream.Id, "sig", "https://example.org/jwksKey")
	s.NoError(err)

	jwkRecord, _ := s.provider.GetKeyService().GetKeyByStreamID(context.Background(), s.stream.Id)

	s.NotNil(jwkRecord)

	s.Equal("example.org", jwkRecord.KeyName)

	res, _ := s.provider.GetKeyService().GetKeyByStreamID(context.Background(), "dummy")
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

	_, err := s.provider.GetStreamService().UpdateStream(context.Background(), "1234", s.project, model.StreamStateRecord{StreamConfiguration: config})
	s.Error(err, "not found")

	res, err := s.provider.GetStreamService().UpdateStream(context.Background(), sid, s.project, model.StreamStateRecord{StreamConfiguration: config})
	s.NoError(err, "Update should have no error")
	s.Equal(orig.Aud, res.Aud, "Audience should not change")
	s.Equal(orig.Iss, res.Iss, "Issuer should not change")
	s.Equal([]string{"abc"}, res.EventsRequested, "Event should be abc")
	s.Equal(0, len(res.EventsDelivered), "Should be no delivered events")

	res.EventsRequested = res.EventsSupported // request all events
	res2, err := s.provider.GetStreamService().UpdateStream(context.Background(), sid, s.project, model.StreamStateRecord{StreamConfiguration: *res})
	s.NoError(err, "2nd Update should have no error")
	s.Equal(res.EventsSupported, res2.EventsDelivered, "All events enabled")

	err = s.provider.GetStreamService().DeleteStream(context.Background(), s.stream.Id)
	s.NoError(err, "Delete should be successful")

	supportedEvents := model.GetSupportedEvents()
	s.InitStream(supportedEvents)
	s.Equal(len(supportedEvents), len(s.stream.EventsDelivered), "All events enabled")
}

func (s *MongoProviderSuite) TestI_UpdateRemoteAddress() {
	addr := &model.RemoteIP{
		Protocol:  "https",
		IP:        "10.0.1.5:443",
		Forwarded: "203.0.113.42",
	}

	s.provider.GetStreamService().UpdateRemoteAddress(context.Background(), s.stream.Id, addr)

	state, err := s.provider.GetStreamService().GetStreamState(context.Background(), s.stream.Id)
	s.NoError(err, "GetStreamState should succeed")
	s.Require().NotNil(state.RemoteAddress, "RemoteAddress should be populated")
	s.Equal("https", state.RemoteAddress.Protocol)
	s.Equal("10.0.1.5:443", state.RemoteAddress.IP)
	s.Equal("203.0.113.42", state.RemoteAddress.Forwarded)
}

// TestZ_SubjectFilterFieldsRoundTrip verifies that the SSF subject-filtering
// configuration fields (defaultSubjects, subjectFilterMode, and the event-source
// descriptor) persist and read back intact through the MongoDB adapter on both
// create and update. It mirrors the memory-adapter coverage in
// internal/services/stream_service_subject_filter_test.go so #90 acceptance
// criterion 4 ("on both the memory and mongo adapters") is exercised on Mongo.
func (s *MongoProviderSuite) TestZ_SubjectFilterFieldsRoundTrip() {
	s.T().Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")

	authCtx := authSupport.ConvertProject(s.project)
	ctx := context.WithValue(context.Background(), authSupport.AuthContextKey, authCtx)

	req := model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Aud:      []string{"test.example.com"},
			Iss:      "test.com",
			Delivery: &model.OneOfStreamConfigurationDelivery{PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll}},
		},
		DefaultSubjects: model.DefaultSubjectsNone,
		EventSource: &model.EventSource{
			Type:            model.EventSourceExplicit,
			SourceStreamIds: []string{"src-1"},
		},
	}

	created, err := s.provider.GetStreamService().CreateStream(ctx, req, authCtx.ProjectId, nil)
	s.Require().NoError(err, "CreateStream should succeed")

	state, err := s.provider.GetStreamService().GetStreamState(ctx, created.Id)
	s.Require().NoError(err, "GetStreamState after create should succeed")
	s.Equal(model.DefaultSubjectsNone, state.DefaultSubjects, "defaultSubjects must round-trip through Mongo create")
	s.Require().NotNil(state.EventSource, "event source must round-trip through Mongo create")
	s.Equal(model.EventSourceExplicit, state.EventSource.Type)
	s.Equal([]string{"src-1"}, state.EventSource.SourceStreamIds)

	// Patch the subject-filtering fields and confirm they survive an update.
	// LOCAL mode does no upstream relay, so it round-trips without requiring a
	// resolvable relay target.
	update := model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{Id: created.Id},
		DefaultSubjects:     model.DefaultSubjectsNone,
		SubjectFilterMode:   model.SubjectFilterModeLocal,
		EventSource:         &model.EventSource{Type: model.EventSourceAudience},
	}
	_, err = s.provider.GetStreamService().UpdateStream(ctx, created.Id, authCtx.ProjectId, update)
	s.Require().NoError(err, "UpdateStream should succeed")

	state, err = s.provider.GetStreamService().GetStreamState(ctx, created.Id)
	s.Require().NoError(err, "GetStreamState after update should succeed")
	s.Equal(model.DefaultSubjectsNone, state.DefaultSubjects, "defaultSubjects must round-trip through Mongo update")
	s.Equal(model.SubjectFilterModeLocal, state.SubjectFilterMode, "subjectFilterMode must round-trip through Mongo update")
	s.Require().NotNil(state.EventSource, "event source must round-trip through Mongo update")
	s.Equal(model.EventSourceAudience, state.EventSource.Type)
}

// TestZ_SubjectRemovalGraceRoundTrip verifies that the SSF §9.3 per-stream
// removal-grace override (PRD #97 issue #98) is persisted on the
// StreamStateRecord and round-trips through the MongoDB adapter on both
// create and update. Mirrors the memory-adapter coverage in
// internal/services/stream_service_subject_filter_test.go.
func (s *MongoProviderSuite) TestZ_SubjectRemovalGraceRoundTrip() {
	authCtx := authSupport.ConvertProject(s.project)
	ctx := context.WithValue(context.Background(), authSupport.AuthContextKey, authCtx)

	req := model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Aud:      []string{"grace.example.com"},
			Iss:      "grace.com",
			Delivery: &model.OneOfStreamConfigurationDelivery{PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll}},
		},
		SubjectRemovalGraceSeconds: 45,
	}

	created, err := s.provider.GetStreamService().CreateStream(ctx, req, authCtx.ProjectId, nil)
	s.Require().NoError(err, "CreateStream should succeed")

	state, err := s.provider.GetStreamService().GetStreamState(ctx, created.Id)
	s.Require().NoError(err, "GetStreamState after create should succeed")
	s.Equal(45, state.SubjectRemovalGraceSeconds,
		"subject_removal_grace_seconds must round-trip through Mongo create")

	update := model.StreamStateRecord{
		StreamConfiguration:        model.StreamConfiguration{Id: created.Id},
		SubjectRemovalGraceSeconds: 90,
	}
	_, err = s.provider.GetStreamService().UpdateStream(ctx, created.Id, authCtx.ProjectId, update)
	s.Require().NoError(err, "UpdateStream should succeed")

	state, err = s.provider.GetStreamService().GetStreamState(ctx, created.Id)
	s.Require().NoError(err, "GetStreamState after update should succeed")
	s.Equal(90, state.SubjectRemovalGraceSeconds,
		"subject_removal_grace_seconds must round-trip through Mongo update")
}
