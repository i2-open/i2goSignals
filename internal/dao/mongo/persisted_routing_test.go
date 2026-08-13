package mongo

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/suite"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// PersistedRoutingSuite closes the loop on issue #259 at the routing seam: the
// stored shape of a SET only matters because routing and subject filtering read
// it back. EventService.MatchesStream keys off the SET's registered claims
// (iss/aud) — the very members the fix relocates out of the `registeredclaims`
// subdocument — and SubjectFilterService reads SubjectId, which the fix
// un-expands.
//
// The dangerous case is a document written before the fix. BSON decoding
// ignores unknown fields, so without the legacy fallback an old row decodes to
// an empty issuer and an empty subject: the event is routed and filtered on
// nothing rather than failing loudly. These tests assert the resulting
// delivery decision, not the decoded struct.
type PersistedRoutingSuite struct {
	suite.Suite
	client    *mongo.Client
	eventCol  *mongo.Collection
	filterCol *mongo.Collection
	eventDAO  interfaces.EventDAO
	filterDAO interfaces.SubjectFilterDAO
}

func (s *PersistedRoutingSuite) SetupSuite() {
	opts := options.Client().ApplyURI(TestDbUrl)
	client, err := mongo.Connect(opts)
	if err != nil {
		s.T().Skip("Mongo connection error: " + err.Error())
		return
	}
	if err = client.Ping(context.Background(), nil); err != nil {
		s.T().Skip("Mongo ping error: " + err.Error())
		return
	}
	s.client = client
	db := client.Database("test_persisted_routing")
	s.eventCol = db.Collection("events")
	s.filterCol = db.Collection("subject_filters")
	s.eventDAO = NewEventDAO(s.eventCol, db.Collection("pending"), db.Collection("delivered"))
	s.filterDAO = NewSubjectFilterDAO(s.filterCol)
}

func (s *PersistedRoutingSuite) TearDownSuite() {
	if s.client != nil {
		_ = s.client.Disconnect(context.Background())
	}
}

func (s *PersistedRoutingSuite) SetupTest() {
	ctx := context.Background()
	_ = s.eventCol.Drop(ctx)
	_ = s.filterCol.Drop(ctx)
	s.filterDAO.(*SubjectFilterDAOMongo).ensureIndex(s.filterCol)
}

func TestPersistedRoutingSuite(t *testing.T) {
	suite.Run(t, new(PersistedRoutingSuite))
}

const (
	routeTypeAcctDisabled = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
)

// routeStream builds a transmitter stream constrained to one issuer, one
// audience and one event type.
func routeStream(iss string, aud []string, delivered ...string) *model.StreamStateRecord {
	return &model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Iss:             iss,
			Aud:             aud,
			EventsDelivered: delivered,
		},
	}
}

// legacyEventDoc is a hand-transcribed pre-#259 events row: the registered
// claims buried under Go field names in a `registeredclaims` subdocument, and
// the subject expanded into every identifier variant.
func legacyEventDoc(jti, iss string, aud []string, opaqueId string, types []string) bson.D {
	audA := bson.A{}
	for _, a := range aud {
		audA = append(audA, a)
	}
	return bson.D{
		{Key: "jti", Value: jti},
		{Key: "types", Value: types},
		{Key: "event", Value: bson.D{
			{Key: "registeredclaims", Value: bson.D{
				{Key: "issuer", Value: iss},
				{Key: "subject", Value: ""},
				{Key: "audience", Value: audA},
				{Key: "expiresat", Value: nil},
				{Key: "notbefore", Value: nil},
				{Key: "issuedat", Value: bson.D{{Key: "time", Value: time.Unix(1700000000, 0)}}},
				{Key: "id", Value: jti},
			}},
			{Key: "timeofevent", Value: nil},
			{Key: "transactionid", Value: ""},
			{Key: "subjectid", Value: bson.D{
				{Key: "format", Value: "email"},
				{Key: "usernameidentifier", Value: bson.D{{Key: "username", Value: ""}}},
				{Key: "emailidentifier", Value: bson.D{{Key: "email", Value: opaqueId}}},
				{Key: "opaqueidentifier", Value: bson.D{{Key: "id", Value: ""}}},
				{Key: "complexidentifier", Value: bson.D{{Key: "user", Value: nil}}},
			}},
			{Key: "events", Value: bson.D{{Key: routeTypeAcctDisabled, Value: bson.D{}}}},
			{Key: "kid", Value: ""},
		}},
		{Key: "sortTime", Value: time.Now()},
	}
}

// TestMatchesStream_LegacyEventKeepsItsIssuer: a stream constrained to issuer A
// must NOT deliver a pre-fix event issued by B. If the stored registered claims
// fail to decode, the issuer reads as empty — which the historical filter treats
// as a wildcard — and the event leaks to a stream that never asked for it.
func (s *PersistedRoutingSuite) TestMatchesStream_LegacyEventKeepsItsIssuer() {
	ctx := context.Background()
	_, err := s.eventCol.InsertOne(ctx, legacyEventDoc(
		"legacy-wrong-iss", "https://other.example", []string{"https://receiver.example"},
		"alice@example.com", []string{routeTypeAcctDisabled}))
	s.Require().NoError(err)

	got, err := s.eventDAO.FindByJTI(ctx, "legacy-wrong-iss")
	s.Require().NoError(err)
	s.Require().NotNil(got)

	stream := routeStream("https://issuer.example", []string{"https://receiver.example"}, routeTypeAcctDisabled)
	s.False(services.NewEventService(nil).MatchesStream(stream, got),
		"a pre-fix event from a different issuer must not be routed as an empty-issuer wildcard")
}

// TestMatchesStream_LegacyEventStillMatchesItsStream is the other half: the
// pre-fix event that SHOULD be delivered still is, so the legacy fallback is
// not simply failing everything closed. The stream is in RouteModeForward,
// where iss matching is mandatory and a missing issuer cannot satisfy it — so
// an event whose claims failed to decode is dropped rather than wildcarded.
func (s *PersistedRoutingSuite) TestMatchesStream_LegacyEventStillMatchesItsStream() {
	ctx := context.Background()
	_, err := s.eventCol.InsertOne(ctx, legacyEventDoc(
		"legacy-right-iss", "https://issuer.example", []string{"https://receiver.example"},
		"alice@example.com", []string{routeTypeAcctDisabled}))
	s.Require().NoError(err)

	got, err := s.eventDAO.FindByJTI(ctx, "legacy-right-iss")
	s.Require().NoError(err)

	stream := routeStream("https://issuer.example", []string{"https://receiver.example"}, routeTypeAcctDisabled)
	stream.StreamConfiguration.RouteMode = model.RouteModeForward
	s.True(services.NewEventService(nil).MatchesStream(stream, got),
		"a pre-fix event from the stream's issuer must still be forwarded")
}

// TestMatchesStream_CompactEventRoundTripsThroughMongo: the new wire shape must
// carry iss/aud through an Insert/FindByJTI round-trip well enough for routing
// to reach the same decision it would on the in-memory record.
func (s *PersistedRoutingSuite) TestMatchesStream_CompactEventRoundTripsThroughMongo() {
	ctx := context.Background()
	rec := &model.EventRecord{
		Jti:   "compact-routed",
		Types: []string{routeTypeAcctDisabled},
		Event: goSet.SecurityEventToken{
			RegisteredClaims: jwt.RegisteredClaims{
				ID:       "compact-routed",
				Issuer:   "https://issuer.example",
				Audience: jwt.ClaimStrings{"https://receiver.example"},
				IssuedAt: jwt.NewNumericDate(time.Unix(1700000000, 0)),
			},
			Events: map[string]interface{}{routeTypeAcctDisabled: map[string]any{}},
		},
		SortTime: time.Now(),
	}
	s.Require().NoError(s.eventDAO.Insert(ctx, rec))

	got, err := s.eventDAO.FindByJTI(ctx, "compact-routed")
	s.Require().NoError(err)

	svc := services.NewEventService(nil)
	s.True(svc.MatchesStream(routeStream("https://issuer.example", []string{"https://receiver.example"}, routeTypeAcctDisabled), got),
		"the persisted event must route to its own stream")
	s.False(svc.MatchesStream(routeStream("https://other.example", []string{"https://receiver.example"}, routeTypeAcctDisabled), got),
		"the persisted event must not route to a different issuer's stream")
}

// TestAllows_LegacyEventStillSubjectFilters is the subject half of the same
// risk, and the one the issue calls out by name: under DefaultSubjects=NONE an
// event is delivered only when its subject was explicitly added. A pre-fix row
// whose subject decoded to empty would silently stop matching its own filter
// entry and the receiver would go quiet.
func (s *PersistedRoutingSuite) TestAllows_LegacyEventStillSubjectFilters() {
	s.T().Setenv("I2SIG_SUBJECT_FILTERING", services.SubjectFilteringEnabledValue)
	ctx := context.Background()

	s.Require().NoError(s.filterDAO.Add(ctx, &model.SubjectFilterEntry{
		StreamId:     "stream-legacy-subj",
		CanonicalKey: "email:alice@example.com",
		Kind:         model.SubjectKindSimple,
		Subject: &goSet.SubjectIdentifier{
			Format:          "email",
			EmailIdentifier: goSet.EmailIdentifier{Email: "alice@example.com"},
		},
	}))

	_, err := s.eventCol.InsertOne(ctx, legacyEventDoc(
		"legacy-subject", "https://issuer.example", []string{"https://receiver.example"},
		"alice@example.com", []string{routeTypeAcctDisabled}))
	s.Require().NoError(err)

	got, err := s.eventDAO.FindByJTI(ctx, "legacy-subject")
	s.Require().NoError(err)

	stream := routeStream("https://issuer.example", []string{"https://receiver.example"}, routeTypeAcctDisabled)
	stream.StreamConfiguration.Id = "stream-legacy-subj"
	stream.DefaultSubjects = model.DefaultSubjectsNone

	svc := services.NewSubjectFilterService(s.filterDAO)
	s.True(svc.Allows(ctx, stream, got),
		"a pre-fix event must still match the filter entry that was added for its subject")

	// And a subject nobody added is still withheld, so the fallback has not
	// simply opened the gate.
	other, err := s.eventDAO.FindByJTI(ctx, "legacy-subject")
	s.Require().NoError(err)
	other.Event.SubjectId = &goSet.SubjectIdentifier{
		Format:          "email",
		EmailIdentifier: goSet.EmailIdentifier{Email: "mallory@example.com"},
	}
	s.False(svc.Allows(ctx, stream, other),
		"an unadded subject must remain undelivered under DefaultSubjects=NONE")
}

// TestAllows_CompactEventRoundTripsThroughMongo: the same delivery decision for
// the new wire shape, persisted and re-read through both collections — the
// filter entry's stored subject and the event's stored subject must still meet.
func (s *PersistedRoutingSuite) TestAllows_CompactEventRoundTripsThroughMongo() {
	s.T().Setenv("I2SIG_SUBJECT_FILTERING", services.SubjectFilteringEnabledValue)
	ctx := context.Background()

	subject := &goSet.SubjectIdentifier{
		Format:          "email",
		EmailIdentifier: goSet.EmailIdentifier{Email: "alice@example.com"},
	}
	s.Require().NoError(s.filterDAO.Add(ctx, &model.SubjectFilterEntry{
		StreamId:     "stream-compact-subj",
		CanonicalKey: "email:alice@example.com",
		Kind:         model.SubjectKindSimple,
		Subject:      subject,
	}))

	rec := &model.EventRecord{
		Jti:   "compact-subject",
		Types: []string{routeTypeAcctDisabled},
		Event: goSet.SecurityEventToken{
			RegisteredClaims: jwt.RegisteredClaims{
				ID:       "compact-subject",
				Issuer:   "https://issuer.example",
				Audience: jwt.ClaimStrings{"https://receiver.example"},
			},
			SubjectId: subject,
			Events:    map[string]interface{}{routeTypeAcctDisabled: map[string]any{}},
		},
		SortTime: time.Now(),
	}
	s.Require().NoError(s.eventDAO.Insert(ctx, rec))

	got, err := s.eventDAO.FindByJTI(ctx, "compact-subject")
	s.Require().NoError(err)

	stream := routeStream("https://issuer.example", []string{"https://receiver.example"}, routeTypeAcctDisabled)
	stream.StreamConfiguration.Id = "stream-compact-subj"
	stream.DefaultSubjects = model.DefaultSubjectsNone

	s.True(services.NewSubjectFilterService(s.filterDAO).Allows(ctx, stream, got),
		"the persisted event's subject must still match its persisted filter entry")
}
