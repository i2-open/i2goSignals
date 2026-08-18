package mongo

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/suite"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// EventDAOMongoSuite exercises the persistence-layer JTI dedup contract.
// The Mongo unique index is the authoritative race breaker; we install the
// sparse-unique index here under the same fixed name (eventJtiUnique) that
// mongo_provider.createIndexes will install in production, so tests verify
// the same wire as the runtime path.
type EventDAOMongoSuite struct {
	suite.Suite
	client       *mongo.Client
	eventCol     *mongo.Collection
	pendingCol   *mongo.Collection
	deliveredCol *mongo.Collection
	dao          interfaces.EventDAO
}

func (s *EventDAOMongoSuite) SetupSuite() {
	opts := options.Client().ApplyURI(TestDbUrl)
	client, err := mongo.Connect(opts)
	if err != nil {
		s.T().Skip("Mongo connection error: " + err.Error())
		return
	}
	if err := client.Ping(context.Background(), nil); err != nil {
		s.T().Skip("Mongo ping error: " + err.Error())
		return
	}
	s.client = client
	db := client.Database("test_event_dao_dedup")
	s.eventCol = db.Collection("events")
	s.pendingCol = db.Collection("pending")
	s.deliveredCol = db.Collection("delivered")
	s.dao = NewEventDAO(s.eventCol, s.pendingCol, s.deliveredCol)
}

func (s *EventDAOMongoSuite) TearDownSuite() {
	if s.client != nil {
		_ = s.client.Disconnect(context.Background())
	}
}

func (s *EventDAOMongoSuite) SetupTest() {
	ctx := context.Background()
	_ = s.eventCol.Drop(ctx)
	_ = s.pendingCol.Drop(ctx)
	_ = s.deliveredCol.Drop(ctx)
	// Install the sparse-unique JTI index that mongo_provider.createIndexes
	// installs in production. This is what enforces the dedup contract at
	// the storage layer.
	_, err := s.eventCol.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "jti", Value: 1}},
		Options: options.Index().
			SetName("eventJtiUnique").
			SetUnique(true).
			SetSparse(true),
	})
	s.Require().NoError(err)
}

func TestEventDAOMongoSuite(t *testing.T) {
	suite.Run(t, new(EventDAOMongoSuite))
}

// TestInsert_DuplicateJTI: second Insert with same JTI returns
// interfaces.ErrDuplicateJTI; FindByJTI continues to return the FIRST record.
func (s *EventDAOMongoSuite) TestInsert_DuplicateJTI() {
	ctx := context.Background()
	first := &model.EventRecord{
		Jti:      "dup-jti",
		Original: `{"jti":"dup-jti","first":true}`,
		SortTime: time.Now(),
	}
	s.Require().NoError(s.dao.Insert(ctx, first))

	second := &model.EventRecord{
		Jti:      "dup-jti",
		Original: `{"jti":"dup-jti","second":true}`,
		SortTime: time.Now(),
	}
	err := s.dao.Insert(ctx, second)
	s.Require().Error(err)
	s.Require().True(errors.Is(err, interfaces.ErrDuplicateJTI), "expected ErrDuplicateJTI, got %v", err)

	got, err := s.dao.FindByJTI(ctx, "dup-jti")
	s.Require().NoError(err)
	s.Require().NotNil(got)
	s.Equal(first.Original, got.Original, "duplicate must not overwrite first record")
}

// TestInsert_DistinctJTIs: two distinct JTIs both succeed.
func (s *EventDAOMongoSuite) TestInsert_DistinctJTIs() {
	ctx := context.Background()
	a := &model.EventRecord{Jti: "jti-a", SortTime: time.Now()}
	b := &model.EventRecord{Jti: "jti-b", SortTime: time.Now()}
	s.Require().NoError(s.dao.Insert(ctx, a))
	s.Require().NoError(s.dao.Insert(ctx, b))
}

// TestInsert_ConcurrentDuplicates: 50 goroutines insert the same JTI; the
// Mongo unique index serializes them so exactly one succeeds and 49 return
// ErrDuplicateJTI.
func (s *EventDAOMongoSuite) TestInsert_ConcurrentDuplicates() {
	ctx := context.Background()
	const goroutines = 50
	var (
		wg    sync.WaitGroup
		ok    atomic.Int32
		dup   atomic.Int32
		other atomic.Int32
		start = make(chan struct{})
	)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			rec := &model.EventRecord{Jti: "race-jti", SortTime: time.Now()}
			err := s.dao.Insert(ctx, rec)
			switch {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, interfaces.ErrDuplicateJTI):
				dup.Add(1)
			default:
				other.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	s.Equal(int32(1), ok.Load(), "exactly one Insert should succeed")
	s.Equal(int32(goroutines-1), dup.Load(), "remainder must be ErrDuplicateJTI")
	s.Equal(int32(0), other.Load(), "no other errors")
}

// TestInsert_StoresCompactSET is the on-disk assertion for issue #259: after
// an Insert through the DAO, the `event` subdocument in Mongo holds the SET's
// wire shape — RFC 8417 claims at the top level under their wire names, a
// compact sub_id, and nothing the token did not carry.
func (s *EventDAOMongoSuite) TestInsert_StoresCompactSET() {
	ctx := context.Background()
	rec := &model.EventRecord{
		Jti: "compact-jti",
		Event: goSet.SecurityEventToken{
			RegisteredClaims: jwt.RegisteredClaims{
				ID:       "compact-jti",
				Issuer:   "https://issuer.example",
				Audience: jwt.ClaimStrings{"https://receiver.example"},
				IssuedAt: jwt.NewNumericDate(time.Unix(1700000000, 0)),
			},
			SubjectId: &goSet.SubjectIdentifier{
				Format:           "opaque",
				OpaqueIdentifier: goSet.OpaqueIdentifier{Id: "codex:exec-b3bfa4ad-2981-44d3-a794-6054ad4b20dd"},
			},
			Events: map[string]interface{}{"urn:example:event": map[string]any{}},
		},
		SortTime: time.Now(),
	}
	s.Require().NoError(s.dao.Insert(ctx, rec))

	// Read the stored document as raw BSON — not through EventRecord — so the
	// assertion is about what is actually on disk.
	var stored bson.Raw
	s.Require().NoError(s.eventCol.FindOne(ctx, bson.M{"jti": "compact-jti"}).Decode(&stored))

	eventDoc, ok := stored.Lookup("event").DocumentOK()
	s.Require().True(ok, "event subdocument must be present")

	s.ElementsMatch(
		[]string{"jti", "iss", "aud", "iat", "sub_id", "events"},
		rawKeys(s.T(), eventDoc),
		"stored SET must carry only its wire members")

	subDoc, ok := eventDoc.Lookup("sub_id").DocumentOK()
	s.Require().True(ok)
	s.ElementsMatch([]string{"format", "id"}, rawKeys(s.T(), subDoc),
		"sub_id must not be expanded into every identifier variant")

	// And it must read back intact through the DAO.
	got, err := s.dao.FindByJTI(ctx, "compact-jti")
	s.Require().NoError(err)
	s.Require().NotNil(got)
	s.Require().NotNil(got.Event.SubjectId)
	s.Equal("codex:exec-b3bfa4ad-2981-44d3-a794-6054ad4b20dd", got.Event.SubjectId.Id)
	s.Equal("https://issuer.example", got.Event.Issuer)
	s.Equal("compact-jti", got.Event.ID)
}

// TestFindByJTI_ReadsLegacyEventDocument: rows written before the fix still
// decode. ResetDate/ResetJti replay can reach them, and the parsed SubjectId is
// used for delivery-time subject filtering, so a silent empty decode would
// mis-match rather than fail.
func (s *EventDAOMongoSuite) TestFindByJTI_ReadsLegacyEventDocument() {
	ctx := context.Background()
	legacyDoc := bson.D{
		{Key: "jti", Value: "legacy-jti"},
		{Key: "event", Value: bson.D{
			{Key: "registeredclaims", Value: bson.D{
				{Key: "issuer", Value: "https://issuer.example"},
				{Key: "subject", Value: ""},
				{Key: "audience", Value: bson.A{"https://receiver.example"}},
				{Key: "expiresat", Value: nil},
				{Key: "notbefore", Value: nil},
				{Key: "issuedat", Value: bson.D{{Key: "time", Value: time.Unix(1700000000, 0)}}},
				{Key: "id", Value: "legacy-jti"},
			}},
			{Key: "timeofevent", Value: nil},
			{Key: "transactionid", Value: ""},
			{Key: "subjectid", Value: legacySubjectDoc("opaque", "", "codex:exec-legacy")},
			{Key: "events", Value: bson.D{{Key: "urn:example:event", Value: bson.D{}}}},
			{Key: "kid", Value: ""},
		}},
		{Key: "original", Value: "eyJ0eXAiOiJzZWNldmVudCtqd3QifQ.legacy.sig"},
		{Key: "sortTime", Value: time.Now()},
	}
	_, err := s.eventCol.InsertOne(ctx, legacyDoc)
	s.Require().NoError(err)

	got, err := s.dao.FindByJTI(ctx, "legacy-jti")
	s.Require().NoError(err)
	s.Require().NotNil(got)
	s.Equal("legacy-jti", got.Event.ID)
	s.Equal("https://issuer.example", got.Event.Issuer)
	s.Require().NotNil(got.Event.SubjectId)
	s.Equal("codex:exec-legacy", got.Event.SubjectId.Id,
		"pre-fix row must not decode to an empty subject")
}

// rawKeys returns the top-level field names of a BSON document.
func rawKeys(t *testing.T, doc bson.Raw) []string {
	t.Helper()
	elems, err := doc.Elements()
	if err != nil {
		t.Fatalf("reading BSON elements: %v", err)
	}
	keys := make([]string, 0, len(elems))
	for _, e := range elems {
		keys = append(keys, e.Key())
	}
	return keys
}
