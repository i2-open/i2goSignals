package mongo

import (
    "context"
    "errors"
    "sync"
    "sync/atomic"
    "testing"
    "time"

    interfaces "github.com/i2-open/i2goSignals/pkg/dao"
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
    first := &model.AgEventRecord{
        Jti:      "dup-jti",
        Original: `{"jti":"dup-jti","first":true}`,
        SortTime: time.Now(),
    }
    s.Require().NoError(s.dao.Insert(ctx, first))

    second := &model.AgEventRecord{
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
    a := &model.AgEventRecord{Jti: "jti-a", SortTime: time.Now()}
    b := &model.AgEventRecord{Jti: "jti-b", SortTime: time.Now()}
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
            rec := &model.AgEventRecord{Jti: "race-jti", SortTime: time.Now()}
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
