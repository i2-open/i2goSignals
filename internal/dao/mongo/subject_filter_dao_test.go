package mongo

import (
    "context"
    "errors"
    "testing"

    "github.com/i2-open/i2goSignals/internal/dao/interfaces"
    model "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/suite"
    "go.mongodb.org/mongo-driver/v2/mongo"
    "go.mongodb.org/mongo-driver/v2/mongo/options"
)

// SubjectFilterDAOMongoSuite exercises the MongoDB SubjectFilterDAO adapter and
// confirms it behaves identically to the memory adapter (PRD #89, #92 AC 9).
type SubjectFilterDAOMongoSuite struct {
    suite.Suite
    client     *mongo.Client
    collection *mongo.Collection
    dao        interfaces.SubjectFilterDAO
}

func (suite *SubjectFilterDAOMongoSuite) SetupSuite() {
    opts := options.Client().ApplyURI(TestDbUrl)
    client, err := mongo.Connect(opts)
    if err != nil {
        suite.T().Skip("Mongo connection error: " + err.Error())
        return
    }
    if err = client.Ping(context.Background(), nil); err != nil {
        suite.T().Skip("Mongo ping error: " + err.Error())
        return
    }
    suite.client = client
    suite.collection = client.Database("test_db").Collection("subject_filters")
    suite.dao = NewSubjectFilterDAO(suite.collection)
}

func (suite *SubjectFilterDAOMongoSuite) TearDownSuite() {
    if suite.client != nil {
        _ = suite.client.Disconnect(context.Background())
    }
}

func (suite *SubjectFilterDAOMongoSuite) SetupTest() {
    _ = suite.collection.Drop(context.Background())
    suite.dao.(*SubjectFilterDAOMongo).ensureIndex(suite.collection)
}

func TestSubjectFilterDAOMongoSuite(t *testing.T) {
    suite.Run(t, new(SubjectFilterDAOMongoSuite))
}

func mSimpleEntry(streamID, key string) *model.SubjectFilterEntry {
    return &model.SubjectFilterEntry{StreamId: streamID, CanonicalKey: key, Kind: model.SubjectKindSimple}
}

// TestAddGet verifies an added entry is read back by its (stream, canonical key).
func (suite *SubjectFilterDAOMongoSuite) TestAddGet() {
    ctx := context.Background()
    suite.NoError(suite.dao.Add(ctx, mSimpleEntry("stream-1", "email:alice@example.com")))

    got, err := suite.dao.Get(ctx, "stream-1", "email:alice@example.com")
    suite.NoError(err)
    suite.Equal("stream-1", got.StreamId)
    suite.Equal("email:alice@example.com", got.CanonicalKey)
}

// TestAddIsUpsert verifies Add on an existing (stream, key) replaces rather
// than duplicating — the same insert-or-replace contract as the memory adapter.
func (suite *SubjectFilterDAOMongoSuite) TestAddIsUpsert() {
    ctx := context.Background()
    suite.NoError(suite.dao.Add(ctx, &model.SubjectFilterEntry{StreamId: "stream-1", CanonicalKey: "email:a@example.com", Kind: model.SubjectKindSimple, Verified: false}))
    suite.NoError(suite.dao.Add(ctx, &model.SubjectFilterEntry{StreamId: "stream-1", CanonicalKey: "email:a@example.com", Kind: model.SubjectKindSimple, Verified: true}))

    got, err := suite.dao.Get(ctx, "stream-1", "email:a@example.com")
    suite.NoError(err)
    suite.True(got.Verified, "Add must replace the existing entry")
}

// TestRemoveDeletesEntry verifies Remove deletes the entry so Get reports ErrNotFound.
func (suite *SubjectFilterDAOMongoSuite) TestRemoveDeletesEntry() {
    ctx := context.Background()
    suite.NoError(suite.dao.Add(ctx, mSimpleEntry("stream-1", "email:alice@example.com")))
    suite.NoError(suite.dao.Remove(ctx, "stream-1", "email:alice@example.com"))

    _, err := suite.dao.Get(ctx, "stream-1", "email:alice@example.com")
    suite.True(errors.Is(err, interfaces.ErrNotFound), "Get after Remove must report ErrNotFound")
}

// TestRemoveMissingIsNotError verifies removing a non-existent entry is a no-op.
func (suite *SubjectFilterDAOMongoSuite) TestRemoveMissingIsNotError() {
    suite.NoError(suite.dao.Remove(context.Background(), "stream-1", "email:nobody@example.com"))
}

// TestClearForStreamWipesOnlyThatStream verifies ClearForStream removes every
// entry for the named stream and leaves other streams untouched.
func (suite *SubjectFilterDAOMongoSuite) TestClearForStreamWipesOnlyThatStream() {
    ctx := context.Background()
    _ = suite.dao.Add(ctx, mSimpleEntry("stream-1", "email:alice@example.com"))
    _ = suite.dao.Add(ctx, mSimpleEntry("stream-1", "email:bob@example.com"))
    _ = suite.dao.Add(ctx, mSimpleEntry("stream-2", "email:carol@example.com"))

    suite.NoError(suite.dao.ClearForStream(ctx, "stream-1"))

    _, err := suite.dao.Get(ctx, "stream-1", "email:alice@example.com")
    suite.True(errors.Is(err, interfaces.ErrNotFound), "stream-1 entry must be cleared")
    _, err = suite.dao.Get(ctx, "stream-2", "email:carol@example.com")
    suite.NoError(err, "stream-2 entry must survive ClearForStream(stream-1)")
}

// TestListComplexReturnsOnlyNonSimpleForStream verifies ListComplex returns the
// complex and aliases entries for one stream and never the simple entries.
func (suite *SubjectFilterDAOMongoSuite) TestListComplexReturnsOnlyNonSimpleForStream() {
    ctx := context.Background()
    _ = suite.dao.Add(ctx, mSimpleEntry("stream-1", "email:alice@example.com"))
    _ = suite.dao.Add(ctx, &model.SubjectFilterEntry{StreamId: "stream-1", CanonicalKey: "complex:[user=email:u]", Kind: model.SubjectKindComplex})
    _ = suite.dao.Add(ctx, &model.SubjectFilterEntry{StreamId: "stream-1", CanonicalKey: "aliases:[email:a]", Kind: model.SubjectKindAliases})
    _ = suite.dao.Add(ctx, &model.SubjectFilterEntry{StreamId: "stream-2", CanonicalKey: "complex:[user=email:v]", Kind: model.SubjectKindComplex})

    got, err := suite.dao.ListComplex(ctx, "stream-1")
    suite.NoError(err)
    suite.Len(got, 2, "ListComplex must return the 2 non-simple stream-1 entries")
    for _, e := range got {
        suite.NotEqual(model.SubjectKindSimple, e.Kind, "ListComplex must never return a simple entry")
        suite.Equal("stream-1", e.StreamId)
    }
}
