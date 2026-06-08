package mongo

import (
    "context"
    "errors"
    "fmt"
    "strings"
    "testing"
    "time"

    interfaces "github.com/i2-open/i2goSignals/pkg/dao"
    model "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/suite"
    "go.mongodb.org/mongo-driver/v2/bson"
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

// TestEnforceAtRoundTrips verifies the SSF §9.3 EnforceAt field survives
// Add/Get round-trip on the Mongo adapter (PRD #97 issue #99). The field
// must encode and decode at the second granularity expected by BSON time.
func (suite *SubjectFilterDAOMongoSuite) TestEnforceAtRoundTrips() {
    ctx := context.Background()
    deadline := time.Date(2026, 5, 19, 12, 30, 0, 0, time.UTC)
    entry := mSimpleEntry("stream-1", "email:alice@example.com")
    entry.EnforceAt = deadline

    suite.NoError(suite.dao.Add(ctx, entry))

    got, err := suite.dao.Get(ctx, "stream-1", "email:alice@example.com")
    suite.NoError(err)
    suite.True(got.EnforceAt.Equal(deadline), "EnforceAt must round-trip: want %v, got %v", deadline, got.EnforceAt)
}

// TestEnforceAtReviveClearsField verifies that re-Adding an entry with a zero
// EnforceAt (the §9.3 revive case) overwrites the previously-stamped
// deadline, so the stored entry is fully active again.
func (suite *SubjectFilterDAOMongoSuite) TestEnforceAtReviveClearsField() {
    ctx := context.Background()
    pending := mSimpleEntry("stream-1", "email:alice@example.com")
    pending.EnforceAt = time.Date(2026, 5, 19, 12, 30, 0, 0, time.UTC)
    suite.NoError(suite.dao.Add(ctx, pending))

    revived := mSimpleEntry("stream-1", "email:alice@example.com")
    suite.NoError(suite.dao.Add(ctx, revived))

    got, err := suite.dao.Get(ctx, "stream-1", "email:alice@example.com")
    suite.NoError(err)
    suite.True(got.EnforceAt.IsZero(), "revive must clear EnforceAt, got %v", got.EnforceAt)
}

// TestEnforceAtSparsePartialIndexExists verifies the SSF §9.3 sparse partial
// index on enforce_at — the index that lets future admin reviews enumerate
// pending-removal entries without scanning the (potentially millions of) full
// filter table (PRD #97 issue #99, ADR-0003).
func (suite *SubjectFilterDAOMongoSuite) TestEnforceAtSparsePartialIndexExists() {
    ctx := context.Background()
    cursor, err := suite.collection.Indexes().List(ctx)
    suite.NoError(err)
    var idx []bson.M
    suite.NoError(cursor.All(ctx, &idx))

    found := false
    for _, ix := range idx {
        // Default index name encodes the keys as "<field>_<dir>_..."; the
        // §9.3 index is created on (stream_id, enforce_at) so its name
        // contains "enforce_at". This is robust against driver-version
        // changes to the shape of the "key" sub-document.
        name, _ := ix["name"].(string)
        if !strings.Contains(name, "enforce_at") {
            continue
        }
        found = true
        // The index must be partial on enforce_at $exists so it only
        // covers pending-removal entries.
        pfe, hasPFE := ix["partialFilterExpression"]
        suite.True(hasPFE, "the §9.3 enforce_at index must be a partial index, not a full one")
        // The driver may decode the nested doc as bson.M or bson.D; render
        // it as a string and look for the $exists constraint either way.
        rendered := fmt.Sprintf("%v", pfe)
        suite.Contains(rendered, "$exists", "partialFilterExpression must require enforce_at to exist; got %s", rendered)
        suite.Contains(rendered, "enforce_at", "partialFilterExpression must target the enforce_at field; got %s", rendered)
        break
    }
    suite.True(found, "an index on enforce_at must exist for SSF §9.3 pending-removal enumeration")
}

// TestListPendingDueReturnsOnlyElapsedForStream verifies the SSF §9.3 sweep
// enumerator (PRD #97 issue #100): ListPendingDue returns every entry for the
// named stream whose enforce_at is set and has elapsed at now, and never
// returns active entries or entries from other streams. The mongo adapter
// rides the sparse partial index on enforce_at — only pending entries are
// indexed, so the query stays cheap at scale.
func (suite *SubjectFilterDAOMongoSuite) TestListPendingDueReturnsOnlyElapsedForStream() {
    ctx := context.Background()
    now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)

    elapsed := mSimpleEntry("stream-1", "email:elapsed@example.com")
    elapsed.EnforceAt = now.Add(-time.Second)
    suite.NoError(suite.dao.Add(ctx, elapsed))

    pending := mSimpleEntry("stream-1", "email:pending@example.com")
    pending.EnforceAt = now.Add(30 * time.Second)
    suite.NoError(suite.dao.Add(ctx, pending))

    active := mSimpleEntry("stream-1", "email:active@example.com")
    suite.NoError(suite.dao.Add(ctx, active))

    otherStream := mSimpleEntry("stream-2", "email:elapsed-other@example.com")
    otherStream.EnforceAt = now.Add(-time.Second)
    suite.NoError(suite.dao.Add(ctx, otherStream))

    got, err := suite.dao.ListPendingDue(ctx, "stream-1", now)
    suite.NoError(err)
    suite.Len(got, 1, "ListPendingDue must return only the elapsed stream-1 entry")
    suite.Equal("email:elapsed@example.com", got[0].CanonicalKey)
}

// TestListPendingDueBoundaryIsInclusive verifies the clock-boundary behavior:
// an entry whose enforce_at equals now is treated as elapsed (consistent with
// entryDelivers's clock-boundary rule from slice #99).
func (suite *SubjectFilterDAOMongoSuite) TestListPendingDueBoundaryIsInclusive() {
    ctx := context.Background()
    now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)

    boundary := mSimpleEntry("stream-1", "email:boundary@example.com")
    boundary.EnforceAt = now
    suite.NoError(suite.dao.Add(ctx, boundary))

    got, err := suite.dao.ListPendingDue(ctx, "stream-1", now)
    suite.NoError(err)
    suite.Len(got, 1, "an entry whose enforce_at equals now must be elapsed")
}

// TestListPendingReturnsOnlyInGraceForStream verifies the admin-review pending
// enumerator (PRD #97 issue #101): ListPending returns entries whose
// enforce_at is strictly after now (still in §9.3 grace window), excludes
// due-or-boundary entries (the complement of ListPendingDue), excludes
// active entries (no enforce_at), and ignores other streams.
func (suite *SubjectFilterDAOMongoSuite) TestListPendingReturnsOnlyInGraceForStream() {
    ctx := context.Background()
    now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)

    inGrace := mSimpleEntry("stream-1", "email:in-grace@example.com")
    inGrace.EnforceAt = now.Add(30 * time.Second)
    suite.NoError(suite.dao.Add(ctx, inGrace))

    due := mSimpleEntry("stream-1", "email:due@example.com")
    due.EnforceAt = now.Add(-time.Second)
    suite.NoError(suite.dao.Add(ctx, due))

    boundary := mSimpleEntry("stream-1", "email:boundary@example.com")
    boundary.EnforceAt = now
    suite.NoError(suite.dao.Add(ctx, boundary))

    active := mSimpleEntry("stream-1", "email:active@example.com")
    suite.NoError(suite.dao.Add(ctx, active))

    other := mSimpleEntry("stream-2", "email:in-grace-other@example.com")
    other.EnforceAt = now.Add(30 * time.Second)
    suite.NoError(suite.dao.Add(ctx, other))

    got, err := suite.dao.ListPending(ctx, "stream-1", now)
    suite.NoError(err)
    suite.Len(got, 1, "ListPending must return only the in-grace stream-1 entry")
    suite.Equal("email:in-grace@example.com", got[0].CanonicalKey)
}

// TestCountReturnsTotalAndPending verifies the admin-review count pair (PRD
// #97 issue #101): total covers every stream entry; pending uses the same
// strictly-after-now predicate as ListPending, so review counts and the
// pending list always agree.
func (suite *SubjectFilterDAOMongoSuite) TestCountReturnsTotalAndPending() {
    ctx := context.Background()
    now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)

    inGrace := mSimpleEntry("stream-1", "email:in-grace@example.com")
    inGrace.EnforceAt = now.Add(30 * time.Second)
    suite.NoError(suite.dao.Add(ctx, inGrace))

    due := mSimpleEntry("stream-1", "email:due@example.com")
    due.EnforceAt = now.Add(-time.Second)
    suite.NoError(suite.dao.Add(ctx, due))

    active := mSimpleEntry("stream-1", "email:active@example.com")
    suite.NoError(suite.dao.Add(ctx, active))

    suite.NoError(suite.dao.Add(ctx, mSimpleEntry("stream-2", "email:other@example.com")))

    total, pending, err := suite.dao.Count(ctx, "stream-1", now)
    suite.NoError(err)
    suite.Equal(int64(3), total, "total must count every stream-1 entry")
    suite.Equal(int64(1), pending, "pending must count only the in-grace entry")
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
