package mongo_provider

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// indexNames returns the set of index names present on col.
func indexNames(t *testing.T, col *mongo.Collection) map[string]bool {
	t.Helper()
	specs, err := col.Indexes().ListSpecifications(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListSpecifications: %v", err)
	}
	names := make(map[string]bool, len(specs))
	for _, s := range specs {
		names[s.Name] = true
	}
	return names
}

// explainPlan describes what an explain output says the server actually did.
// The fields are gathered by walking the whole explain document rather than
// indexing fixed paths, because the document shape differs between the find
// and aggregate commands and between server versions.
type explainPlan struct {
	stages       map[string]bool
	indexes      map[string]bool
	docsExamined int64
	keysExamined int64
	sawExecStats bool
}

func (p explainPlan) usedIndex(name string) bool { return p.indexes[name] }

func (p explainPlan) String() string {
	return fmt.Sprintf("stages=%v indexes=%v docsExamined=%d keysExamined=%d",
		keysOf(p.stages), keysOf(p.indexes), p.docsExamined, p.keysExamined)
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func asInt64(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		return int64(n), true
	}
	return 0, false
}

// walkExplain recursively collects stage names, index names, and the largest
// totalDocsExamined / totalKeysExamined it finds anywhere in the document.
func walkExplain(v interface{}, p *explainPlan) {
	switch node := v.(type) {
	case bson.M:
		for k, val := range node {
			walkExplainField(k, val, p)
		}
	case bson.A:
		for _, val := range node {
			walkExplain(val, p)
		}
	case bson.D:
		for _, e := range node {
			walkExplainField(e.Key, e.Value, p)
		}
	}
}

// walkExplainField records the one field k=val and then descends into val.
func walkExplainField(k string, val interface{}, p *explainPlan) {
	switch k {
	case "rejectedPlans":
		// Only the winning plan runs. A rejected candidate (say, the partial
		// createdAt index followed by a SORT) says nothing about production.
		return
	case "stage":
		if s, ok := val.(string); ok {
			p.stages[s] = true
		}
	case "indexName":
		if s, ok := val.(string); ok {
			p.indexes[s] = true
		}
	case "totalDocsExamined", "docsExamined":
		if n, ok := asInt64(val); ok && n > p.docsExamined {
			p.docsExamined = n
			p.sawExecStats = true
		}
	case "totalKeysExamined", "keysExamined":
		if n, ok := asInt64(val); ok && n > p.keysExamined {
			p.keysExamined = n
			p.sawExecStats = true
		}
	}
	walkExplain(val, p)
}

// runExplain issues an explain of inner at executionStats verbosity and
// summarizes the resulting plan.
func runExplain(t *testing.T, p *MongoProvider, inner bson.D) explainPlan {
	t.Helper()
	cmd := bson.D{
		{Key: "explain", Value: inner},
		{Key: "verbosity", Value: "executionStats"},
	}
	var raw bson.M
	if err := p.ssefDb.RunCommand(context.Background(), cmd).Decode(&raw); err != nil {
		t.Fatalf("explain %v: %v", inner, err)
	}
	plan := explainPlan{stages: map[string]bool{}, indexes: map[string]bool{}}
	walkExplain(raw, &plan)
	if !plan.sawExecStats {
		t.Fatalf("explain returned no executionStats: %v", raw)
	}
	return plan
}

// seedPendingRefs inserts n pending delivery references for sid into the
// deliveries collection and returns their JTIs.
func seedPendingRefs(t *testing.T, col *mongo.Collection, sid bson.ObjectID, n int, prefix string) []string {
	t.Helper()
	docs := make([]interface{}, 0, n)
	jtis := make([]string, 0, n)
	now := time.Now()
	for i := 0; i < n; i++ {
		jti := fmt.Sprintf("%s-%05d", prefix, i)
		jtis = append(jtis, jti)
		docs = append(docs, bson.M{"sid": sid, "jti": jti, "ackJti": jti, "state": "pending", "createdAt": now})
	}
	if _, err := col.InsertMany(context.Background(), docs); err != nil {
		t.Fatalf("InsertMany: %v", err)
	}
	return jtis
}

// allDeliveriesIndexNames are the deliveries indexes createIndexes installs.
var allDeliveriesIndexNames = []string{
	deliveriesSidJtiIndexName,
	deliveriesSidAckJtiIndexName,
	deliveriesSidStateJtiIndexName,
	deliveriesExpireAtIndexName,
	deliveriesJtiIndexName,
	deliveriesPendingCreatedAtIndexName,
}

// assertDeliveriesIndexes fails t for every deliveries index or the events
// originalJti index that p lacks.
func assertDeliveriesIndexes(t *testing.T, p *MongoProvider, when string) {
	t.Helper()
	names := indexNames(t, p.deliveriesCol)
	for _, n := range allDeliveriesIndexNames {
		if !names[n] {
			t.Errorf("%s: deliveries index %q missing (have %v)", when, n, keysOf(names))
		}
	}
	if ev := indexNames(t, p.eventCol); !ev[eventOriginalJtiIndexName] {
		t.Errorf("%s: events index %q missing (have %v)", when, eventOriginalJtiIndexName, keysOf(ev))
	}
}

// TestDeliveriesIndexes_CreatedOnFreshDb: a fresh database's createIndexes
// run installs every deliveries index (#359) and the events originalJti index.
func TestDeliveriesIndexes_CreatedOnFreshDb(t *testing.T) {
	p := openEventIdxProvider(t)
	assertDeliveriesIndexes(t, p, "fresh db")
}

// TestDeliveriesIndexes_Idempotent: re-running createIndexes against a
// database that already has the indexes is a no-op, not an error.
func TestDeliveriesIndexes_Idempotent(t *testing.T) {
	p := openEventIdxProvider(t)
	ctx := context.Background()

	before := indexNames(t, p.deliveriesCol)
	if err := p.createIndexes(ctx); err != nil {
		t.Fatalf("second createIndexes must not error: %v", err)
	}
	after := indexNames(t, p.deliveriesCol)
	if len(before) != len(after) {
		t.Fatalf("index set changed on re-run: before %v after %v", keysOf(before), keysOf(after))
	}
	for n := range before {
		if !after[n] {
			t.Errorf("index %q disappeared on re-run", n)
		}
	}
}

// TestRemovePendingMany_ScanBoundedByBatch: the batched pending delete's
// filter {sid, jti:{$in}, state} examines a number of documents bounded by
// the $in list, not by the depth of the stream's pending buffer.
func TestRemovePendingMany_ScanBoundedByBatch(t *testing.T) {
	p := openEventIdxProvider(t)

	sid := bson.NewObjectID()
	const buffered = 2000
	jtis := seedPendingRefs(t, p.deliveriesCol, sid, buffered, "ack")

	batch := jtis[:25]
	filter := bson.D{
		{Key: "sid", Value: sid},
		{Key: "jti", Value: bson.D{{Key: "$in", Value: batch}}},
		{Key: "state", Value: "pending"},
	}
	plan := runExplain(t, p, bson.D{{Key: "find", Value: CDbDeliveries}, {Key: "filter", Value: filter}})
	if plan.stages["COLLSCAN"] {
		t.Fatalf("RemovePendingMany filter fell back to a collection scan: %s", plan)
	}
	if plan.docsExamined > int64(len(batch)) {
		t.Fatalf("docsExamined %d exceeds the batch size %d (buffer depth %d): %s",
			plan.docsExamined, len(batch), buffered, plan)
	}

	removed, err := p.GetEventDAO().RemovePendingMany(context.Background(), batch, sid.Hex())
	if err != nil {
		t.Fatalf("RemovePendingMany: %v", err)
	}
	if len(removed) != len(batch) {
		t.Fatalf("RemovePendingMany removed %d, want %d", len(removed), len(batch))
	}
}

// TestAck_ScanBoundedByBatch: the Ack filter {sid, ackJti:{$in}, state} is an
// index scan bounded by the batch, served by deliveriesSidAckJti.
func TestAck_ScanBoundedByBatch(t *testing.T) {
	p := openEventIdxProvider(t)

	sid := bson.NewObjectID()
	const buffered = 2000
	jtis := seedPendingRefs(t, p.deliveriesCol, sid, buffered, "ackj")

	batch := jtis[:25]
	filter := bson.D{
		{Key: "sid", Value: sid},
		{Key: "ackJti", Value: bson.D{{Key: "$in", Value: batch}}},
		{Key: "state", Value: "pending"},
	}
	plan := runExplain(t, p, bson.D{{Key: "find", Value: CDbDeliveries}, {Key: "filter", Value: filter}})
	if plan.stages["COLLSCAN"] {
		t.Fatalf("Ack filter fell back to a collection scan: %s", plan)
	}
	if !plan.usedIndex(deliveriesSidAckJtiIndexName) {
		t.Fatalf("Ack filter did not use %q: %s", deliveriesSidAckJtiIndexName, plan)
	}
	if plan.docsExamined > int64(len(batch)) {
		t.Fatalf("docsExamined %d exceeds the batch size %d: %s", plan.docsExamined, len(batch), plan)
	}
}

// TestGetPendingForStream_IndexedSortedRead: the pending page read
// {sid, state:"pending"} sorted by jti is served by deliveriesSidStateJti
// without a blocking SORT stage.
func TestGetPendingForStream_IndexedSortedRead(t *testing.T) {
	p := openEventIdxProvider(t)

	sid := bson.NewObjectID()
	seedPendingRefs(t, p.deliveriesCol, sid, 2000, "page")
	plan := runExplain(t, p, bson.D{
		{Key: "find", Value: CDbDeliveries},
		{Key: "filter", Value: bson.D{{Key: "sid", Value: sid}, {Key: "state", Value: "pending"}}},
		{Key: "sort", Value: bson.D{{Key: "jti", Value: 1}}},
		{Key: "limit", Value: 100},
	})
	if !plan.usedIndex(deliveriesSidStateJtiIndexName) {
		t.Fatalf("pending read did not use %q: %s", deliveriesSidStateJtiIndexName, plan)
	}
	if plan.stages["SORT"] || plan.stages["COLLSCAN"] {
		t.Fatalf("pending read needs a blocking sort or collection scan: %s", plan)
	}
}

// TestDeleteBodyIfUnreferenced_RefcountUsesIndex: the per-JTI refcount on the
// retention purge path is an index scan on deliveriesJti, not a collection
// scan.
func TestDeleteBodyIfUnreferenced_RefcountUsesIndex(t *testing.T) {
	p := openEventIdxProvider(t)

	sid := bson.NewObjectID()
	// Seeded: the planner short-circuits an empty collection.
	seedPendingRefs(t, p.deliveriesCol, sid, 2000, "purge")

	// CountDocuments issues an aggregate; explain the same pipeline so the
	// plan under test is the plan production gets.
	plan := runExplain(t, p, bson.D{
		{Key: "aggregate", Value: CDbDeliveries},
		{Key: "pipeline", Value: bson.A{
			bson.D{{Key: "$match", Value: bson.D{{Key: "jti", Value: "purge-00001"}}}},
			bson.D{{Key: "$group", Value: bson.D{
				{Key: "_id", Value: nil},
				{Key: "n", Value: bson.D{{Key: "$sum", Value: 1}}},
			}}},
		}},
		{Key: "cursor", Value: bson.D{}},
	})
	if plan.stages["COLLSCAN"] {
		t.Errorf("jti refcount is still a collection scan: %s", plan)
	}
	if !plan.usedIndex(deliveriesJtiIndexName) {
		t.Errorf("jti refcount did not use %q: %s", deliveriesJtiIndexName, plan)
	}
}

// TestDeliveriesIndexes_BuiltOnExistingDatabase is the upgrade path: a server
// that starts against a database it has seen before must still build indexes
// a later release added. Reconnecting to a database whose deliveries indexes
// are missing must restore them.
func TestDeliveriesIndexes_BuiltOnExistingDatabase(t *testing.T) {
	p := openEventIdxProvider(t)
	ctx := context.Background()

	for _, n := range allDeliveriesIndexNames {
		_ = p.deliveriesCol.Indexes().DropOne(ctx, n)
	}
	_ = p.eventCol.Indexes().DropOne(ctx, eventOriginalJtiIndexName)
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Restart against the SAME database: dbExists is true this time.
	p2, err := Open(ttlMongoURL(), "eventidxtest")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = p2.Close() })
	assertDeliveriesIndexes(t, p2, "restart against an existing database")
}
