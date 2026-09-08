package mongo_provider

import (
	"context"
	"fmt"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
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

// seedPendingRefs inserts n pending references for sid and returns their JTIs.
func seedPendingRefs(t *testing.T, col *mongo.Collection, sid bson.ObjectID, n int, prefix string) []string {
	t.Helper()
	docs := make([]interface{}, 0, n)
	jtis := make([]string, 0, n)
	for i := 0; i < n; i++ {
		jti := fmt.Sprintf("%s-%05d", prefix, i)
		jtis = append(jtis, jti)
		docs = append(docs, bson.M{"jti": jti, "sid": sid})
	}
	if _, err := col.InsertMany(context.Background(), docs); err != nil {
		t.Fatalf("InsertMany: %v", err)
	}
	return jtis
}

// TestEventRefIndexes_CreatedOnFreshDb: a fresh database's createIndexes run
// installs the compound {sid,jti} and single-field {jti} indexes on both
// pendingEvents and deliveredEvents, and leaves no legacy sid-only index.
func TestEventRefIndexes_CreatedOnFreshDb(t *testing.T) {
	p := openEventIdxProvider(t)

	for _, tc := range []struct {
		col            *mongo.Collection
		name           string
		sidJti, jtiIdx string
	}{
		{p.pendingCol, CDbPending, pendingSidJtiIndexName, pendingJtiIndexName},
		{p.deliveredCol, CDbDelivered, deliveredSidJtiIndexName, deliveredJtiIndexName},
	} {
		names := indexNames(t, tc.col)
		if !names[tc.sidJti] {
			t.Errorf("%s: compound index %q missing (have %v)", tc.name, tc.sidJti, keysOf(names))
		}
		if !names[tc.jtiIdx] {
			t.Errorf("%s: jti index %q missing (have %v)", tc.name, tc.jtiIdx, keysOf(names))
		}
		if names[legacySidIndexName] {
			t.Errorf("%s: legacy %q index should be retired by the compound index", tc.name, legacySidIndexName)
		}
	}
}

// TestEventRefIndexes_Idempotent: re-running createIndexes against a database
// that already has the indexes is a no-op, not an error. This is the restart
// path for an existing deployment — no migration step is required.
func TestEventRefIndexes_Idempotent(t *testing.T) {
	p := openEventIdxProvider(t)
	ctx := context.Background()

	before := indexNames(t, p.pendingCol)
	if err := p.createIndexes(ctx); err != nil {
		t.Fatalf("second createIndexes must not error: %v", err)
	}
	after := indexNames(t, p.pendingCol)
	if len(before) != len(after) {
		t.Fatalf("index set changed on re-run: before %v after %v", keysOf(before), keysOf(after))
	}
	for n := range before {
		if !after[n] {
			t.Errorf("index %q disappeared on re-run", n)
		}
	}
}

// TestEventRefIndexes_LegacySidIndexRetired: a deployment upgrading from the
// sid-only index has it dropped in favour of the compound index, which serves
// the same sid-prefixed queries. The drop happens after the compound index is
// in place, so the sid access path is never unindexed.
func TestEventRefIndexes_LegacySidIndexRetired(t *testing.T) {
	p := openEventIdxProvider(t)
	ctx := context.Background()

	// Recreate the pre-upgrade state: the auto-named {sid:1} index.
	if _, err := p.pendingCol.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "sid", Value: 1}},
		Options: options.Index().SetName(legacySidIndexName),
	}); err != nil {
		t.Fatalf("could not recreate legacy index: %v", err)
	}
	if !indexNames(t, p.pendingCol)[legacySidIndexName] {
		t.Fatal("legacy index was not created; test setup is wrong")
	}

	if err := p.createIndexes(ctx); err != nil {
		t.Fatalf("createIndexes: %v", err)
	}

	names := indexNames(t, p.pendingCol)
	if names[legacySidIndexName] {
		t.Errorf("legacy index %q was not retired", legacySidIndexName)
	}
	if !names[pendingSidJtiIndexName] {
		t.Errorf("compound index %q missing after legacy retirement", pendingSidJtiIndexName)
	}
}

// TestRemovePendingMany_ScanBoundedByBatch proves the acceptance criterion for
// the batched-ack path: with the compound {sid,jti} index the number of
// documents examined for {sid, jti:{$in:[...]}} is bounded by the size of the
// $in list, not by the depth of the stream's pending buffer. Before the index
// this filter could only seek on the sid prefix and examined every pending
// document for the stream.
func TestRemovePendingMany_ScanBoundedByBatch(t *testing.T) {
	p := openEventIdxProvider(t)

	sid := bson.NewObjectID()
	const buffered = 2000
	jtis := seedPendingRefs(t, p.pendingCol, sid, buffered, "ack")

	batch := jtis[:25]
	filter := bson.D{{Key: "sid", Value: sid}, {Key: "jti", Value: bson.D{{Key: "$in", Value: batch}}}}

	plan := runExplain(t, p, bson.D{
		{Key: "find", Value: CDbPending},
		{Key: "filter", Value: filter},
	})

	if !plan.usedIndex(pendingSidJtiIndexName) {
		t.Fatalf("RemovePendingMany filter did not use %q: %s", pendingSidJtiIndexName, plan)
	}
	if plan.stages["COLLSCAN"] {
		t.Fatalf("RemovePendingMany filter fell back to a collection scan: %s", plan)
	}
	if plan.docsExamined > int64(len(batch)) {
		t.Fatalf("docsExamined %d exceeds the batch size %d (buffer depth %d): %s",
			plan.docsExamined, len(batch), buffered, plan)
	}

	// Sanity: the DAO's real call returns exactly the batch, so the plan
	// above is the plan the production path gets.
	removed, err := p.GetEventDAO().RemovePendingMany(context.Background(), batch, sid.Hex())
	if err != nil {
		t.Fatalf("RemovePendingMany: %v", err)
	}
	if len(removed) != len(batch) {
		t.Fatalf("RemovePendingMany removed %d, want %d", len(removed), len(batch))
	}
}

// TestDeleteBodyIfUnreferenced_RefcountUsesIndex proves the second acceptance
// criterion: the per-JTI refcount counts on the retention purge path are index
// scans, not collection scans, on both reference collections.
func TestDeleteBodyIfUnreferenced_RefcountUsesIndex(t *testing.T) {
	p := openEventIdxProvider(t)

	sid := bson.NewObjectID()
	// Both collections are seeded: the planner short-circuits an empty
	// collection, so an unseeded one would not exercise the index choice.
	seedPendingRefs(t, p.pendingCol, sid, 2000, "purge")
	seedPendingRefs(t, p.deliveredCol, sid, 2000, "purge")

	for _, tc := range []struct {
		colName string
		index   string
	}{
		{CDbPending, pendingJtiIndexName},
		{CDbDelivered, deliveredJtiIndexName},
	} {
		// CountDocuments issues an aggregate; explain the same pipeline so
		// the plan under test is the plan production gets.
		plan := runExplain(t, p, bson.D{
			{Key: "aggregate", Value: tc.colName},
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
			t.Errorf("%s: jti refcount is still a collection scan: %s", tc.colName, plan)
		}
		if !plan.usedIndex(tc.index) {
			t.Errorf("%s: jti refcount did not use %q: %s", tc.colName, tc.index, plan)
		}
	}
}
