package server

import (
	"context"
	"net"
	"sort"
	"testing"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/ids"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// TestClusterHarness_DeliveriesMigrationUnderLease seeds the pre-#359
// pendingEvents / deliveredEvents collections and boots node B while another
// node holds the migration:deliveries lease (#361, seam S2): B waits rather
// than serve, the holder migrates, and B, once it gets the lease, finds
// nothing to migrate and starts with the migrated documents unchanged.
func TestClusterHarness_DeliveriesMigrationUnderLease(t *testing.T) {
	h := newClusterHarness(t)
	ctx := context.Background()

	client, err := mongo.Connect(options.Client().ApplyURI(h.url))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	db := client.Database(h.db)

	sid, err := bson.ObjectIDFromHex(ids.NewObjectID())
	require.NoError(t, err)
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	// The driver assigns each legacy row an ObjectID _id, as the old writer did.
	_, err = db.Collection("pendingEvents").InsertMany(ctx, []any{
		bson.D{{Key: "jti", Value: "p1"}, {Key: "sid", Value: sid}},
		bson.D{{Key: "jti", Value: "both"}, {Key: "sid", Value: sid}},
	})
	require.NoError(t, err)
	_, err = db.Collection("deliveredEvents").InsertMany(ctx, []any{
		bson.D{{Key: "jti", Value: "d1"}, {Key: "sid", Value: sid}, {Key: "ackDate", Value: base}},
		bson.D{{Key: "jti", Value: "both"}, {Key: "sid", Value: sid}, {Key: "ackDate", Value: base}},
	})
	require.NoError(t, err)

	const resource = "migration:deliveries"
	held, _, err := h.admin.Coordinator.TryAcquireOrRenewLease(resource, "node-z", time.Minute)
	require.NoError(t, err)
	require.True(t, held)

	// Node B boots in the background: StartServer blocks in NewRouter until
	// the migration lease is free.
	p := h.open("node-b")
	t.Setenv("I2SIG_CLUSTER_NODE_ID", "node-b")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	started := make(chan *SignalsApplication, 1)
	go func() { started <- StartServer(listener.Addr().String(), p, "http://"+listener.Addr().String()+"/") }()

	select {
	case <-started:
		t.Fatal("node B started while node-z held the migration lease")
	case <-time.After(2500 * time.Millisecond):
	}

	res, err := h.admin.EventService.MigrateLegacyDeliveries(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, interfaces.MigrationResult{Pending: 2, Delivered: 2, Dropped: true}, res)
	want := deliveriesSnapshot(t, db)
	require.Len(t, want, 3)
	require.NoError(t, h.admin.Coordinator.ReleaseLeaseIfOwned(resource, "node-z"))

	var app *SignalsApplication
	select {
	case app = <-started:
	case <-time.After(30 * time.Second):
		t.Fatal("node B did not start after the migration lease was released")
	}
	go func() { _ = app.Server.Serve(listener) }()
	t.Cleanup(app.Shutdown)
	waitServing(t, "http://"+listener.Addr().String())

	assert.Equal(t, want, deliveriesSnapshot(t, db), "node B rewrote the migrated documents")
	names, err := db.ListCollectionNames(ctx, bson.D{{Key: "name", Value: bson.D{{Key: "$in", Value: []string{"pendingEvents", "deliveredEvents"}}}}})
	require.NoError(t, err)
	assert.Empty(t, names, "legacy collections left behind")
	owner, until, _, err := h.admin.Coordinator.GetLeaseOwner(resource)
	require.NoError(t, err)
	assert.True(t, owner == "" || time.Now().After(until), "migration lease still held by %q", owner)
}

// deliveriesSnapshot returns the deliveries documents sorted by jti.
func deliveriesSnapshot(t *testing.T, db *mongo.Database) []bson.M {
	t.Helper()
	cur, err := db.Collection("deliveries").Find(context.Background(), bson.D{})
	require.NoError(t, err)
	var docs []bson.M
	require.NoError(t, cur.All(context.Background(), &docs))
	sort.Slice(docs, func(i, j int) bool { return docs[i]["jti"].(string) < docs[j]["jti"].(string) })
	return docs
}
