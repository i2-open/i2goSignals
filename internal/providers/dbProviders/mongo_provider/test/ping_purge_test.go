package test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/mongo_provider"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/goSet/events"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// TestPingPurge_MongoRun is done-means 1 of planning#142 (ADR 0048): on a
// Mongo-backed store with the default retention, one run deletes a ping
// delivered and stored 30h ago from both collections, logs its INFO summary,
// and leaves a pending ping and a data event of the same age in place.
func TestPingPurge_MongoRun(t *testing.T) {
	setMongoResumeFileTempDir(t)
	t.Setenv(services.PingRetentionEnv, "")
	dbName := "ssef_test_ping_purge"
	p, err := mongo_provider.Open(mongoURL(), dbName)
	if err != nil {
		t.Skip("MongoDB client error: " + err.Error())
	}
	if err := p.Check(); err != nil {
		t.Skip("MongoDB Server not available: " + err.Error())
	}
	require.NoError(t, p.ResetDb(true))
	t.Cleanup(func() { _ = p.Close() })

	client, err := mongo.Connect(options.Client().ApplyURI(mongoURL()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	db := client.Database(dbName)

	buf := &lockedBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	ctx := context.Background()
	d := p.GetEventDAO()
	stored := time.Now().UTC().Add(-30 * time.Hour).Truncate(time.Millisecond)
	sid := bson.NewObjectID().Hex()
	put := func(jti string, ping bool) {
		types := []string{"urn:test"}
		if ping {
			types = []string{events.VerificationEventUri}
		}
		require.NoError(t, d.Insert(ctx, &model.EventRecord{Jti: jti, Types: types, Original: jti, SortTime: stored, ReceivedAt: stored}))
		require.NoError(t, d.AddPending(ctx, interfaces.PendingRef{Jti: jti, AckJti: jti, EnqueuedAt: stored, Ping: ping}, sid))
	}
	put("delivered-ping", true)
	put("pending-ping", true)
	put("delivered-data", false)
	_, err = d.Ack(ctx, interfaces.AckBatch{StreamID: sid, Jtis: []string{"delivered-ping", "delivered-data"}, AckDate: stored.Add(time.Minute)})
	require.NoError(t, err)

	count := func(coll, jti string) int64 {
		n, err := db.Collection(coll).CountDocuments(ctx, bson.D{{Key: "jti", Value: jti}})
		require.NoError(t, err)
		return n
	}
	require.Equal(t, int64(1), count(mongo_provider.CDbEvents, "delivered-ping"))
	require.Equal(t, int64(1), count(mongo_provider.CDbDeliveries, "delivered-ping"))

	purger := services.NewPingPurger(d, p.Coordinator(), "node-1",
		services.PingPurgeOptions{Retention: services.PingRetentionFromEnv(), Pause: time.Millisecond})
	sum, err := purger.RunOnce(ctx)
	require.NoError(t, err)
	assert.True(t, sum.Ran)
	assert.Equal(t, int64(1), sum.Deliveries)
	assert.Equal(t, int64(1), sum.Bodies)

	assert.Equal(t, int64(0), count(mongo_provider.CDbEvents, "delivered-ping"), "ping body gone")
	assert.Equal(t, int64(0), count(mongo_provider.CDbDeliveries, "delivered-ping"), "ping delivery row gone")
	assert.Equal(t, int64(1), count(mongo_provider.CDbEvents, "pending-ping"), "pending ping body kept")
	assert.Equal(t, int64(1), count(mongo_provider.CDbDeliveries, "pending-ping"), "pending ping row kept")
	assert.Equal(t, int64(1), count(mongo_provider.CDbEvents, "delivered-data"), "data event kept")
	assert.Equal(t, int64(1), count(mongo_provider.CDbDeliveries, "delivered-data"), "data row kept")

	var summary string
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, "Ping purge complete") {
			summary = line
		}
	}
	require.NotEmpty(t, summary, buf.String())
	assert.Contains(t, summary, "level=INFO")
	assert.Contains(t, summary, "deliveries=1")
	assert.Contains(t, summary, "bodies=1")

	last, err := p.Coordinator().LastPingPurge()
	require.NoError(t, err)
	assert.False(t, last.IsZero(), "the run records lastPurgeAt")
}
