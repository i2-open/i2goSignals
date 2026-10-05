package mongo_provider

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// mongoActiveWindow matches the active-window convention used by both
// adapters: a node is active if it has heartbeated in the last 60 seconds.
const mongoActiveWindow = 60 * time.Second

// MongoCoordinator implements cluster.ClusterCoordinator backed by MongoDB.
// It carries the lease and node-registry logic that previously lived on
// MongoProvider directly. Collection pointers are stored atomically so
// reconnect-driven rebinds don't need an external mutex.
type MongoCoordinator struct {
	leaseCol atomic.Pointer[mongo.Collection]
	nodeCol  atomic.Pointer[mongo.Collection]

	// ctx is the server lifecycle context handed in at construction (seam S4).
	// Every heartbeat/lease round-trip derives its per-operation deadline from
	// it, so cancelling it at shutdown cancels the in-flight Mongo call instead
	// of leaving it to run out its own 5s budget against a socket nobody will
	// read. Never nil — NewMongoCoordinator substitutes context.Background().
	ctx context.Context

	// clock, when set, replaces time.Now for the lease operations, so a test
	// can expire a lease without sleeping. See SetClock.
	clock atomic.Pointer[func() time.Time]
}

// SetClock replaces the clock the lease operations read. A nil clock
// restores time.Now.
func (c *MongoCoordinator) SetClock(now func() time.Time) {
	if now == nil {
		c.clock.Store(nil)
		return
	}
	c.clock.Store(&now)
}

// now reads the coordinator's clock in UTC.
func (c *MongoCoordinator) now() time.Time {
	if f := c.clock.Load(); f != nil {
		return (*f)().UTC()
	}
	return time.Now().UTC()
}

// NewMongoCoordinator returns a coordinator with no collections bound, whose
// operations are scoped to the server lifecycle ctx. The MongoProvider calls
// SetCollections after each successful (re)connect.
//
// A nil ctx is treated as context.Background() so that a caller which has no
// lifecycle to offer (a one-shot CLI, a test) still gets a usable coordinator.
func NewMongoCoordinator(ctx context.Context) *MongoCoordinator {
	if ctx == nil {
		ctx = context.Background()
	}
	return &MongoCoordinator{ctx: ctx}
}

// LifecycleContext returns the context this coordinator's heartbeats are scoped
// to — the signal that says "the process is going away". Callers that own work
// which must not outlive the cluster membership this coordinator maintains can
// hang their own cancellation off it rather than inventing a second shutdown
// channel that has to be kept in sync with this one.
func (c *MongoCoordinator) LifecycleContext() context.Context {
	if c.ctx == nil {
		return context.Background()
	}
	return c.ctx
}

// coordinatorOpTimeout bounds a single lease or node-registry round-trip.
const coordinatorOpTimeout = 5 * time.Second

// opCtx derives a per-operation context from the lifecycle ctx. The returned
// context is cancelled either by the operation timeout or by server shutdown,
// whichever comes first; callers must always call the returned cancel func.
func (c *MongoCoordinator) opCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(c.LifecycleContext(), coordinatorOpTimeout)
}

// SetCollections binds (or rebinds) the collections used for leases and the
// node registry. Safe to call concurrently with coordinator method calls;
// callers in flight will see either the old or the new collection.
func (c *MongoCoordinator) SetCollections(leaseCol, nodeCol *mongo.Collection) {
	c.leaseCol.Store(leaseCol)
	c.nodeCol.Store(nodeCol)
}

// errCoordinatorNotInit is returned before the coordinator's collection is
// bound (the provider has not connected yet); it wraps ErrStoreNotReady.
var errCoordinatorNotInit = fmt.Errorf("mongo coordinator not initialized: %w", interfaces.ErrStoreNotReady)

// Compile-time check.
var _ cluster.ClusterCoordinator = (*MongoCoordinator)(nil)

func (c *MongoCoordinator) TryAcquireOrRenewLease(resource string, nodeId string, leaseDuration time.Duration) (bool, int64, time.Time, error) {
	col := c.leaseCol.Load()
	if col == nil {
		return false, 0, time.Time{}, errCoordinatorNotInit
	}

	ctx, cancel := c.opCtx()
	defer cancel()

	now := c.now()
	leaseUntil := now.Add(leaseDuration)

	filter := bson.M{
		"_id": resource,
		"$or": []bson.M{
			{"leaseUntil": bson.M{"$lte": now}},
			{"ownerNodeId": nodeId},
		},
	}

	// A renewal by the holder of a live lease keeps its fencing token, so the
	// holder's acks stay valid across heartbeats. Any acquisition of an expired
	// or unowned lease, by the same node or another, starts a new tenure with
	// the next token (#334). The pipeline form reads the stored owner and
	// expiry before overwriting them.
	renewal := bson.M{"$and": bson.A{
		bson.M{"$eq": bson.A{"$ownerNodeId", nodeId}},
		bson.M{"$gt": bson.A{"$leaseUntil", now}},
	}}
	update := mongo.Pipeline{
		{{Key: "$set", Value: bson.M{
			"fencingToken": bson.M{"$cond": bson.A{
				renewal,
				"$fencingToken",
				bson.M{"$add": bson.A{bson.M{"$ifNull": bson.A{"$fencingToken", 0}}, 1}},
			}},
			"ownerNodeId": nodeId,
			"leaseUntil":  leaseUntil,
			"updatedAt":   now,
			"createdAt":   bson.M{"$ifNull": bson.A{"$createdAt", now}},
		}}},
	}

	opts := options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After)

	var lease model.ClusterLease
	err := col.FindOneAndUpdate(ctx, filter, update, opts).Decode(&lease)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return false, 0, time.Time{}, nil
		}
		return false, 0, time.Time{}, err
	}

	// The After-document holds the expiry this call stored (#364).
	if lease.OwnerNodeId != nodeId {
		return false, lease.FencingToken, time.Time{}, nil
	}
	return true, lease.FencingToken, lease.LeaseUntil, nil
}

func (c *MongoCoordinator) ReleaseLeaseIfOwned(resource string, nodeId string) error {
	col := c.leaseCol.Load()
	if col == nil {
		return errCoordinatorNotInit
	}

	ctx, cancel := c.opCtx()
	defer cancel()

	filter := bson.M{
		"_id":         resource,
		"ownerNodeId": nodeId,
	}
	now := c.now()
	update := bson.M{
		"$set": bson.M{
			"leaseUntil": now,
			"updatedAt":  now,
		},
	}

	_, err := col.UpdateOne(ctx, filter, update)
	return err
}

func (c *MongoCoordinator) GetLeaseOwner(resource string) (string, time.Time, int64, error) {
	col := c.leaseCol.Load()
	if col == nil {
		return "", time.Time{}, 0, errCoordinatorNotInit
	}

	ctx, cancel := c.opCtx()
	defer cancel()

	var lease model.ClusterLease
	err := col.FindOne(ctx, bson.M{"_id": resource}).Decode(&lease)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return "", time.Time{}, 0, nil
		}
		return "", time.Time{}, 0, err
	}
	if !lease.LeaseUntil.After(c.now()) {
		// An expired (or released) lease has no owner.
		return "", time.Time{}, 0, nil
	}

	return lease.OwnerNodeId, lease.LeaseUntil, lease.FencingToken, nil
}

func (c *MongoCoordinator) RegisterNode(node model.ClusterNode) error {
	col := c.nodeCol.Load()
	if col == nil {
		return errCoordinatorNotInit
	}

	ctx, cancel := c.opCtx()
	defer cancel()

	filter := bson.M{"_id": node.Id}
	update := bson.M{
		"$set": bson.M{
			"address":    node.Address,
			"version":    node.Version,
			"lastSeenAt": node.LastSeenAt,
		},
		"$setOnInsert": bson.M{
			"startedAt": node.StartedAt,
		},
	}

	opts := options.UpdateOne().SetUpsert(true)
	_, err := col.UpdateOne(ctx, filter, update, opts)
	return err
}

func (c *MongoCoordinator) GetActiveNodeCount() (int64, error) {
	col := c.nodeCol.Load()
	if col == nil {
		return 0, errCoordinatorNotInit
	}

	ctx, cancel := c.opCtx()
	defer cancel()

	threshold := time.Now().UTC().Add(-mongoActiveWindow)
	filter := bson.M{
		"lastSeenAt": bson.M{"$gte": threshold},
	}

	return col.CountDocuments(ctx, filter)
}

func (c *MongoCoordinator) GetActiveNodes() ([]model.ClusterNode, error) {
	col := c.nodeCol.Load()
	if col == nil {
		return nil, errCoordinatorNotInit
	}

	ctx, cancel := c.opCtx()
	defer cancel()

	threshold := time.Now().UTC().Add(-mongoActiveWindow)
	filter := bson.M{
		"lastSeenAt": bson.M{"$gte": threshold},
	}

	cursor, err := col.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer func(cursor *mongo.Cursor, ctx context.Context) {
		_ = cursor.Close(ctx)
	}(cursor, ctx)

	var nodes []model.ClusterNode
	if err := cursor.All(ctx, &nodes); err != nil {
		return nil, err
	}

	return nodes, nil
}

func (c *MongoCoordinator) GetNode(nodeId string) (*model.ClusterNode, error) {
	col := c.nodeCol.Load()
	if col == nil {
		return nil, errCoordinatorNotInit
	}

	ctx, cancel := c.opCtx()
	defer cancel()

	var node model.ClusterNode
	err := col.FindOne(ctx, bson.M{"_id": nodeId}).Decode(&node)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}
		return nil, err
	}

	return &node, nil
}

var _ cluster.Reaper = (*MongoCoordinator)(nil)

func (c *MongoCoordinator) PurgeStaleNodes(before time.Time) (int, error) {
	col := c.nodeCol.Load()
	if col == nil {
		return 0, errCoordinatorNotInit
	}
	ctx, cancel := c.opCtx()
	defer cancel()
	res, err := col.DeleteMany(ctx, bson.M{"lastSeenAt": bson.M{"$lt": before}})
	if err != nil {
		return 0, err
	}
	return int(res.DeletedCount), nil
}

func (c *MongoCoordinator) PurgeExpiredLeases(before time.Time, keep func(resource string) bool) (int, error) {
	col := c.leaseCol.Load()
	if col == nil {
		return 0, errCoordinatorNotInit
	}
	ctx, cancel := c.opCtx()
	defer cancel()

	expired := bson.M{"leaseUntil": bson.M{"$lt": before}}
	cursor, err := col.Find(ctx, expired, options.Find().SetProjection(bson.M{"_id": 1}))
	if err != nil {
		return 0, err
	}
	var rows []struct {
		Id string `bson:"_id"`
	}
	err = cursor.All(ctx, &rows)
	_ = cursor.Close(ctx)
	if err != nil {
		return 0, err
	}
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		if keep == nil || !keep(row.Id) {
			ids = append(ids, row.Id)
		}
	}
	if len(ids) == 0 {
		return 0, nil
	}
	// Re-check the expiry in the delete so a lease acquired between the scan
	// and the delete survives.
	res, err := col.DeleteMany(ctx, bson.M{"_id": bson.M{"$in": ids}, "leaseUntil": bson.M{"$lt": before}})
	if err != nil {
		return 0, err
	}
	return int(res.DeletedCount), nil
}
