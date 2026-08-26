package mongo_provider

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/cluster"
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

// Compile-time check.
var _ cluster.ClusterCoordinator = (*MongoCoordinator)(nil)

func (c *MongoCoordinator) TryAcquireOrRenewLease(resource string, nodeId string, leaseDuration time.Duration) (bool, int64, error) {
	col := c.leaseCol.Load()
	if col == nil {
		return false, 0, errors.New("mongo coordinator not initialized")
	}

	ctx, cancel := c.opCtx()
	defer cancel()

	now := time.Now().UTC()
	leaseUntil := now.Add(leaseDuration)

	filter := bson.M{
		"_id": resource,
		"$or": []bson.M{
			{"leaseUntil": bson.M{"$lte": now}},
			{"ownerNodeId": nodeId},
		},
	}

	update := bson.M{
		"$set": bson.M{
			"ownerNodeId": nodeId,
			"leaseUntil":  leaseUntil,
			"updatedAt":   now,
		},
		"$inc":         bson.M{"fencingToken": 1},
		"$setOnInsert": bson.M{"createdAt": now},
	}

	opts := options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After)

	var lease model.ClusterLease
	err := col.FindOneAndUpdate(ctx, filter, update, opts).Decode(&lease)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return false, 0, nil
		}
		return false, 0, err
	}

	return lease.OwnerNodeId == nodeId, lease.FencingToken, nil
}

func (c *MongoCoordinator) ReleaseLeaseIfOwned(resource string, nodeId string) error {
	col := c.leaseCol.Load()
	if col == nil {
		return errors.New("mongo coordinator not initialized")
	}

	ctx, cancel := c.opCtx()
	defer cancel()

	filter := bson.M{
		"_id":         resource,
		"ownerNodeId": nodeId,
	}
	now := time.Now().UTC()
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
		return "", time.Time{}, 0, errors.New("mongo coordinator not initialized")
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

	return lease.OwnerNodeId, lease.LeaseUntil, lease.FencingToken, nil
}

func (c *MongoCoordinator) RegisterNode(node model.ClusterNode) error {
	col := c.nodeCol.Load()
	if col == nil {
		return errors.New("mongo coordinator not initialized")
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
		return 0, errors.New("mongo coordinator not initialized")
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
		return nil, errors.New("mongo coordinator not initialized")
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
		return nil, errors.New("mongo coordinator not initialized")
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
