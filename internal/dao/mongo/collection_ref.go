package mongo

import (
    "sync/atomic"

    "go.mongodb.org/mongo-driver/v2/mongo"
)

// collectionRef wraps an atomic *mongo.Collection so DAOs can be rebound
// across reconnects without an external mutex. The zero value is a valid
// "not yet bound" state — load() returns nil and DAO methods can fall back
// to the standard "mongo collection not initialized" error path.
//
// This pattern is the reason MongoProvider no longer needs the
// BaseProvider-swap dance for collection rebinds: on reconnect, we call
// set() on each DAO's ref instead of constructing a new DAO.
type collectionRef struct {
    p atomic.Pointer[mongo.Collection]
}

// set rebinds the underlying collection. Safe to call concurrently with
// load(); in-flight callers see either the old or the new collection.
func (r *collectionRef) set(c *mongo.Collection) {
    r.p.Store(c)
}

// load returns the current collection, or nil if not yet bound.
func (r *collectionRef) load() *mongo.Collection {
    return r.p.Load()
}
