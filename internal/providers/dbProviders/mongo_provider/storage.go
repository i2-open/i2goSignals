package mongo_provider

import (
    "net/url"

    "github.com/i2-open/i2goSignals/internal/providers/storage"
)

// MongoStorage is a narrow lifecycle wrapper exposing only the surface
// described by storage.Storage. It is the value Persistence.Storage holds
// for Mongo-backed servers.
type MongoStorage struct {
    p *MongoProvider
}

// NewMongoStorage wraps a MongoProvider for use behind the storage.Storage
// seam.
func NewMongoStorage(p *MongoProvider) *MongoStorage {
    return &MongoStorage{p: p}
}

// Compile-time check.
var _ storage.Storage = (*MongoStorage)(nil)

func (s *MongoStorage) Name() string                  { return s.p.Name() }
func (s *MongoStorage) Check() error                  { return s.p.Check() }
func (s *MongoStorage) Close() error                  { return s.p.Close() }
func (s *MongoStorage) ResetDb(initialize bool) error { return s.p.ResetDb(initialize) }
func (s *MongoStorage) SetBaseUrl(u *url.URL)         { s.p.SetBaseUrl(u) }
