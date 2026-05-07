// Package storage defines the lifecycle seam used by the goSignals server
// to manage the underlying persistence handle (Mongo or memory): liveness
// checks, base-URL plumbing, reset, and orderly shutdown.
//
// The seam is intentionally narrow — only the methods that the server
// lifecycle actually needs. Service-level operations live behind the
// service types and the persistence DAOs, not behind this interface.
package storage

import "net/url"

// Storage describes the lifecycle surface every persistence adapter must
// expose. Implementations live alongside the persistence adapters that own
// them (mongo_provider.MongoStorage, memory_provider.MemoryStorage).
type Storage interface {
    // Name returns the human-readable database name (used in startup logs
    // and metrics labels).
    Name() string

    // Check verifies the persistence backend is reachable. Returns nil when
    // healthy, an error otherwise.
    Check() error

    // Close releases resources held by the backend. Safe to call multiple
    // times; subsequent calls are no-ops.
    Close() error

    // ResetDb wipes all persisted state. When initialize is true, the
    // backend re-initialises (recreates collections/services) so callers
    // can continue using it without reopening.
    ResetDb(initialize bool) error

    // SetBaseUrl records the server's externally-visible base URL so the
    // backend can include it in token issuer/audience claims.
    SetBaseUrl(u *url.URL)
}
