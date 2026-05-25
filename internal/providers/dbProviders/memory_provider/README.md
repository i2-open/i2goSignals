<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../../../brand/logo/gosignals-hero-primary.svg"><img src="../../../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# Memory Database Provider

## Overview

The `memory_provider` is an in-memory implementation of the `DbProviderInterface` that simulates MongoDB behavior without requiring an actual MongoDB instance. This is useful for testing and development scenarios where you want to avoid external dependencies.

## Features

- **In-Memory Storage**: Data (streams, events, keys, clients) is primarily stored in memory using Go maps
- **Persistence Support**: Periodically saves state to disk and reloads on startup
- **Memory Protection**: Offloads large event data to disk to minimize memory footprint
- **Thread-Safe**: Uses `sync.RWMutex` to ensure concurrent access safety
- **Full Interface Implementation**: Implements all methods from `DbProviderInterface`
- **No External Dependencies**: No MongoDB server required
- **Fast Setup**: Instant initialization without database connection overhead

## Usage

### Triggering the Memory Provider

The memory provider is automatically triggered when the database URL is empty or starts with `memorydb:`. You can use it in two ways:

#### 1. Using the Factory Function (Recommended)

```go
import "github.com/i2-open/i2goSignals/internal/providers/dbProviders"

// This will automatically detect and use the memory provider
provider, err := dbProviders.OpenProvider("memorydb://localhost", "test_db")
if err != nil {
    log.Fatal(err)
}
defer provider.Close()
```

#### 2. Direct Usage

```go
import "github.com/i2-open/i2goSignals/internal/providers/dbProviders/memory_provider"

memoryProvider, err := memory_provider.Open("memorydb:", "test_db")
if err != nil {
    log.Fatal(err)
}
defer memoryProvider.Close()
```

### Testing Example

```go
func TestWithMemoryProvider(t *testing.T) {
    // Use memory provider for testing
    provider, err := dbProviders.OpenProvider("memorydb:", "test_db")
    if err != nil {
        t.Fatal(err)
    }
    defer provider.Close()
    
    // Reset database for clean test state
    provider.ResetDb(true)
    
    // Use provider as normal
    streams := provider.ListStreams()
    // ... rest of your test
}
```

## Implementation Details

### Data Storage

The memory provider stores all data in memory using the following structure:

- `streams`: `map[string]*model.StreamStateRecord` - Stream configurations and states
- `keys`: `map[string]*JwkKeyRec` - Cryptographic keys for authentication
- `events`: `map[string]*model.EventRecord` - Security events
- `pendingEvents`: `map[string][]DeliverableEvent` - Events pending delivery per stream
- `deliveredEvents`: `map[string][]DeliveredEvent` - Acknowledged events per stream
- `clients`: `map[string]*model.SsfClient` - Registered clients

### Differences from MongoDB Provider

1. **Local Persistence**: Data is persisted to local files instead of a MongoDB cluster
2. **No Change Streams**: MongoDB change stream features are not available
3. **Simplified Queries**: All lookups are direct map operations
4. **No Indexes**: All data access is O(1) or O(n) without optimization
5. **Single Node**: The memory provider runs as a single node only. Clustering features are simulated.

### Thread Safety

All public methods use read/write locks to ensure thread-safe access:
- Read operations use `RLock()`/`RUnlock()`
- Write operations use `Lock()`/`Unlock()`

## Configuration

The memory provider respects the same environment variables as the MongoDB provider:

- `I2SIG_ISSUER`: Default issuer name (default: "DEFAULT")
- `I2SIG_DBNAME`: Database name (default: "goSignalsMem")
- `I2SIG_TOKEN_ISSUER`: Token issuer name (default: "DEFAULT")

### Memory Provider Specific Variables

- `MEM_DIRECTORY`: Directory to store persistent state (default: `config/{dbName}`)
- `MEM_SAVE_RATE`: The interval in seconds between periodic saves. A setting of 0 means every change. (default: 30)

In addition, the `OpenProvider` factory function respects:
- `MONGO_URL`: If not set, memory provider is automatically selected.
- `MONGO_FAILTOMEM`: If set to `FALSE`, the server will exit on connection failure instead of falling back to memory provider.

## Limitations

- No MongoDB-specific features (aggregation, change streams, etc.)
- Events are stored with the full SecurityEventToken object, not as raw JSON
- No transaction support
- No query optimization or indexing

## Persistence and Memory Protection

The memory provider can be configured to periodically save its state to disk. When enabled:
- All state (streams, keys, clients, pending/delivered events) is saved to JSON files in the configured `MEM_DIRECTORY`.
- Individual Security Event Tokens (SETs) are saved as `{jti}.set` files in an `events` sub-directory.
- To protect memory usage, the raw SET data is offloaded to disk after being saved, keeping only the necessary metadata in memory for filtering and routing. The full SET is reloaded from disk only when requested.

## When to Use

**Use the memory provider when:**
- Writing unit tests
- Running integration tests without external dependencies
- Developing features without a MongoDB instance
- Creating quick prototypes or demos

**Use the real MongoDB provider when:**
- Running in production
- Need data persistence
- Using MongoDB-specific features
- Performance testing with realistic data sizes
- Multi-node clustering is required

---

<!-- gosignals-brand-footer -->
<p align="center"><sub>(C)2026 Independent Identity Inc.</sub></p>
