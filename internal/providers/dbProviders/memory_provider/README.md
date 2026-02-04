# Memory Database Provider

## Overview

The `memory_provider` is an in-memory implementation of the `DbProviderInterface` that simulates MongoDB behavior without requiring an actual MongoDB instance. This is useful for testing and development scenarios where you want to avoid external dependencies.

## Features

- **In-Memory Storage**: All data (streams, events, keys, clients) is stored in memory using Go maps
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

1. **No Persistence**: Data is lost when the provider is closed or the process ends
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
- `I2SIG_DBNAME`: Database name (default: "ssef")
- `I2SIG_TOKEN_ISSUER`: Token issuer name (default: "DEFAULT")

In addition, the `OpenProvider` factory function respects:
- `MONGO_URL`: If not set, memory provider is automatically selected.
- `MONGO_FAILTOMEM`: If set to `FALSE`, the server will exit on connection failure instead of falling back to memory provider.

## Limitations

- No persistent storage across restarts
- No MongoDB-specific features (aggregation, change streams, etc.)
- Events are stored with the full SecurityEventToken object, not as raw JSON
- No transaction support
- No query optimization or indexing

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
