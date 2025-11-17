# Mock MongoDB Provider

## Overview

The `mock_mongo_provider` is an in-memory implementation of the `DbProviderInterface` that simulates MongoDB behavior without requiring an actual MongoDB instance. This is useful for testing and development scenarios where you want to avoid external dependencies.

## Features

- **In-Memory Storage**: All data (streams, events, keys, clients) is stored in memory using Go maps
- **Thread-Safe**: Uses `sync.RWMutex` to ensure concurrent access safety
- **Full Interface Implementation**: Implements all methods from `DbProviderInterface`
- **No External Dependencies**: No MongoDB server required
- **Fast Setup**: Instant initialization without database connection overhead

## Usage

### Triggering the Mock Provider

The mock provider is automatically triggered when the database URL starts with `mockdb:`. You can use it in two ways:

#### 1. Using the Factory Function (Recommended)

```go
import "github.com/i2-open/i2goSignals/internal/providers/dbProviders"

// This will automatically detect and use the mock provider
provider, err := dbProviders.OpenProvider("mockdb://localhost:27017/", "test_db")
if err != nil {
    log.Fatal(err)
}
defer provider.Close()
```

#### 2. Direct Usage

```go
import "github.com/i2-open/i2goSignals/internal/providers/dbProviders/mock_mongo_provider"

mockProvider, err := mock_mongo_provider.Open("mockdb://localhost:27017/", "test_db")
if err != nil {
    log.Fatal(err)
}
defer mockProvider.Close()
```

### Testing Example

```go
func TestWithMockProvider(t *testing.T) {
    // Use mock provider for testing
    provider, err := dbProviders.OpenProvider("mockdb:", "test_db")
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

The mock provider stores all data in memory using the following structure:

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

### Thread Safety

All public methods use read/write locks to ensure thread-safe access:
- Read operations use `RLock()`/`RUnlock()`
- Write operations use `Lock()`/`Unlock()`

## Configuration

The mock provider respects the same environment variables as the MongoDB provider:

- `I2SIG_ISSUER`: Default issuer name (default: "DEFAULT")
- `I2SIG_DBNAME`: Database name (default: "ssef")
- `I2SIG_TOKEN_ISSUER`: Token issuer name (default: "DEFAULT")

## Limitations

- No persistent storage across restarts
- No MongoDB-specific features (aggregation, change streams, etc.)
- Events are stored with the full SecurityEventToken object, not as raw JSON
- No transaction support
- No query optimization or indexing

## When to Use

**Use the mock provider when:**
- Writing unit tests
- Running integration tests without external dependencies
- Developing features without a MongoDB instance
- Creating quick prototypes or demos

**Use the real MongoDB provider when:**
- Running in production
- Need data persistence
- Using MongoDB-specific features
- Performance testing with realistic data sizes
