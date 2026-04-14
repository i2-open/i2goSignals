### Task 1: Infrastructure & Provider Updates

#### Objective
Add necessary methods to `DbProviderInterface` and implement them in `MongoProvider`. Define new environment variables for cluster communication and transmitter backfill.

#### Requirements
1.  Update `DbProviderInterface` in `internal/providers/dbProviders/provider_interface.go`:
    - Add `GetLeaseOwner(resource string) (ownerNodeId string, leaseUntil time.Time, fencingToken int64, err error)`
    - Add `GetNode(nodeId string) (*model.ClusterNode, error)`
2.  Implement these methods in `internal/providers/dbProviders/mongo_provider/provider.go`.
3.  Define new environment variables in `internal/providers/dbProviders/mongo_provider/constants.go` (or wherever constants are kept):
    - `CLUSTER_INTERNAL_TOKEN`: HMAC secret for internal calls.
    - `CLUSTER_INTERNAL_PORT`: Port for the internal wake-up API (defaults to main port).
    - `TRANSMITTER_BACKFILL_INTERVAL`: Interval for periodic backfill (default `1s`).
    - `TRANSMITTER_BACKFILL_BATCH`: Max events to fetch in one backfill (default `100`).
    - `MONGO_WATCH_ENABLED`: Boolean to toggle change stream (default `false`).
4.  Add unit tests for the new provider methods in `internal/providers/dbProviders/mongo_provider/provider_test.go`.

#### Definition of Done
- `DbProviderInterface` updated.
- `MongoProvider` implements the new methods.
- New constants defined.
- Unit tests pass.
