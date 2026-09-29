# Ring-fed delivery (#342)

`I2SIG_STORE_WAL_RING_FED=true`, with `I2SIG_STORE_WAL=local` (ADR 0045),
lets the delivery runners on the buffering node read an acknowledged SET
from the local WAL before the drain writes it to the store.

## How it works

- The router puts a read-through (`walReadThrough`,
  `internal/eventRouter/wal_read_through.go`) in front of the
  EventService's DAO. It holds every undrained WAL entry in memory: the
  records by JTI and the pending markers by stream.
- At append (and for entries replayed at start-up) the entry is added to
  the overlay and its targets are woken. The drain never wakes them again,
  because a second wake-up could push an already-acked SET twice.
- `GetPendingForStream` merges the overlay with the store in ascending-jti
  order (ADR 0040), removes duplicates, and cuts to the limit.
  `FindByJTI` and `FindByJTIs` serve undrained bodies from the overlay. Each
  hit counts in `goSignals_wal_ring_fed_served_total`. So push, poll
  (RFC 8936) and SSTP runners all see the SET at once.
- An ack or a pending clear for an undrained SET is held in the overlay and
  hides the SET from later reads. The drain writes the SET, then the held
  acks and clears, and only then truncates the entry and drops it from the
  overlay. If that write fails, nothing is truncated and the pass is retried.
- Ingress and egress counters still move at drain, as in ADR 0045.

## Measurement

`TestLocalWal_RingFedDeliveryLatency`
(`internal/eventRouter/local_wal_ring_fed_test.go`) measures the time from
the WAL ack to the first push. A gated store write that takes 300 ms stands
in for a slow drain. It uses the memory store on the macOS dev host.

| Mode | WAL-ack to push |
|------|-----------------|
| drain-fed (`RING_FED` unset) | 305.7 ms |
| ring-fed (`RING_FED=true`)   | 8.9 ms   |

The drain-fed number is the store latency plus the wake-up. The ring-fed
number does not depend on the store. A live measurement against the
3-member Mongo replica set under load is not in this slice. The
`docs/perf/local-wal-340.md` benchmark does not measure delivery, and a
delivery-latency run against Mongo is a follow-up.

To run it:

```bash
go test -run TestLocalWal_RingFedDeliveryLatency -v ./internal/eventRouter/
```

## Known edges

- **At-least-once.** Held acks live in memory. If the node crashes before
  the drain applies them, the SETs are replayed as pending and delivered
  again.
- **Store duplicates.** A SET whose JTI is already in the store is served
  from the overlay once, before the drain finds the duplicate and drops it.
- **Remote push owners.** A push stream whose lease is on another node gets
  its wake-up before the store has the SET, so that owner's backfill may
  find nothing until the drain. This does not happen yet, because `local`
  mode is single-node until #343.
- **`ResetDb`.** The memory adapter's `ResetDb(true)`, which only tests and
  dev use, rebuilds the EventService without the read-through. Build a new
  router after a reset, as the test helpers already do.
- **Stream reset.** Re-queueing by time range (`ResetEventStream`) reads the
  store only, so it does not include SETs that have not been drained yet.
  They are still pending on the stream through the overlay.
