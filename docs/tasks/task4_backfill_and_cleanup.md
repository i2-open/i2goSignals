### Task 4: Router Refactoring - Backfill & Watch Deprecation

#### Objective
Implement periodic backfill and immediate fetch on wake-up for transmitters. Deprecate MongoDB change stream (watch).

#### Requirements
1.  Implement `wakeupCh` for `PushStreamHandler` to signal immediate backfill.
2.  Add a periodic ticker to `PushStreamHandler` for backfill.
    - Interval from `TRANSMITTER_BACKFILL_INTERVAL` (default 1s).
    - Fetches events using `provider.GetEventIds`.
    - Batch size from `TRANSMITTER_BACKFILL_BATCH` (default 100).
3.  Implement backfill for `PollStreamHandler`.
    - Prefetch on demand before reading buffer.
4.  Deprecate `WatchPending`:
    - Only start if `MONGO_WATCH_ENABLED=true`.
    - Default to `false`.
5.  Add unit tests for backfill and wake-up signalling.

#### Definition of Done
- Periodic backfill working for push streams.
- Wake-up signal triggers immediate fetch.
- Poll prefetching working.
- Watch is disabled by default.
