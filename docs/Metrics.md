<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../brand/logo/gosignals-hero-primary.svg"><img src="../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# goSignalsServer Metrics

This document describes the Prometheus metrics exposed by `goSignalsServer` at the `/metrics` endpoint.

## Router Metrics

These metrics track the flow of Security Event Tokens (SETs) and the state of event streams.

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `goSignals_router_events_in_total` | Counter | `type`, `iss`, `tfr`, `stream_id` | Total number of events received by the router. |
| `goSignals_router_events_out_total` | Counter | `type`, `iss`, `tfr`, `stream_id` | Total number of events delivered by the router. |
| `goSignals_router_event_age_at_receipt_seconds` | Histogram | `tfr` | Age of each inbound SET when this node counts it: receipt time minus the SET's `toe` claim. SETs without `toe` are not observed. Buckets: exponential, 1 ms to 30 s (31 buckets). |
| `goSignals_router_stream_pub_polling_cnt` | Gauge | None | Number of active SET polling publisher streams. |
| `goSignals_router_stream_pub_push_cnt` | Gauge | None | Number of active SET push publisher streams. |
| `goSignals_router_stream_rcv_poll_cnt` | Gauge | None | Number of active SET polling receiver streams. |
| `goSignals_router_stream_rcv_push_cnt` | Gauge | None | Number of active SET push receiver streams. |
| `goSignals_router_stream_status_info` | Gauge | `stream_id`, `status` | Current status of a stream (1 if status matches). |
| `goSignals_router_stream_error_info` | Gauge | `stream_id`, `error_msg` | Error message for a stream if any (1 if error matches). |
| `goSignals_router_stream_created_at_seconds` | Gauge | `stream_id` | Timestamp when the stream was created (Unix seconds). |
| `goSignals_router_stream_start_date_seconds` | Gauge | `stream_id` | Timestamp when the stream was started (Unix seconds). |
| `goSignals_router_stream_modified_at_seconds` | Gauge | `stream_id` | Timestamp when the stream was last modified (Unix seconds). |

The `tfr` ("transfer method") label on `goSignals_router_events_in_total` and
`goSignals_router_events_out_total` takes one of three values: **`PUSH`** (RFC
8935), **`POLL`** (RFC 8936), or **`SSTP`** (Synchronous SET Transfer Protocol).
For an SSTP pair both directions report `tfr=SSTP`: the inbound counter
(`events_in`) is labelled `stream_id=<rxSid>` and the outbound counter
(`events_out`) `stream_id=<txSid>`, so each direction of a pair is observable
independently. The active-stream gauges above are not split by SSTP — an SSTP
pair is counted via its underlying publisher/receiver activity. See
[docs/SSTP.md](SSTP.md).

`goSignals_router_event_age_at_receipt_seconds` uses the same `tfr` values for
the receiving transfer method. It measures from the transmitter's clock (`toe`)
to this node's clock, so it is only meaningful when the clocks agree. `toe` is
set by the event's issuer, so for ordinary events it records how old the event
was when it arrived, not delivery time alone. `cmd/goSignalsBench` stamps `toe`
just before each POST, which turns it into ingest-to-receiver delivery latency
(see [e2e benchmark — Delivery latency](perf/e2e-benchmark.md#delivery-latency)).
With local-WAL durability, inbound events are counted when the WAL drains, so
the age includes time spent in the WAL.

## Push Delivery Metrics

These metrics surface the push state machine described in `docs/operations.md`. They give operators
visibility into receiver health, recovery activity, and the T3 idle keepalive feature.

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `goSignals_router_push_failures_total` | Counter | `stream_id`, `err_class` | Push delivery failures, labeled by `FailureClass` (`Transport`, `ServerError`, `Unauthorized`, `Forbidden`, `RateLimited`, `RFC8935Error`, `WeirdClientError`, `WeirdResponse`). |
| `goSignals_router_push_state_transitions_total` | Counter | `stream_id`, `from`, `to` | One increment per actual stream state change (`enabled`/`paused`/`disabled`). Mirrors the `PUSH-SRV: state transition` audit log. |
| `goSignals_router_push_recovery_duration_seconds` | Histogram | `stream_id` | Wall-time elapsed inside `recoveryLoop`, from entry to exit. Long-tail buckets up to 6h to surface streams stuck in transport recovery. |
| `goSignals_router_push_idle_verify_total` | Counter | `stream_id`, `outcome` | Verify-event push outcomes (`acked` or `failed`). Dominated in production by T3 idle keepalives; operator-triggered verifies also pass through. |
| `goSignals_router_delivery_inflight` | Gauge | `stream_id`, `transport` | JTIs a delivery runner (`transport` = `push` or `sstp`) has taken for sending and not yet acked or handed back (#336). It is bounded by `I2SIG_DELIVERY_INFLIGHT_MAX`; a stream sitting at the bound is waiting on its ack writes. With pipelining (#339, ADR 0044) this spans up to K push batches or `I2SIG_SSTP_PUSH_INFLIGHT` SSTP second pushes at once. The series is removed when the runner stops. |
| `goSignals_router_delivery_ack_batch_size` | Histogram | `transport` | JTIs applied per coalesced ack write (#336). A mean well above the push batch size shows coalescing is saving store writes; a mean of one batch shows the window is too short for the send rate, or `I2SIG_ACK_COALESCE_WINDOW=0`. |
| `goSignals_router_poll_claimed_inflight` | Gauge | `stream_id` | SETs of an RFC 8936 poll stream claimed by a poll response on this node and not yet acked, released or expired (#337). Set after each poll; a value near the stream's pending count means pollers are not acking and will see redelivery once `I2SIG_POLL_CLAIM_TTL` passes. Always 0 when `I2SIG_POLL_CLAIM_TTL=0`. The series is removed when the stream is removed. |
| `goSignals_router_poll_receiver_outstanding` | Gauge | `stream_id` | Polls a poll receiver stream on this node has sent to its upstream transmitter and not yet finished processing (#338). Bounded by `I2SIG_POLL_PIPELINE_DEPTH`. A stream sitting at the bound is limited by the transmitter's response time or by its own store writes. An idle long-poll stream shows 1, or more after it sends acks, until those polls return. The series is removed when the receiver stops. |

## Event Validation Metrics

Inbound SET payload validation, controlled per receiver stream by `event_validation`
(see `docs/configuration_properties.md` for the `I2SIG_STREAM_EVENT_VALIDATION`
server default). The counter is the only machine-readable signal a `WARN` rollout
produces, since `WARN` leaves the wire response unchanged — watch
`disposition="malformed"` on `WARN` to size the impact before moving a stream to
`ENFORCE`.

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `goSignals_router_event_validation_total` | Counter | `disposition`, `mode`, `transport` | Whole-SET event-validation dispositions (`valid`, `unsupported`, `malformed`) by resolved `event_validation` mode (`WARN`, `ENFORCE`, `STRICT`) and receive transport (`push`, `poll`, `sstp` — one label for both SSTP paths, acceptor and dialer inbound half). |

Deliberately **not** labeled by `stream_id` or event URI: either would make the
series count unbounded on a busy receiver. A stream on `NONE` engages no
validators and therefore records nothing, so there is no `mode="NONE"` series.

## Delivery Wait and Backlog Metrics

Transmitter-side waiting, per target stream (#352; vocabulary in `CONTEXT.md`,
"Enqueue time / Queue time / Acknowledgement time / Backlog"). Both histograms
and both gauges are read from the node's in-memory `DeliveryQueue`: no store or
coordinator call is made to record or scrape them.

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `goSignals_router_queue_time_seconds` | Histogram | `tfr` | Enqueue time to the SET's *first* hand-out on this node: push request sent, poll response written, SSTP frame sent (either role). Observed once per SET, when it is acknowledged. Buckets: exponential, 5 ms to 60 s (15 buckets). |
| `goSignals_router_ack_time_seconds` | Histogram | `tfr` | First hand-out to acknowledgement. Retries and redeliveries fall inside it. Same buckets. |
| `goSignals_router_stream_backlog_depth` | Gauge | `stream_id` | SETs enqueued for the stream and not yet acknowledged, handed out or not. |
| `goSignals_router_stream_backlog_oldest_age_seconds` | Gauge | `stream_id` | Age at scrape time of the oldest SET in the stream's backlog; 0 when the backlog is empty. |

`tfr` takes the same values as on `goSignals_router_events_out_total`: `PUSH`,
`POLL` (RFC 8936 poll transmitter) and `SSTP` (both the acceptor and the dialer
role of a pair). Per ADR 0047 the histograms carry no `stream_id`; per-stream
health comes from the two gauges.

What is not observed:

- A subject-filtered SET is discarded without being sent: it leaves the backlog
  but is observed in neither histogram.
- A SET handed out by a previous owner of the stream has no hand-out time on the
  new owner, so its acknowledgement there is not observed (owner failover).
- A SET is timed only while this node holds its reference in the delivery queue;
  a SET handed out from beyond the queue window is not observed.

Each stream's gauges are reported only by the node that owns its lease. A node
holding a queue for a stream it does not own reports nothing for it, and a
removed stream's series stop on the next scrape. Summing across nodes therefore
counts each stream once, and a stream with no series anywhere has no owner.

Examples:

```promql
# p95 queue time and ack time by transfer method
histogram_quantile(0.95, sum by (le, tfr) (rate(goSignals_router_queue_time_seconds_bucket[5m])))
histogram_quantile(0.95, sum by (le, tfr) (rate(goSignals_router_ack_time_seconds_bucket[5m])))

# Largest backlogs across the cluster
topk(10, max by (stream_id) (goSignals_router_stream_backlog_depth))
```

Alert on the oldest pending SET:

```yaml
- alert: StreamBacklogStale
  expr: max by (stream_id) (goSignals_router_stream_backlog_oldest_age_seconds) > 300
  for: 5m
  annotations:
    summary: "Stream {{ $labels.stream_id }} has a SET pending for over 5 minutes"
```

Alert on a stream's backlog series going absent (no node owns it, or its owner
stopped reporting). `absent()` takes a fixed selector, so the rule names the
stream; for many streams, compare against a series every node exports per
stream, such as `goSignals_router_stream_status_info`. A stream's backlog series
appears once its owner has built its delivery queue, and a receiver-only stream
has none, so scope the second rule to the transmitter streams you deliver to:

```yaml
- alert: StreamBacklogAbsent
  expr: absent(goSignals_router_stream_backlog_depth{stream_id="<stream id>"})
  for: 5m

- alert: StreamBacklogUnreported
  expr: |
    count by (stream_id) (goSignals_router_stream_status_info{status="enabled"})
      unless on (stream_id) count by (stream_id) (goSignals_router_stream_backlog_depth)
  for: 5m
```

## DAO Metrics

Per-call latency and batch size at the `EventDAO` seam, so the ingest write
path (`InsertWithPending`: the event bodies and their pending markers in one
majority-acked, journaled write before the 202 — one multi-namespace
`bulkWrite` on MongoDB 8.0+, ADR 0043; ADR 0038 contract) can be read apart from the HTTP time
in `goSignals_http_duration_seconds`. Both persistence providers (Mongo and
memory) wrap their live `EventDAO` in the `internal/dao/daometrics` decorator,
so every call the router and retention engine make is observed.

| Metric Name | Type | Labels | Buckets | Description |
|-------------|------|--------|---------|-------------|
| `goSignals_dao_op_duration_seconds` | Histogram | `op`, `outcome` | 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5 s | Wall-time of each `EventDAO` call. `op` is the Go method name (`Insert`, `InsertMany`, `FindByJTI`, `FindByJTIs`, `FindByTimeRange`, `AddPending`, `AddPendingMany`, `EnsurePending`, `GetPendingForStream`, `GetPendingForStreamBeyond`, `RemovePendingMany`, `InsertWithPending`, `ClearPendingForStream`, `Ack`, `ResetPendingAckJti`, `ListDeliveredForStream`, `RemoveDelivered`, `DeleteBodyIfUnreferenced`, `CountRetainedForStream`, `SweepExpired`, `MigrateLegacyDeliveries`, `WatchPending`); `GetPendingForStreamBeyond` is a `GetPendingForStream` call whose page held fewer rows than the stream's pending total (`Total > len(Refs)`), so the store also read `PendingPage.OldestBeyond`; the difference of the two labels' means is that query's cost (#366). `outcome` is `ok` or `error` (the call's returned error — `InsertMany`'s and `InsertWithPending`'s per-record results such as a duplicate JTI do not count as `error`). |
| `goSignals_dao_batch_size` | Histogram | `op` | 1, 2, 5, 10, 25, 50, 100, 250, 500, 1000 | Items passed to each batch-taking call: `InsertMany`, `InsertWithPending` (records), `AddPendingMany` (references), `FindByJTIs`, `RemovePendingMany` (JTIs), `Ack` (acknowledgement JTIs). Divide an op's latency by its batch size for per-document cost. |

Label cardinality is closed (method names × two outcomes); there is deliberately
no `stream_id`. `WatchPending`'s latency is the watch set-up time on Mongo; on
the memory store it blocks for the watch's lifetime, so ignore it there.

Example — ingest p50 per write, beside the HTTP p50:

```promql
histogram_quantile(0.5, sum by (le, op) (rate(goSignals_dao_op_duration_seconds_bucket{op="InsertWithPending"}[1m])))
histogram_quantile(0.5, sum by (le) (rate(goSignals_http_duration_seconds_bucket[1m])))
```

## Local WAL Metrics

These metrics cover the node-local ingest WAL used when `I2SIG_STORE_WAL=local` (ADR 0045, #341). They stay at zero in the default `majority` mode.

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `goSignals_wal_depth` | Gauge | None | Entries (acknowledged inbound batches) in the local WAL not yet drained to the store. |
| `goSignals_wal_drain_lag_seconds` | Gauge | None | Age of the oldest undrained entry, refreshed on every drain attempt. 0 when the WAL is empty. |
| `goSignals_wal_drained_total` | Counter | None | SETs drained from the WAL to the store. A JTI the store already held counts as drained. |
| `goSignals_wal_replayed_total` | Counter | None | SETs found in the WAL at start-up (left by a crash, or by a shutdown drain that timed out) and replayed to the store before ingest reopened. |
| `goSignals_wal_drain_duration_seconds` | Histogram | None | Duration of one drain batch: the store write plus the WAL truncate. |
| `goSignals_wal_append_seconds` | Histogram | None | One WAL append as ingest sees it: the wait behind the current group commit plus the write and fsync (ADR 0046). With `goSignals_wal_drain_duration_seconds` it separates a slow disk from a slow drain. |
| `goSignals_wal_ring_fed_served_total` | Counter | None | SET bodies served to delivery from the local WAL before the drain stored them (`I2SIG_STORE_WAL_RING_FED=true`, #342). Stays at 0 with ring-feeding off. |
| `goSignals_wal_local_ingest_suspended` | Gauge | None | 1 once this local-mode node found another active cluster node without ring-fed delivery and suspended local ingest (#343): `durability=local` streams run at majority until the node restarts. Alert on it; the fix is `I2SIG_STORE_WAL_RING_FED=true` on every node or a return to `majority`. |

Alerting guidance: a depth that keeps growing, or a drain lag above a few seconds that does not fall, means the store is not keeping up or is unreachable. Acknowledged SETs are then single-node durable only, and are lost if this node's disk is lost. A non-zero `rate(goSignals_wal_replayed_total[5m])` after a restart means the previous run stopped with undrained entries.

## HTTP Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `goSignals_http_duration_seconds` | Histogram | `path` | Duration of HTTP requests in seconds. |

## Cluster Metrics

These metrics provide observability into the clustering and lease management.

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `goSignals_cluster_leases_held_total` | Gauge | None | Number of time-bounded leases currently held by this node. |
| `goSignals_cluster_lease_acquisition_total` | Counter | `resource`, `status` | Total number of lease acquisition and renewal attempts. `status` is either `success` or `failure`. |
| `goSignals_cluster_nodes_count` | Gauge | None | Number of active nodes in the cluster (nodes that have heartbeated within the last 60 seconds). |

---

<!-- gosignals-brand-footer -->
<p align="center"><sub>(C)2026 Independent Identity Inc.</sub></p>
