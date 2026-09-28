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

## Push Delivery Metrics

These metrics surface the push state machine described in `docs/operations.md`. They give operators
visibility into receiver health, recovery activity, and the T3 idle keepalive feature.

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `goSignals_router_push_failures_total` | Counter | `stream_id`, `err_class` | Push delivery failures, labeled by `FailureClass` (`Transport`, `ServerError`, `Unauthorized`, `Forbidden`, `RateLimited`, `RFC8935Error`, `WeirdClientError`, `WeirdResponse`). |
| `goSignals_router_push_state_transitions_total` | Counter | `stream_id`, `from`, `to` | One increment per actual stream state change (`enabled`/`paused`/`disabled`). Mirrors the `PUSH-SRV: state transition` audit log. |
| `goSignals_router_push_recovery_duration_seconds` | Histogram | `stream_id` | Wall-time elapsed inside `recoveryLoop`, from entry to exit. Long-tail buckets up to 6h to surface streams stuck in transport recovery. |
| `goSignals_router_push_idle_verify_total` | Counter | `stream_id`, `outcome` | Verify-event push outcomes (`acked` or `failed`). Dominated in production by T3 idle keepalives; operator-triggered verifies also pass through. |
| `goSignals_router_delivery_inflight` | Gauge | `stream_id`, `transport` | JTIs a delivery runner (`transport` = `push` or `sstp`) has taken for sending and not yet acked or handed back (#336). It is bounded by `I2SIG_DELIVERY_INFLIGHT_MAX`; a stream sitting at the bound is waiting on its ack writes. The series is removed when the runner stops. |
| `goSignals_router_delivery_ack_batch_size` | Histogram | `transport` | JTIs applied per coalesced ack write (#336). A mean well above the push batch size shows coalescing is saving store writes; a mean of one batch shows the window is too short for the send rate, or `I2SIG_ACK_COALESCE_WINDOW=0`. |

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
| `goSignals_dao_op_duration_seconds` | Histogram | `op`, `outcome` | 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5 s | Wall-time of each `EventDAO` call. `op` is the Go method name (`Insert`, `InsertMany`, `FindByJTI`, `FindByJTIs`, `FindByTimeRange`, `AddPending`, `AddPendingMany`, `GetPendingForStream`, `RemovePending`, `RemovePendingMany`, `InsertWithPending`, `ClearPendingForStream`, `MarkDelivered`, `MarkDeliveredMany`, `AckDelivered`, `ListDeliveredForStream`, `RemoveDelivered`, `DeleteBodyIfUnreferenced`, `CountRetainedForStream`, `WatchPending`); `outcome` is `ok` or `error` (the call's returned error — `InsertMany`'s and `InsertWithPending`'s per-record results such as a duplicate JTI do not count as `error`). |
| `goSignals_dao_batch_size` | Histogram | `op` | 1, 2, 5, 10, 25, 50, 100, 250, 500, 1000 | Items passed to each batch-taking call: `InsertMany`, `InsertWithPending` (records), `AddPendingMany`, `FindByJTIs`, `RemovePendingMany` (JTIs), `MarkDeliveredMany` (events), `AckDelivered` (JTIs). Divide an op's latency by its batch size for per-document cost. |

Label cardinality is closed (method names × two outcomes); there is deliberately
no `stream_id`. `WatchPending`'s latency is the watch set-up time on Mongo; on
the memory store it blocks for the watch's lifetime, so ignore it there.

Example — ingest p50 per write, beside the HTTP p50:

```promql
histogram_quantile(0.5, sum by (le, op) (rate(goSignals_dao_op_duration_seconds_bucket{op="InsertWithPending"}[1m])))
histogram_quantile(0.5, sum by (le) (rate(goSignals_http_duration_seconds_bucket[1m])))
```

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
