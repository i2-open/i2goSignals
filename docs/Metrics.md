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

## Push Delivery Metrics

These metrics surface the push state machine described in `docs/operations.md`. They give operators
visibility into receiver health, recovery activity, and the T3 idle keepalive feature.

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `goSignals_router_push_failures_total` | Counter | `stream_id`, `err_class` | Push delivery failures, labeled by `FailureClass` (`Transport`, `ServerError`, `Unauthorized`, `Forbidden`, `RateLimited`, `RFC8935Error`, `WeirdClientError`, `WeirdResponse`). |
| `goSignals_router_push_state_transitions_total` | Counter | `stream_id`, `from`, `to` | One increment per actual stream state change (`enabled`/`paused`/`disabled`). Mirrors the `PUSH-SRV: state transition` audit log. |
| `goSignals_router_push_recovery_duration_seconds` | Histogram | `stream_id` | Wall-time elapsed inside `recoveryLoop`, from entry to exit. Long-tail buckets up to 6h to surface streams stuck in transport recovery. |
| `goSignals_router_push_idle_verify_total` | Counter | `stream_id`, `outcome` | Verify-event push outcomes (`acked` or `failed`). Dominated in production by T3 idle keepalives; operator-triggered verifies also pass through. |

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
