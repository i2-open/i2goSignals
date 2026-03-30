### goSignals Metrics

The `goSignalsServer` exposes a `/metrics` endpoint that provides Prometheus-formatted metrics about the server's operation and event routing.

#### Custom Metrics

| Metric Name | Type | Description | Labels |
|-------------|------|-------------|--------|
| `goSignals_http_duration_seconds` | Histogram | Duration of HTTP requests. | `path` |
| `goSignals_router_events_in_total` | Counter | Total number of events received. | `type`, `iss`, `tfr` |
| `goSignals_router_events_out_total` | Counter | Total number of events delivered. | `type`, `iss`, `tfr` |
| `goSignals_router_stream_pub_polling_cnt` | Gauge | Current number of SET polling publisher streams. | None |
| `goSignals_router_stream_pub_push_cnt` | Gauge | Current number of SET push publisher streams. | None |
| `goSignals_router_stream_rcv_poll_cnt` | Gauge | Current number of SET polling receivers. | None |
| `goSignals_router_stream_rcv_push_cnt` | Gauge | Current number of SET push receivers. | None |

#### Standard Metrics

The endpoint also includes standard Go runtime and process metrics provided by the Prometheus client, such as:
- `go_gc_duration_seconds`
- `go_goroutines`
- `go_memstats_alloc_bytes`
- `process_cpu_seconds_total`
- `process_resident_memory_bytes`

#### Accessing Metrics

You can access the metrics by sending a GET request to the `/metrics` endpoint:

```bash
curl https://keycloak:9080/metrics
```

#### Sample Client

A sample Go client that fetches and prints these metrics is available in `cmd/metrics/main.go`.
