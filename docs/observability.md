# goSignals Observability

> **Audience:** operators, SREs, and developers running goSignals in any
> environment — from a laptop to a multi-cloud production deployment. This
> doc starts with the basics and works up to cloud-specific reference
> setups, so you can read just the first few sections to get a working
> mental model, or skip to the section matching your cloud.

## What is "observability"?

**Observability** is the practice of making a running system understandable
from the *outside* — without attaching a debugger, SSH'ing into a box, or
reading source code. A system is "observable" when you can answer
questions like:

- *Is it healthy right now?*
- *What did it do five minutes ago when that customer's request failed?*
- *Which of the ten replicas is misbehaving, and why?*

There are three classic data sources that feed observability:

| Source       | What it tells you                                       | Example in goSignals                 |
|--------------|---------------------------------------------------------|--------------------------------------|
| **Logs**     | A timestamped diary of what happened.                   | "Pushed event JTI=abc to stream X."  |
| **Metrics**  | Numerical aggregates (counters, gauges, histograms).    | `goSignals_router_events_in_total`.  |
| **Traces**   | The path a single request took across components.       | (not yet emitted by goSignals)       |

This document is about the **logs** side. The metrics side is documented
separately in [Metrics.md](Metrics.md); the two are complementary —
metrics tell you *something is wrong*; logs tell you *what specifically
went wrong*.

## How log shipping works (the 30-second version)

goSignals does **not** know or care where its logs end up. It just writes
them — one record per line, as JSON when `LOG_FORMAT=json` is set — to
**stdout** (the process's standard output stream).

A separate program, called a **log collector** (or "agent" or "shipper"),
runs alongside the goSignals container, reads those stdout lines, and
forwards them to a **log backend** (a database designed to ingest, store,
and query log data at scale).

```
   ┌───────────────────┐   stdout   ┌─────────────┐   network   ┌────────────┐
   │ goSignalsServer   │ ─────────▶ │  collector  │ ──────────▶ │  backend   │
   │ (writes JSON)     │            │  (Alloy /   │             │  (Loki /   │
   │                   │            │ Fluent Bit) │             │ CloudWatch)│
   └───────────────────┘            └─────────────┘             └────────────┘
                                                                       │
                                                                       ▼
                                                                ┌────────────┐
                                                                │ Operator   │
                                                                │ (Grafana,  │
                                                                │ CloudWatch │
                                                                │  Insights) │
                                                                └────────────┘
```

This separation — known as the "12-factor logs" pattern — is why the same
goSignals binary works unchanged in every cloud. You swap the collector
and the backend; goSignals stays oblivious.

### Why "structured JSON" matters

A traditional log line looks like:

```
2026-05-14 14:23:01 INFO router pushed event abc to stream xyz, status=200
```

A human reads it easily, but a machine has to parse the prose. Subtle
differences in wording (`pushed event abc` vs `event abc pushed`) defeat
search and indexing.

A structured JSON line for the same event:

```json
{"time":"2026-05-14T14:23:01Z","level":"INFO","service":"gosignals","component":"ROUTER","msg":"pushed event","jti":"abc","stream_id":"xyz","status":200}
```

Every collector and backend can extract `level`, `component`, `jti`,
`stream_id`, `status` directly without guessing. That is what enables the
fast filtering and dashboards described later in this document.

## What the dev compose ships out of the box

`docker-compose-dev.yml` brings up a complete working example of the
shipping pipeline so you can poke at it before committing to a cloud
choice:

| Container     | Role                       | URL                                |
|---------------|----------------------------|------------------------------------|
| `gosignals1`  | goSignals server (node 1)  | http://localhost:8888              |
| `gosignals2`  | goSignals server (node 2)  | http://localhost:8889              |
| `gossfserver` | Demo SSF receiver          | http://localhost:8881              |
| `alloy`       | Log collector              | http://localhost:3200 (UI)         |
| `loki`        | Log backend                | http://localhost:3100              |
| `grafana`     | Query/visualization UI     | http://localhost:3000 (admin/grafana) |
| `prometheus`  | Metrics backend            | http://localhost:9090              |

Run `make dev-up`, wait ~30 seconds, then:

1. Open Grafana at <http://localhost:3000> (log in as `admin` / `grafana`).
2. Click **Explore** in the left rail.
3. Select **Loki** from the datasource picker at the top.
4. Paste `{service="gosignals"}` into the query box and run it.

You should see live log lines streaming in from both goSignals nodes,
with the JSON fields shown as searchable attributes on the right.

A scripted smoke test for the same pipeline is available at
`scripts/verify-observability.sh` — run it after `make dev-up` and it
checks every link in the chain in under a minute.

## How to use the rest of this document

- **Sections 1–2** define the contract: what fields goSignals emits, and
  which of them become Loki labels vs. searchable line fields.
- **Sections 3–6** are recipe cards for each major cloud. Read the one
  that matches your environment; skip the others.
- **Section 7** covers production hardening for the self-hosted path.
- **Section 8** is a cheat-sheet of LogQL queries you can paste into
  Grafana.
- **Section 9** is forward-looking — what Operational SETs will add in v2.

Related reading:
- [Configuration Properties](configuration_properties.md) — `LOG_LEVEL`,
  `LOG_FORMAT`, `I2SIG_CLUSTER_NAME`.
- [Metrics & Monitoring](Metrics.md) — Prometheus side of the observability
  story.
- [Clustering & High Availability](Cluster.md) — what `node_id` and the
  cluster lease model actually mean.
- [Security Model](security_model.md) — auth contexts referenced by some
  forwarder examples (SPIFFE, OAuth).

---

## 1. The stdout-JSON contract

This section is the "what does goSignals actually write to stdout?"
reference. If you are wiring up a collector for the first time, you need
to know two things: the *shape* of each log line, and which fields are
guaranteed to be there.

When the environment variable `LOG_FORMAT=json` is set, every record
written by `internal/logger` (which means every package that uses
`logger.Sub(...)`) is emitted as a single line of JSON on stdout. One
self-contained JSON object per line, separated by newlines — a format
that every mainstream log collector understands natively.

When `LOG_FORMAT` is unset (or set to `text`), goSignals writes
human-readable `key=value` lines instead. That mode is useful for `go
run` / `go test` during development; **always set `LOG_FORMAT=json` in
container deployments** so the collector can parse what it sees.

### Always-present fields

| Field          | Type   | Source                                          | Notes                                                |
|----------------|--------|-------------------------------------------------|------------------------------------------------------|
| `time`         | string | slog default                                    | RFC 3339 nanosecond timestamp.                       |
| `level`        | string | slog default                                    | `DEBUG` / `INFO` / `WARN` / `ERROR`.                 |
| `msg`          | string | slog default                                    | Human-readable message; do not parse it.             |
| `service`      | string | `logger.DefaultAttrs` set by `main.go`          | `"gosignals"` or `"gossfserver"`.                    |
| `version`      | string | `constants.GoSignalsVersion`                    | Build-time version.                                  |
| `node_id`      | string | `I2SIG_CLUSTER_NODE_ID` → `POD_NAME` → `hostname-timestamp` | Same identity used by the cluster lease model. |
| `component`    | string | `logger.Sub("ROUTER")` etc.                     | Sub-system name attached by the producer.            |

### Conditionally-present fields

| Field          | Condition                                       | Notes                                                |
|----------------|-------------------------------------------------|------------------------------------------------------|
| `cluster_name` | `I2SIG_CLUSTER_NAME` is non-empty               | Free-form operator label. Omitted when empty.        |

### Per-call fields

Anything passed as a key/value pair to a `slog` call (`log.Info("event",
"stream_id", sid)`) appears as a top-level JSON field. The full list grows
organically as code adds context; common ones include `stream_id`, `jti`,
`audience`, `issuer`, `error`, `remote_addr`.

### Stability guarantees

- The eight always-present fields will not be renamed within a major
  version. New fields may be added.
- The conditional `cluster_name` field is stable; its inclusion is governed
  only by `I2SIG_CLUSTER_NAME` being non-empty.
- Per-call field names are *conventions*, not contract. Treat them as
  best-effort. The same logical concept (e.g. a stream identifier) will
  use the same key (`stream_id`) across the codebase, but the set of keys
  emitted on any given line is not part of any compatibility promise.

### Reserved namespace: `op_event_*`

The `op_event_*` prefix is reserved for a planned future feature where
goSignals emits its own Operational Security Event Tokens to a dedicated
SSF stream (in addition to logs). **No fields in this namespace are emitted
in v1**; the prefix exists only so that operators and ingest pipelines
can pre-allocate label / parse rules.

See §9 below for the v2 sketch.

---

## 2. Label schema and cardinality rationale

### The short version

Log backends like Loki sort logs into "buckets" using **labels** so they
can find logs fast. A label is something like `service=gosignals` or
`level=ERROR`. The backend builds an index on every distinct combination
of labels, so the more *unique values* a label can have, the bigger the
index — and the slower the system gets.

Rule of thumb:

- **A few possible values** (e.g. four log levels) → safe to use as a
  label.
- **Thousands or millions of possible values** (e.g. stream IDs, event
  IDs) → leave it inside the log line as searchable text.

### The technical version

A *label* in Loki (and in most log backends with an indexed metadata side)
is a high-leverage, low-cardinality dimension that the storage indexes for
fast query slicing. "Cardinality" is the number of distinct values a label
can take. A label whose cardinality explodes (millions of distinct values)
destroys query performance and inflates storage cost. The cure is
discipline at the collector: only a small, fixed set of JSON fields ever
become labels; everything else stays in the log line and is queried at
read time with `| json` (LogQL) or equivalent.

### Promote to labels (low cardinality)

| Label          | Bounded by                                  | Typical cardinality |
|----------------|---------------------------------------------|---------------------|
| `service`      | Binary count                                | < 5                 |
| `node_id`      | Pod / replica count                         | tens                |
| `cluster_name` | Operator-defined cluster name               | < 10                |
| `component`    | `logger.Sub("...")` call sites              | tens                |
| `level`        | `DEBUG` / `INFO` / `WARN` / `ERROR`         | 4                   |
| `version`      | Release count over retention window         | tens                |

That is exactly six labels. The dev compose's
[`config/monitor/alloy/config.alloy`](../config/monitor/alloy/config.alloy)
extracts and promotes precisely these and no others.

### Keep in the log line (high cardinality)

| Field         | Cardinality                                        |
|---------------|----------------------------------------------------|
| `stream_id`   | Unbounded; grows linearly with stream count.       |
| `jti`         | One per event; explodes immediately.               |
| `audience`    | One per receiver; can be very high in a hub.       |
| `issuer`      | One per transmitter; can be very high in a hub.    |
| `remote_addr` | One per client IP; effectively unbounded.          |
| `trace_id`    | One per request; effectively unbounded.            |
| `error`       | Free-form strings; impossible to bound.            |

These are *first-class queryable* — they just queryable through the line
parser, not the label index. See §8 for LogQL examples.

> **Resist the temptation** to promote `stream_id` or `jti` to labels.
> A single high-traffic stream + retention will produce millions of label
> values and degrade the whole Loki tenant.

---

## 3. Self-hosted / on-prem reference: Alloy → Loki

This is the configuration the dev compose uses. It is the simplest viable
production deployment: one Loki, one Alloy per host (or one Alloy DaemonSet
per Kubernetes node), Grafana for query.

### Shipper config (Alloy, abbreviated)

```alloy
discovery.docker "containers" {
    host = "unix:///var/run/docker.sock"
}

loki.source.docker "containers" {
    host       = "unix:///var/run/docker.sock"
    targets    = discovery.docker.containers.targets
    forward_to = [loki.process.parse_json.receiver]
}

loki.process "parse_json" {
    forward_to = [loki.write.local.receiver]

    stage.json {
        expressions = {
            service      = "service",
            node_id      = "node_id",
            cluster_name = "cluster_name",
            component    = "component",
            level        = "level",
            version      = "version",
        }
    }

    stage.labels {
        values = {
            service = "", node_id = "", cluster_name = "",
            component = "", level = "", version = "",
        }
    }
}

loki.write "local" {
    endpoint { url = "http://loki:3100/loki/api/v1/push" }
}
```

Full config: [`config/monitor/alloy/config.alloy`](../config/monitor/alloy/config.alloy).

### Admin-side backend (planned)

The i2gosignals-admin server will read these logs through a configurable
`[[log_backends]]` block. **The block below is forward-looking — admin v1
ships with the Loki backend only.**

```toml
[[log_backends]]
name = "primary-loki"
type = "loki"
url  = "http://loki:3100"
# Optional: basic auth, mTLS, etc. — see admin docs when published.
```

---

## 4. GCP / GKE reference: managed Fluent Bit → Cloud Logging

GKE clusters ship with a managed Fluent Bit / OpsAgent (depending on the
cluster generation) that already tails container stdout into Cloud Logging.
You do not deploy a forwarder yourself — you only annotate the workload so
the agent parses the JSON and surfaces the fields as `jsonPayload.*`.

### Shipper config (Fluent Bit, illustrative)

```yaml
[FILTER]
    Name    parser
    Match   kube.*goSignals*
    Key_Name log
    Parser   json
    Reserve_Data On
```

Cloud Logging indexes `jsonPayload.service`, `jsonPayload.node_id`, etc.
directly; no label promotion step is needed. Build dashboards from those
fields.

### Admin-side backend (planned)

```toml
[[log_backends]]
name = "gcp-logging"
type = "gcp_cloud_logging"
project_id = "my-gcp-project"
# Auth via Workload Identity in-cluster; service account JSON outside.
```

> Marked **planned, not yet implemented** in admin v1. The admin server
> currently only queries the Loki backend.

---

## 5. AWS / EKS reference: Fluent Bit DaemonSet → CloudWatch Logs

EKS does not ship a log collector by default. Run a Fluent Bit DaemonSet
configured to parse JSON and forward to CloudWatch Logs.

### Shipper config (Fluent Bit, illustrative)

```yaml
[INPUT]
    Name              tail
    Tag               kube.goSignals.*
    Path              /var/log/containers/*goSignals*.log
    Parser            docker
    Refresh_Interval  5

[FILTER]
    Name              parser
    Match             kube.goSignals.*
    Key_Name          log
    Parser            json
    Reserve_Data      On

[OUTPUT]
    Name              cloudwatch_logs
    Match             kube.goSignals.*
    region            us-east-1
    log_group_name    /gosignals/${cluster_name}
    log_stream_prefix ${node_id}-
    auto_create_group true
```

CloudWatch surfaces the parsed fields under `$.service`, `$.node_id`, etc.,
queryable from CloudWatch Logs Insights with the `parse @message as ...`
syntax.

### Admin-side backend (planned)

```toml
[[log_backends]]
name = "aws-cloudwatch"
type = "aws_cloudwatch_logs"
region = "us-east-1"
log_group = "/gosignals/prod"
# Auth via IRSA in-cluster; static keys outside.
```

> Marked **planned, not yet implemented** in admin v1.

---

## 6. Azure / AKS reference: Container Insights → Azure Monitor

AKS clusters with Container Insights enabled forward container stdout into
Log Analytics workspaces (`ContainerLogV2` table). Enabling JSON parsing
is a workspace-side configuration; no extra forwarder is deployed.

### Shipper config (Container Insights ConfigMap snippet, illustrative)

```yaml
[log_collection_settings.enrich_container_logs]
    enabled = true
[log_collection_settings.schema]
    containerlog_schema_version = "v2"
```

Query examples in KQL (Kusto):

```kusto
ContainerLogV2
| where LogMessage contains "service"
| extend payload = parse_json(LogMessage)
| where payload.service == "gosignals"
| project TimeGenerated, payload.level, payload.component, payload.msg
```

### Admin-side backend (planned)

```toml
[[log_backends]]
name = "azure-monitor"
type = "azure_log_analytics"
workspace_id = "00000000-0000-0000-0000-000000000000"
# Auth via managed identity in-cluster.
```

> Marked **planned, not yet implemented** in admin v1.

---

## 7. Securing Loki in production

The Loki shipped in the dev compose has `auth_enabled: false` because it
is firewalled to the compose network. In production:

1. **Terminate TLS at a reverse proxy** (Nginx, Caddy, Traefik). Loki
   itself does not need a TLS-aware listener.
2. **Require HTTP Basic auth at the proxy**. Loki accepts a `X-Scope-OrgID`
   header for multi-tenancy but does not authenticate itself.
3. **Restrict the push endpoint to internal networks** — the
   `/loki/api/v1/push` endpoint accepts arbitrary log writes.
4. **Use the Alloy `loki.write` block's `basic_auth` field** to send
   credentials from the forwarder.

Example Alloy block:

```alloy
loki.write "secure" {
    endpoint {
        url = "https://loki.internal.example.com/loki/api/v1/push"
        basic_auth {
            username = "gosignals-forwarder"
            password = env("LOKI_PUSH_PASSWORD")
        }
    }
}
```

Cross-reference: the same trust model that protects `/loki/api/v1/push`
should also gate goSignals' own management APIs — see
[security_model.md](security_model.md) for the authentication patterns
goSignals uses internally (OAuth, HMAC, SPIFFE).

---

## 8. Querying examples

All of the following work against the dev compose's Loki at
`http://localhost:3100`. Open Grafana at `http://localhost:3000`
(admin/grafana), select the Loki datasource, and paste any of the queries
below.

### All goSignals logs

```logql
{service="gosignals"}
```

### Errors only, across both nodes

```logql
{service="gosignals", level="ERROR"}
```

### Errors from the push delivery component

```logql
{service="gosignals", component="ROUTER", level="ERROR"}
```

### Filter to a single stream by parsing the line

`stream_id` is intentionally **not** a label (see §2). Query it through the
JSON parser:

```logql
{service="gosignals"} | json | stream_id="abc123"
```

### Tail a node by `node_id`

```logql
{service="gosignals", node_id="gosignals1"}
```

### Find a specific JTI

```logql
{service="gosignals"} | json | jti="set-jti-..."
```

### Recent errors grouped by component

```logql
sum by (component) (count_over_time({service="gosignals", level="ERROR"}[15m]))
```

For more on the related metrics path, see
[Metrics.md](Metrics.md). Field names referenced in queries
(`stream_id`, `jti`, etc.) match what the codebase emits via `slog` and
should not be confused with the cluster identifiers documented in
[Cluster.md](Cluster.md) or the environment variables in
[configuration_properties.md](configuration_properties.md).

---

## 9. Forward-looking: Operational SETs (v2 sketch)

A future release will introduce **Operational Security Event Tokens** —
SETs that goSignals emits about its own operational state (stream
lifecycle, lease takeovers, push degradation, etc.) onto a dedicated SSF
stream that operators and downstream tooling can subscribe to.

The `op_event_*` JSON field namespace is reserved for this feature. In v1:

- **No `op_event_*` fields are emitted.**
- **No Operational SET stream is created.**
- The namespace exists only so that ingest pipelines can be configured
  ahead of time without breaking when v2 lands.

Sketch of the v2 shape (subject to change):

| Field                    | Notes                                              |
|--------------------------|----------------------------------------------------|
| `op_event_id`            | JTI of the emitted operational SET.                |
| `op_event_type`          | `stream.lifecycle.*`, `cluster.lease.*`, etc.      |
| `op_event_subject`       | Stream ID, node ID, or other affected resource.    |

Operators integrating an admin-side log backend today should leave the
`op_event_*` namespace unindexed (or index it as a single low-cardinality
*event type* field) so the index design stays stable across the v1→v2
upgrade.

This section will be expanded in the v2 PRD; treat it as a stability
contract for the field-name prefix only, not a feature plan.
