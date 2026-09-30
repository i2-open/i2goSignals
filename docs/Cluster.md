<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../brand/logo/gosignals-hero-primary.svg"><img src="../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# goSignalsServer Clustering Design

This document describes the clustering approach implemented in `goSignalsServer` to support running multiple instances in a cluster.

## Overview

The clustering mechanism ensures that specific tasks are owned by a single node at a time to avoid conflicts and redundant processing. This is achieved using MongoDB-backed leases.

The following features are owned by a single node per stream:
*   **Event Stream Poll Receivers**: Only one node polls an upstream SSF Events endpoint.
*   **Event Stream Push Transmitters**: Only one node pushes events to a downstream receiver endpoint.
*   **SSTP Pair Clients (initiators)**: Only one node opens the outbound SSTP connection cycle for a pair. The SSTP **server (responder)** side takes **no** lease — every node can answer `POST /sstp/{id}`, so the receiver side scales horizontally.

## Node Identity

Each node identifies itself using a `NodeID`, which is determined at startup:
1.  `I2SIG_CLUSTER_NODE_ID` environment variable.
2.  `POD_NAME` environment variable (for Kubernetes).
3.  Fallback: `hostname` + process start timestamp.

## Lease Mechanism

Leases are stored in the `cluster_leases` collection in MongoDB.

### Document Schema
```json
{
  "_id": "resource_key",
  "ownerNodeId": "node-123",
  "leaseUntil": "2026-01-25T12:00:30Z",
  "createdAt": "2026-01-25T11:00:00Z",
  "updatedAt": "2026-01-25T12:00:00Z",
  "fencingToken": 42
}
```

### Atomic Acquisition and Renewal
Leases are acquired or renewed using an atomic `FindOneAndUpdate` operation:
*   **Condition**: (lease is expired) OR (lease is owned by current node).
*   **Update**: Set `ownerNodeId` to current node and extend `leaseUntil`. `fencingToken` is kept when the current owner renews a live lease, and incremented when a new tenure starts (a first acquire, a takeover, or a re-acquire after the lease expired). The token therefore names one tenure of the lease.

### Reading the Owner
`GetLeaseOwner` reports an expired or released lease as unowned (empty owner, token 0), so a caller never mistakes a lapsed lease for a live one.

### Release on Stop
Push transmitter and poll receiver runners release their lease (`ReleaseLeaseIfOwned`) when they stop, after their heartbeat has stopped, so another node can take the stream at once instead of waiting out the TTL. The SSTP client releases its pair lease the same way.

### Local WAL: Drain Before Release
With `I2SIG_STORE_WAL=local` (ADR 0045), a SET is acknowledged once it is in this node's WAL, before it reaches the store. A lease must not pass to another node while such SETs are only on this node's disk. So in local mode the stop order is (#341):
1.  Ingest closes. A SET arriving now gets 503 + `Retry-After`, and the transmitter resends it, possibly to another node.
2.  The background drain worker stops between batches, and the WAL is drained to the store synchronously, retrying store failures, for at most `I2SIG_STORE_WAL_DRAIN_TIMEOUT` (default 20s).
3.  Only then are the delivery runners stopped. Each releases its lease as it exits (above), so the next holder finds every acknowledged SET in the store.

If the drain times out, the node logs the residual depth at ERROR, and the entries stay on disk. Its leases are still released at stop and then expire normally. The residue is replayed when this node starts again. At start, a WAL that holds entries from a previous run is replayed to the store first. Until it is empty, ingest answers 503 + `Retry-After`. In the default `majority` mode, none of this applies and the stop order is unchanged.

### Local WAL: Multi-Node Guard
A SET acknowledged into one node's WAL is not in the store until the drain moves it. Another node that owns the stream's delivery lease cannot see it until then. Ring-fed delivery (`I2SIG_STORE_WAL_RING_FED=true`, #342) closes that gap on the buffering node. So local mode in a cluster requires ring-fed delivery (#343). The guard has a startup half and a runtime half:
*   At startup, a node with `I2SIG_STORE_WAL=local` and ring-fed off first registers itself with the cluster coordinator, then asks for the active nodes. If any active node other than itself is registered, it logs an ERROR and refuses to start. The error names the condition and both fixes: set `I2SIG_STORE_WAL_RING_FED=true`, or return to `majority` (unset `I2SIG_STORE_WAL`). Registering before reading means two such nodes started at the same time see each other; at least one refuses, and if both do, the refused entries age out of the active window (60s) and the next start succeeds.
*   If membership cannot be read, the node also refuses, since it cannot confirm it is alone.
*   With ring-fed on, both halves are skipped and local mode is allowed in any cluster size.
*   At runtime, after every 10s heartbeat, a running local-mode node without ring-fed reads the active peers. The first time it finds one, it logs an ERROR naming the peer and both fixes and suspends local ingest on itself: streams with `durability=local` are acknowledged at majority from then on (their effective durability reads `majority`), entries already in the WAL keep draining, and `goSignals_wal_local_ingest_suspended` reads 1. There is no re-arm; the node stays at majority until it restarts, so its durability contract does not flap with membership. A failed membership read is retried on the next heartbeat, not acted on.
*   So when a second node joins, the joiner refuses to start and the running node steps down to majority. Either way no SET is acknowledged into a WAL another node's delivery cannot see for longer than one heartbeat.

Even in local mode, only streams whose per-stream `durability` is `local` use the WAL. All other streams keep the majority contract.

### Fenced Acks
`AckEvent` / `AckEvents` carry the caller's fencing token. The event service checks it once per call, before any write, against the current lease for the stream:
*   If the stream's lease is now held under a different token (or has expired), the ack is refused with `ErrStaleFencingToken` and nothing is written. A push runner that sees this stops its batch and goes back to re-acquire the lease.
*   A lease lookup error fails closed: the ack is refused.
*   Modes that hold no lease (poll transmitter, SSTP server) ack with `NoFencingToken`. The check passes only because the router reports no lease resource for the stream — a `NoFencingToken` ack on a leased stream (push, SSTP client) is refused, as is any token once the lease has expired.

### Parameters
*   **Lease Duration**: 30 seconds.
*   **Renewal (Heartbeat) Interval**: 10 seconds.
*   **Failover Detection**: 30 seconds.

## Feature Implementation

### Poll Receivers
When a stream is configured as a `POLL` receiver, the node attempts to acquire the lease `poll-receiver:<streamId>`.
*   If successful, it starts the polling loop and a background heartbeat to renew the lease.
*   If the lease is lost (e.g., due to network issues or node slowdown), the heartbeat cancels the polling loop context, causing it to stop.
*   Other nodes will periodically try to acquire the lease and take over if the current owner's lease expires.

### Push Transmitters
Similarly, for `PUSH` transmitters, the node attempts to acquire the lease `push-transmitter:<streamId>`.
*   Only the lease holder runs the `PushStreamHandler` loop for that stream.
*   If the lease is lost, the loop stops.

### SSTP Pair Clients
For the **client (initiator)** side of an SSTP pair, the node attempts to acquire the lease `sstp-client:<PairId>` (note: keyed by the pair's `PairId`, not a per-direction SID).
*   Only the lease holder runs the SSTP-client connection loop, opening and re-opening the single bidirectional HTTP cycle for that pair.
*   The lease uses the same 30 s duration / 10 s heartbeat as push/poll. A new owner waits a short randomized takeover jitter before opening its first connection, spreading the thundering-herd after a cluster-wide blip.
*   If the lease is lost, the heartbeat cancels the cycle context, aborting any in-flight request; another node takes over after the lease expires.
*   The SSTP **server (responder)** side takes no lease and is not listed here — see the overview above.

## Intra-Cluster Coordination (Wake-up Mechanism)

To ensure low-latency event delivery without relying on MongoDB Change Streams (which can be resource-intensive and complex to manage), `goSignalsServer` uses a lease-aware wake-up mechanism.

When a node receives or generates an event that needs to be routed to an outbound stream:
1. It identifies the current lease owner for that stream (e.g., `push-transmitter:<streamId>`).
2. If the current node is the owner, it enqueues the event locally for immediate transmission.
3. If another node is the owner, it sends a lightweight `POST /_cluster/wake-transmitter` request to that node.
4. The receiving node, upon validation of the request, triggers an immediate backfill from MongoDB to fetch and transmit any pending events.

This mechanism is secured using a shared HMAC secret (`I2SIG_CLUSTER_INTERNAL_TOKEN`) and includes rate-limiting to prevent denial-of-service.

Wake-ups are coalesced per target over a 250 ms window, on the sending and on the receiving node, and on **both edges** (#347): the first wake of a burst goes out (or is acted on) at once, and any further wake inside the window arms one trailing wake at the window's end, shared by the rest of the burst. A wake says only "this target has work", so the last wake of a burst is never lost.

On a push stream the owner's wake backfill reads the store past what is already queued or in flight, up to a cap of ten backfill batches per wake. A read that stops at the cap, or a periodic backfill that comes back full, marks a backlog: the loop then reads again each time a batch completes and the buffer runs low, so a burst deeper than the cap drains at delivery speed rather than one batch per backfill interval.

### SSTP wake-up endpoints

SSTP adds two wake-up routes that mirror `/_cluster/wake-transmitter` but are kept separate for telemetry. Both reuse the wake-transmitter authentication (SPIFFE mTLS peer certificate, else the `I2SIG_CLUSTER_INTERNAL_TOKEN` shared-HMAC bearer) and the same two-edge coalescing window, so duplicate wake-ups inside the window collapse into one trailing wake:

*   **`POST /_cluster/wake-sstp-client`** — the request body's `sid` field carries the pair's **`PairId`**. Broadcast to all cluster nodes when a node receives an inbound event whose target SSTP-client pair is owned (via the `sstp-client:<PairId>` lease) by a different node, so the lease owner drains the pending event into the next outbound cycle.
*   **`POST /_cluster/wake-sstp-server`** — the request body's `sid` field carries the pair's **tx-side SID**. Broadcast when a node receives an outbound event matching an SSTP-server pair, so a long-poll held open on the receiver side returns the event immediately.

## Stream-table reconciliation

Each node keeps its own in-memory table of the outbound streams it serves (push transmitters, poll receivers, SSTP pairs). A stream created or deleted through one node changes only the shared store, so every node reconciles its table against the store (#349, #350):

*   **Periodic sync** — every 40 seconds the background sync reads every stream from the store, (re)applies each one to the router, and removes every stream the router serves that the store no longer has. This is the fallback that always runs.
*   **Stream-changed broadcast** — after a stream or SSTP pair is created or deleted, the node that handled the request calls `POST /_cluster/stream-changed` on every other active node with an advertised address. The receiving node runs the same reconcile at once and answers `202`. The call uses the wake-up authentication (SPIFFE mTLS peer certificate, else the `I2SIG_CLUSTER_INTERNAL_TOKEN` shared-HMAC bearer, minted with its own `stream-changed` mode so a wake-up token is not accepted here). Stream-changed calls are **not** coalesced: a create followed at once by a delete of the same stream must both be seen.
*   **Synchronous, bounded** — the create/delete request returns only after every peer has answered or timed out (2 seconds per peer, called in parallel). A peer that misses the call catches up on its next periodic sync, within 40 seconds.
*   **No store read on the hot path** — a node that routes an event and finds no matching stream does not re-read the store to look for a new one; that would put a store read on every unmatched event. New streams arrive through the broadcast or the periodic sync.

A reconcile snapshots the streams the router serves **before** it reads the store, so a stream created locally after the snapshot is never removed. If the store read fails, nothing is removed and the cluster-row GC below is skipped.

### Deleted streams

When a reconcile finds that a stream is gone from the store, the router removes it: its transmitter runner stops, its lease is released at once (not left to expire), and later events write no pending marker for it.

On the deleting node, the stream delete holds the stream-table lock from the receiver teardown through the router's `RemoveStream` to the store's `DeleteStream`, so no reconcile can run between them and re-add the stream. An SSTP pair delete does not take the lock, because `DeleteSstpPair` may make a courtesy call to the peer. A reconcile that runs between its `RemoveStream` and the store delete can re-add the pair for one cycle, and the next reconcile removes it again.

### Orphan pending events

`DeleteStream` removes the stream document only. Pending-event markers already written for the stream stay in the store, but they are inert: nothing reads them once no node serves the stream, and no new marker is written for it. They are not purged.

### Cluster-row GC

After each successful reconcile, a node purges cluster rows left behind by nodes and streams that no longer exist. The GC window is 90 seconds (three lease TTLs):

*   **`cluster_nodes`** — a node row whose `lastSeenAt` is older than the window is deleted.
*   **`cluster_leases`** — a lease row whose `leaseUntil` is older than the window is deleted **only** when its resource (`push-transmitter:<sid>`, `poll-receiver:<sid>`, `sstp-client:<PairId>`) names a stream or pair no longer in the store. Lease rows of unknown kinds are kept.

A live stream's lease row is never deleted, however long it has been expired. Deleting a lease row restarts its fencing token at 1, which would let a stale holder's acks validate again; a stream that no longer exists has no holder left to fence.

## Periodic Backfill

As a fallback and to ensure eventual consistency, transmitter loops periodically perform a "backfill" by polling MongoDB for any pending events that might have been missed by the wake-up mechanism (e.g., due to network transient issues). The backfill interval and batch size are configurable.

An SSTP-client pair loop whose primary long-poll is held by the peer re-checks its outbound work on the same interval (1 second), whether or not a wake was seen, so a wake lost to coalescing or a failed wake call delays those SETs by at most one interval rather than until the long-poll returns (#347).

## Observability

Nodes register themselves in the `cluster_nodes` collection with metadata:
*   `_id`: Node ID.
*   `address`: The wake-up address peers call (see below).
*   `version`: Build version.
*   `startedAt`: Startup timestamp.
*   `lastSeenAt`: Last heartbeat timestamp.

### Advertised wake-up address

Each node writes the address its peers use for wake-up calls into `address`, at registration and on every heartbeat:

*   `I2SIG_CLUSTER_ADVERTISE_URL`, when set, is stored verbatim (e.g. `http://goSignals1b:8898`).
*   Otherwise it is derived as `http://<BASE_URL host>:<port>`, where the port is `I2SIG_CLUSTER_INTERNAL_PORT` if set, else the `BASE_URL` port. The scheme is always `http`, so pair a derived address with `I2SIG_CLUSTER_INTERNAL_PORT` (the internal listener serves plain HTTP unless SPIFFE mTLS is on) rather than a TLS main port.

When every node shares one `BASE_URL` (a load-balanced or public name), the derived addresses collide: every node advertises the same address, wake-up calls reach only one node, and cross-node delivery silently falls back to the periodic backfill (SSTP stalls). Give each node its own `I2SIG_CLUSTER_ADVERTISE_URL` (or a per-node `BASE_URL`). A node that finds another live node advertising its own address logs one WARN per peer naming both node ids (`nodeID`, `peerNodeID`).

## Failure Modes and Handling

*   **Node Crash**: The lease will expire after 30 seconds, allowing another node to take over.
*   **MongoDB Downtime**: Nodes will lose their leases if they cannot renew them within the duration. Tasks will stop until MongoDB is available again.
*   **Network Partition**: A partitioned node will lose its lease and stop its tasks. The other side of the partition (if it can reach MongoDB) will take over.

## Deployment and Demonstration

To demonstrate clustering in a Docker environment, use the provided cluster configuration files:

*   `docker-compose-cluster.yml`: Runs `goSignals1` as a two-node cluster (`goSignals1a` and `goSignals1b`) and `goSignals2` as a standalone instance.
*   `docker-compose-cluster-dev.yml`: Development version of the cluster configuration.

In this setup, you can observe that:
1. Both `goSignals1a` and `goSignals1b` connect to the same MongoDB database (`goSignals1`).
   Both share `BASE_URL=https://gosignals1:8888/`, so each sets `I2SIG_CLUSTER_INTERNAL_PORT=8898` and its own `I2SIG_CLUSTER_ADVERTISE_URL`; `cluster_nodes` shows `http://goSignals1:8898` and `http://goSignals1b:8898`.
2. They will compete for leases for any stream defined in that database.
3. If you stop the container holding a lease, the other node will automatically take over after the lease expires (approx. 30 seconds).

---

<!-- gosignals-brand-footer -->
<p align="center"><sub>(C)2026 Independent Identity Inc.</sub></p>
