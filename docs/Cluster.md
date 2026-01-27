# goSignalsServer Clustering Design

This document describes the clustering approach implemented in `goSignalsServer` to support running multiple instances in a cluster.

## Overview

The clustering mechanism ensures that specific tasks are owned by a single node at a time to avoid conflicts and redundant processing. This is achieved using MongoDB-backed leases.

The following features are owned by a single node per stream:
*   **Event Stream Poll Receivers**: Only one node polls an upstream SSF Events endpoint.
*   **Event Stream Push Transmitters**: Only one node pushes events to a downstream receiver endpoint.

## Node Identity

Each node identifies itself using a `NodeID`, which is determined at startup:
1.  `NODE_ID` environment variable.
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
*   **Update**: Set `ownerNodeId` to current node, extend `leaseUntil`, increment `fencingToken`.

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

## Observability

Nodes register themselves in the `cluster_nodes` collection with metadata:
*   `_id`: Node ID.
*   `address`: Host/port.
*   `version`: Build version.
*   `startedAt`: Startup timestamp.
*   `lastSeenAt`: Last heartbeat timestamp.

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
2. They will compete for leases for any stream defined in that database.
3. If you stop the container holding a lease, the other node will automatically take over after the lease expires (approx. 30 seconds).
