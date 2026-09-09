<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 40. SET delivery ordering is a published contract carried by `jti`

Date: 2026-09-09

## Status

Accepted (community #293).

## Context

Neither RFC 8935, RFC 8936 nor the SSF specification promises that SETs are
delivered in the order they were issued, and ADR 0035 recorded that push
delivery order inside a batch is not buffer order. That is a correct reading of
the specs, but it is not the whole story a receiver needs.

Some event profiles are order-sensitive in practice. A SCIM receiver (RFC 9967)
applying `add`, then `replace`, then `remove` to one resource converges on a
different state if it applies them in a different order. Telling such a
receiver only that ordering is "not guaranteed" leaves it with no way to
recover the order, when in fact this server hands it everything it needs.

Three facts were established while reviewing the ADRs 0035-0039 performance
work, and they had never been written down together:

1. **`jti` is already a time-ordered identifier.** `goSet.GenerateJti` returns
   `ids.NewV7`, an RFC 9562 version-7 UUID. Its leading 60 bits are a
   timestamp, so the canonical string form sorts lexicographically into mint
   order. `pkg/goSet/jti_test.go` has always asserted this, and the poll and
   buffer paths already lean on it, but it was stated only as an internal test
   invariant. No receiver-facing document said it.

2. **The pending read had no sort and inherited one from the query planner.**
   `EventDAO.GetPendingForStream` issued an unsorted `find` on `{sid}`. Under
   the legacy `{sid:1}` index that returned insertion order; under the
   `{sid:1,jti:1}` index this release installs it returns `jti` order. The
   change is an improvement, since `jti` order is issue order at the ingesting
   node rather than acceptance order at the replica set primary. But delivery
   order was moving as a side effect of index selection, with no test that
   would have caught it.

3. **The delivery legs have very different ordering properties, and the
   intuitive ranking is backwards.** Poll and SSTP look weaker because their
   `sets` member is a JSON object keyed by `jti` (`map[string]string`), which
   has no defined member order. Concurrent push looks stronger because RFC 8935
   is one SET per POST, a wire format that can carry order. The opposite is
   true. A poll or SSTP batch arrives atomically in one message, messages are
   dispatched serially, and the receiver can reconstruct exact issue order by
   sorting the keys it already holds. Concurrent push dispatches in order and
   then surrenders ordering to the receiver: with several POSTs in flight, the
   order the receiver's application layer observes is decided by its own
   request scheduling, connection handling and internal contention, none of
   which the transmitter can observe or control.

## Decision

**1. `jti` ordering is a published contract, not an implementation detail.**
Every SET this server issues carries a UUIDv7 `jti`. Sorting `jti` values as
strings yields the order the SETs were minted. Receivers may rely on this, and
it is the sanctioned way to recover order on any leg. The generator is
mutex-guarded and strictly monotonic within a process at 1/4096 ms resolution,
so within one node the order is total. Across nodes it is a wall-clock
comparison and therefore only as good as clock synchronisation between them;
under ordinary NTP, concurrent events from different nodes within a millisecond
or so of each other may sort either way. Ordering is per stream. It is not a
transaction boundary and says nothing about causality between resources.

**2. `GetPendingForStream` states its sort.** It now passes an explicit
ascending-`jti` sort rather than inheriting order from whichever index the
planner picks. The `{sid:1,jti:1}` index supplies that order directly, so the
sort adds no blocking stage and no round trip. A test drops the index and
asserts the order survives a collection scan, so the contract is pinned to the
query rather than to the index.

**3. The per-leg ordering properties are documented as follows.**

| Leg | Ordering |
|---|---|
| Poll (RFC 8936), SSTP | Batch is atomic, messages are serial, full issue order recoverable by sorting `jti` |
| Push, `I2SIG_PUSH_CONCURRENCY=1` | In issue order on the happy path; a failure leaves JTIs pending, so a retry reorders them relative to later successes |
| Push, concurrency above 1 | Reordered at the receiver by factors the transmitter cannot see |

Go's `encoding/json` emits map keys sorted, so a poll or SSTP `sets` object is
in fact serialised in `jti` order today. That is a convenience, not part of the
contract: JSON object member order is not significant, and a receiver must sort
rather than depend on parse order.

**4. Receiver guidance.** For an order-sensitive receiver, in preference order:
prefer poll or SSTP, where order is fully recoverable at no throughput cost; if
push is mandatory and order is important, set `I2SIG_PUSH_CONCURRENCY=1`;
and in all cases prefer reconciling on resource state or version over relying
on arrival order, which is the only approach that also survives redelivery.

## Consequences

- **Ordering guidance now points at poll first.** The previous advice offered
  serial POSTs as the ordering lever without noting that poll achieves more and
  costs nothing. `docs/configuration_properties.md` is corrected accordingly.
- **`I2SIG_PUSH_CONCURRENCY=1` is a real but expensive option.** ADR 0035
  measured push at 108 ev/s serially and 398 ev/s pooled, so ordering by
  serialisation costs roughly four times the delivery rate. It is recommended
  only when push is mandatory *and* order matters, not as a general posture.
- **A cross-node ordering claim is bounded by clock skew.** This is the one
  place the contract is weaker than "total order", and it is why receiver-side
  reconciliation remains the recommendation rather than an afterthought.
- **Retraction no longer depends on document order.** `RetractPending` sorts by
  descending `_id` to pick a duplicate deterministically, and its comment used
  to justify that as preserving the older marker's position in a natural-order
  list. Under `jti` ordering the duplicates share a sort key and are
  interchangeable, so the sort is now documented as an arbitrary but
  deterministic choice. An ObjectID is a second-granularity timestamp plus a
  per-process random value, so it was never a cross-node recency ordering.
- Rejected: sorting the pending read by an insertion sequence of our own. It
  would need a new monotonic per-stream counter written on the ingest hot path,
  and `jti` already carries mint order for free.
- Rejected: emitting `sets` as a JSON array to make poll order explicit on the
  wire. RFC 8936 §2.2 defines it as an object keyed by `jti`; changing the
  shape would break every conforming receiver to convey what sorting the keys
  already conveys.
