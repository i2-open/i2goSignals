<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# Subject filter storage and matching at scale

A stream's subject filter is **not one undifferentiated set scanned per event**.
It is split by subject kind, because SSF §8.1.3.1 matching splits cleanly:

- **Simple subjects** match iff *exactly identical* — so a simple subject
  canonicalizes (per RFC9493 per-format rules) to one stable key and is held in
  a **hash-indexed set** with O(1) membership. The `subject_filters` collection
  carries an index on that canonical key.
- **Complex subjects** match *field-wise with undefined-as-wildcard* — they
  cannot collapse to a single key, so they are held in a small **linear-scanned
  list**.

A subject filter may legitimately reach **millions of entries** (a watchlist of
every account or email a receiver cares about). A single linear scan per
delivered event would be O(N) — unworkable. The split makes delivery-time
matching O(1) when the event subject is simple and O(complexCount) when it is
complex, and complexCount is small in practice: bulk watchlists are simple
subjects, complex subjects are the rare device/session composites.

On top of the store sits a **per-node, bounded (LRU), short-TTL match-result
cache** keyed by `(stream_id, subject canonical key) → deliver/drop`. Events
about a subject arrive in temporal clusters, so a small cache absorbs most
lookups; the canonical hash-indexed table stays in Mongo rather than being
pinned whole in node memory (millions of entries is real memory pressure). PUSH
(the lease owner) and POLL (any serving node) both use cache-or-single-lookup.

Cache accuracy is deliberately *soft*. A stale **"deliver"** merely over-delivers
for a few seconds — harmless, and consistent with SSF §9.3's tolerance for
events after removal. A stale **"drop"** wrongly suppresses, which is the
hazardous direction — so the cluster invalidation signal fires promptly on
**delivery-increasing** operations (Add), while delivery-decreasing operations
are already softened by the §9.3 removal grace period. Short TTL bounds the rest.

## Considered options

- **One set, linear scan per event ("N is small")** — the original PRD #89
  design. Rejected once N was allowed to reach millions: O(N) per event, and
  the whole table pinned in node memory.
- **Index everything, including complex subjects** — rejected: complex matching
  is field-wise with wildcards, so there is no single key to index on; and the
  complex subset is small enough that a scan is free.
- **Cache the entire filter table per node** (PRD #89's first cut) — rejected at
  scale: millions of entries per stream per node is memory pressure for data
  that is mostly cold. Caching match *results* exploits temporal locality
  instead.

## Consequences

- `SubjectFilterService` exposes simple-key membership and complex field-wise
  matching as distinct paths; `Allows(stream, event)` picks the path by the
  event subject's kind.
- `SubjectFilterDAO` / the `subject_filters` collection carries a canonical-key
  index and a *sparse* index on the §9.3 `enforceAt` field (only pending-removal
  entries carry it) so pending removals are enumerable without scanning the
  table.
- The cluster reload notification (PRD #89) is a cache *invalidation* signal,
  not a "reload the whole filter" signal.
- The admin review endpoint is a **point lookup + aggregate counts**, never a
  paginated enumeration — the hash index makes "is subject X filtered here?"
  O(1), and millions of rows are never streamed to an operator.

---

<!-- gosignals-brand-footer -->
<p align="center"><sub>(C)2026 Independent Identity Inc.</sub></p>
