<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 30. SETs persist in their wire shape, via a JSON round-trip codec

Date: 2026-08-13

## Status

Accepted (GH #259)

## Context

`goSet.SecurityEventToken` and `goSet.SubjectIdentifier` were persisted by the
mongo-driver's default struct codec. That codec keys documents by **Go field
name** and has no notion of the `json:",omitempty"` tags these types carry, so
every stored event was Go-shaped rather than wire-shaped:

- The RFC 8417 registered claims were buried in a `registeredclaims`
  subdocument under Go names (`issuer`, `audience`, `expiresat`, `issuedat`,
  `id`) instead of appearing at the top level as `iss`, `aud`, `exp`, `iat`,
  `jti`.
- `SubjectIdentifier` embeds eleven identifier variants, so an opaque subject
  that is two members on the wire (`{"format":"opaque","id":"…"}`) was stored
  fully expanded, with every unused variant present and empty.
- The same defect reached the `subject_filters` collection, because
  `ssfModels.SubjectFilterEntry.Subject` is a `*goSet.SubjectIdentifier` too.

Nothing queried those fields — the events collection filters on `EventRecord`
level `jti` / `sid` / `sortTime` / `types`, and subject matching goes through
the canonical key in `subject_filters` (ADR-0003) — so this was storage bloat
and unreadable documents rather than a live routing bug. But it made stored
events unusable to any reader that expects a SET, and it grew every row.

The obvious fix, adding `bson:` tags, cannot work: the registered claims come
from `jwt.RegisteredClaims`, a third-party embedded type we cannot tag, whose
`jwt.NumericDate` / `jwt.ClaimStrings` members also carry custom JSON
marshalling. Tags alone can never produce wire-named claims.

The second problem is reading. BSON decoding **ignores unknown fields** rather
than erroring, so a document written before the fix would decode under a
wire-shaped codec to a zero value — an empty issuer, an empty subject — and the
failure would surface as a mis-routed or silently withheld event, not as an
error.

## Decision

**D1 — The BSON representation is derived from the JSON representation.**
`pkg/goSet/set_bson.go` implements `bson.Marshaler` / `bson.Unmarshaler` on
`SecurityEventToken` and `SubjectIdentifier` by round-tripping through the
type's own JSON encoding: `json.Marshal` → `bson.UnmarshalExtJSON` → `bson.D`
on the way out, and the inverse on the way in. The `json:` tags stay the single
source of truth for member names and for which members are omitted when empty,
including for types we do not own.

**D2 — Relaxed (non-canonical) ExtJSON is the intermediate.** It preserves
field order, so stored documents are deterministic, and it preserves integer
types rather than widening everything to double. The known constraint is that
`$`-prefixed keys inside an arbitrary event payload are not representable; that
surfaces as a loud `Insert` failure, not silent corruption, and no SCIM / RISC /
CAEP profile uses such keys.

**D3 — Read compatibility is a legacy sniff inside `UnmarshalBSON`.** Before
decoding, the unmarshaler checks the document's top-level keys for markers that
only the old codec could have produced — `registeredclaims` for a SET, the ten
embedded-identifier field names (`opaqueidentifier`, `emailidentifier`, …) for a
subject. On a hit, it decodes through a defined-type alias that carries no BSON
methods, which *is* the default struct codec — i.e. exactly the encoder that
wrote the row. A legacy SET's nested `subjectid` re-enters
`SubjectIdentifier.UnmarshalBSON` and falls back in turn.

The sniff lives in `pkg/goSet` rather than at the DAO, which is what makes it
cover `subject_filters` as well as `events` — those rows have no `Original` JWS
to reparse, so a DAO-level reparse path would have fixed only half the problem.

**D4 — No migration.** Old rows are read in place and rewritten in the new
shape only if something updates them. There is no backfill and no dual-write.

## Consequences

### Positive

- Stored events are readable SETs: claims under their wire names, subjects as
  RFC 9493 members, and nothing the token did not carry.
- Row size drops materially for the common case — an opaque subject goes from
  eleven subdocuments to two members.
- `subject_filters` gets the same compaction and the same read compatibility for
  free, because the fix is on the shared type.
- Absent complex-subject members are no longer stored as null, which matters
  because SSF §8.1.3.1 reads an absent member as a wildcard.

### Negative

- Persisting a SET now costs a JSON marshal plus an ExtJSON parse. Event
  persistence is not the hot path (delivery is), but this is not free.
- The legacy sniff is permanent dead weight until we are willing to declare a
  floor version and drop it. It is cheap (a top-level key scan) but it is a
  branch that has to keep being tested.
- `json:` tags are now load-bearing for the storage format. Renaming a member
  changes the on-disk shape, which was previously insulated from JSON changes.

## Related

- GH [#259](https://github.com/i2-open/i2goSignals/issues/259) — the defect and
  its acceptance coverage.
- [ADR-0003](0003-split-subject-filter-storage.md) — why subject *matching* runs
  off the canonical key, which is why this was a storage defect and not a
  routing one.
- `pkg/goSet/set_bson.go`, `pkg/goSet/set_bson_test.go` — the codec and its
  format tests; `internal/dao/mongo/persisted_routing_test.go` — the
  persist → re-read → route/filter assertions for both shapes.
