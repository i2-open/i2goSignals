<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 18. One bidirectional StreamStateRecord per SSTP pair

Date: 2026-06-07

## Status

Accepted

## Context

SSTP (draft-hunt-secevent-sstp-00, PRD #154) is goSignals' third delivery
method. Unlike RFC 8935 push and RFC 8936 poll — each of which is a single
direction modelled by one `StreamStateRecord` — an SSTP pair carries SETs in
*both* directions over a single HTTP cycle: the initiator's outbound SETs ride
the request body while it long-polls for the responder's inbound SETs in the
response. A node that participates in an SSTP pair is therefore simultaneously a
transmitter (outbound) and a receiver (inbound) for the same logical peer
relationship.

The existing data model has no shape for "both directions of one relationship."
The naive port of the RFC 8935/8936 model would provision two independent
`StreamStateRecord`s per node and cross-link them by SID or pointer. That
reintroduces exactly the management cost SSTP exists to remove: four SIDs across
the two nodes, two bearer credentials, two endpoint URLs, two lease owners — the
"doubling the management surface" problem from the PRD problem statement. It also
makes pair atomicity (create/update/delete must affect both directions together)
a multi-document transaction or a service-aggregate wrapper, and a cross-link
pointer can drift if one side is updated and the other is not.

A separate concern is secret/endpoint leakage. The SSF wire-format
`StreamConfiguration.delivery` object is returned on management and discovery
responses. If the per-direction delivery objects carried the per-pair bearer
token and endpoint URL (as the RFC 8935/8936 transmit/receive methods do), those
secrets would be exposed on the wire for both directions and would need bespoke
redaction in two places.

## Decision

An SSTP pair is **one `StreamStateRecord` per node**, carrying both directions:

- The embedded `StreamConfiguration` (the primary, the one aliased to `_id`) is
  the **transmit (outbound)** side. Its `Delivery` holds the marker-only
  `SstpTransmitMarker`.
- A new `SstpInbound *StreamConfiguration` field is the **receive (inbound)**
  side. Its `Delivery` holds the marker-only `SstpReceiveMarker`.
- Connectivity that is pair-scoped — `Role`, `EndpointUrl`,
  `AuthorizationHeader`, `PeerPairId` — lives in a new `SstpMethod *SstpMethod`
  field on the record, **not** duplicated across the two per-direction
  `Delivery` objects. Secrets and endpoints are encapsulated in one place;
  redacting the SSF wire shape is trivial because the wire-format `delivery`
  objects are markers (method URN only).
- `PairId string` is a fresh `bson.ObjectID` hex minted at create time and is
  the on-wire SSF `stream_id` for each side of the pair.
- Per-direction status mirrors the existing fields: `Status`/`ErrorMsg` cover
  the transmit side; new `InboundStatus`/`InboundErrorMsg` cover the receive
  side.

The type system distinguishes the bidirectional shape without a separate record
type:

- `GetType()` returns a new internal discriminator `DeliverySstpPair` whenever
  `SstpMethod` is set — regardless of which marker the primary `Delivery` holds.
  `DeliverySstpPair` is a goSignals-internal type tag, **not** an SSF wire URN.
- `HasInbound()` / `HasOutbound()` return `true`/`true` for an SSTP pair, and
  fall through to `IsReceiver()` / `IsTransmitter()` (which read the primary
  `Delivery` method) for RFC 8935/8936 records.

`OneOfStreamConfigurationDelivery` grows two marker-only embedded pointer
variants, `SstpTransmitMarker` and `SstpReceiveMarker`, each carrying only
`{ Method string }`. `UnmarshalJSON` matches on URN substrings — the receive URN
(`urn:i2-open:secevent:delivery:sstp:receive`) is a superstring of the transmit
URN (`urn:i2-open:secevent:delivery:sstp`), so the receive check runs first —
and `GetMethod()` returns the method constant by which pointer is non-nil. The
SSF delivery-method URN `urn:i2-open:secevent:delivery:sstp` is advertised
unconditionally in `delivery_methods_supported` on every server's
`.well-known/ssf-configuration`, so a peer can discover SSTP support without
per-server config.

Two DAO accessors locate a pair: `FindByInboundSID(sid)` (matches
`SstpInbound.Id`) and `FindByPairId(pairId)`. Both are backed by **sparse-unique**
Mongo indexes (`sstp_inbound.id`, `pair_id`); because non-SSTP records lack both
fields, the sparse option means those records pay zero index cost. The existing
aliasing invariant `StreamConfiguration.Id == _id` is preserved on the transmit
side, and `RemoteAddress` stays single per record — one HTTP cycle multiplexes
both directions, so there is one peer address to track.

## Consequences

### Positive

- **One paired object.** Operators reason about a single record per node for a
  pair; create/update/delete is single-document atomic with no cross-link
  pointer to drift. This is the four-SID-elimination the PRD set out to achieve,
  without a service-aggregate wrapper.
- **Secrets stay off the wire.** The per-direction `Delivery` objects are
  markers; the bearer token and endpoint live in `SstpMethod`, so SSF
  discovery/management responses never leak per-pair credentials and redaction
  is a single non-serialised path rather than two.
- **The OneOf dispatcher contract is preserved.** Existing callers that branch
  on `GetMethod()` keep working; SSTP adds two cases rather than a parallel
  type.
- **Non-SSTP records are unaffected.** The new fields are `omitempty` in JSON
  and BSON; the sparse indexes skip records without the keys; `GetType()`,
  `HasInbound()`, `HasOutbound()` fall through to the existing RFC 8935/8936
  behaviour.

### Negative

- `StreamStateRecord` carries two `StreamConfiguration`s for SSTP records, which
  is a slightly larger document and a second embedded delivery object to keep
  consistent. Mitigated by the single-document atomicity that makes the
  consistency trivial to maintain.
- The `DeliverySstpPair` discriminator is goSignals-internal and not an SSF wire
  URN, so readers must not confuse it with the advertised
  `urn:i2-open:secevent:delivery:sstp`. Documented here and in the field
  comments.
- `GetType()` now depends on `SstpMethod` presence as well as the `Delivery`
  marker; a record with an SSTP marker but no `SstpMethod` would report its
  marker method, not `DeliverySstpPair`. Pair creation (slice #161) is
  responsible for always setting `SstpMethod` on a pair record.

## Related

- PRD #154 — SSTP as a third delivery method (Q22, Q23, Q24, Q25, Q48).
- Issue #159 — bidirectional `StreamStateRecord` + DAO accessors (this ADR).
- ADR 0010 (provider decomposition) — the per-domain DAO seam these accessors
  ride on.
- ADR 0017 (JTI is the event dedup key) — the idempotent-ingestion prerequisite
  SSTP recovery depends on.
- `pkg/ssfModels/model_stream_state.go`,
  `pkg/ssfModels/model_one_of_stream_configuration_delivery.go`,
  `pkg/ssfModels/model_sstp_delivery_method.go`,
  `internal/dao/interfaces/dao_interfaces.go`,
  `internal/providers/dbProviders/mongo_provider/provider.go` (sparse-unique
  indexes), draft-hunt-secevent-sstp-00.
