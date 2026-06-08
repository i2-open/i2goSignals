<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../brand/logo/gosignals-hero-primary.svg"><img src="../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# Synchronous SET Transfer Protocol (SSTP)

SSTP is goSignals' **third SET delivery method**, alongside RFC 8935 push and
RFC 8936 poll. It is defined by `draft-hunt-secevent-sstp-00`
(`docs/specs/draft-hunt-secevent-sstp-00.txt`) and lets two nodes exchange SETs
in **both directions over a single HTTP request/response cycle**: the initiator's
outbound SETs ride the request body while it long-polls for the responder's
inbound SETs in the response.

Unlike push and poll — each a single direction modelled by one
`StreamStateRecord` — an SSTP **pair** is one bidirectional relationship. This
doc covers the pair model, bootstrap, the peer cascade, per-direction mode and
status semantics, and the operator runbook. The wire format and error taxonomy
live in `pkg/goSetSstp` and the source spec.

> The focused per-direction status/verify runbook (formerly a standalone
> rider doc) is folded into this document — see the
> [operator runbook](#operator-runbook).

## Why SSTP

Push and poll each model **one** direction. A bidirectional relationship between
two nodes therefore needs two streams per node — four stream IDs, two bearers,
two endpoint URLs, two lease owners across the pair. SSTP collapses that to one
logical pair per relationship, carried over a single HTTP cycle, halving the
management surface. It suits peers that want a symmetric, firewall-friendly
exchange where the initiator dials out and both directions multiplex on the one
connection.

## The pair model

An SSTP pair is **one `StreamStateRecord` per node**, carrying both directions
(ADR 0018):

| Concept | Where it lives | Notes |
| :------ | :------------- | :---- |
| **txSid** (transmit / outbound) | primary `StreamConfiguration.Id` | Aliased to the Mongo `_id` **and** to `PairId`. Its `Delivery` is a marker only (`urn:i2-open:secevent:delivery:sstp`). |
| **rxSid** (receive / inbound) | `SstpInbound.Id` | Its `Delivery` is a marker only (`urn:i2-open:secevent:delivery:sstp:receive`). |
| **PairId** | `PairId` | A fresh `ObjectID` hex; the **on-wire SSF `stream_id`** and the `{id}` in `POST /sstp/{id}`. Equals txSid. |
| Pair-scoped connectivity | `SstpMethod` | `Role`, `EndpointUrl`, `AuthorizationHeader`, `PeerPairId`. Secrets/endpoints live here, **not** in the per-direction `Delivery` objects, so SSF discovery/management responses never leak per-pair credentials. |
| Per-direction status | `Status`/`ErrorMsg` (tx) and `InboundStatus`/`InboundErrorMsg` (rx) | The two directions report and pause **independently**. |

`GetType()` returns the goSignals-**internal** discriminator `DeliverySstpPair`
whenever `SstpMethod` is set. That is *not* an SSF wire URN — the advertised URN
is `urn:i2-open:secevent:delivery:sstp`, published unconditionally in
`delivery_methods_supported` on every server's `.well-known/ssf-configuration` so
peers can discover SSTP support without per-server config.

Two DAO accessors locate a pair: `FindByPairId(pairId)` and
`FindByInboundSID(sid)`, both backed by sparse-unique Mongo indexes (`pair_id`,
`sstp_inbound.id`). Non-SSTP records lack both fields and pay zero index cost.

### Roles

- **initiator** — the HTTP **client**. It opens and re-opens the connection cycle
  and is owned by exactly one cluster node via the `sstp-client:<PairId>` lease.
- **responder** — the HTTP **server**. It answers `POST /sstp/{id}`, derives its
  own `EndpointUrl` (`/sstp/<PairId>`), and mints its own per-pair bearer. It
  takes **no** cluster lease, so every node can serve the endpoint.

`Role` is **required at create with no default** — the "both peers responder"
misconfiguration is rejected outright.

## Bootstrap (P3): the `SstpPairBootstrap` DTO

A pair is provisioned by `POST /stream` with a **second body shape**,
`SstpPairBootstrap`, discriminated on shape alongside the existing
`StreamConfiguration` (ADR 0019). A body is an SSTP bootstrap when it carries a
top-level `role` of `initiator`/`responder` together with at least one
per-direction `primary`/`inbound` object. A malformed body falls through to the
`StreamConfiguration` path. There is **no `/pairs` endpoint** — create rides the
existing `POST /stream` surface.

Fields:

- **Pair-level**: `role`, `endpoint_url`, `authorization_header`,
  `peer_server_alias`, `peer_pair_id`, `description`.
- **Per direction** (`primary` = transmit, `inbound` = receive): `iss`,
  `iss_jwks_url`, `aud`, `events`, `mode`.

`StreamService.CreateSstpPair` validates and expands the bootstrap:

- `PairId` is minted fresh and aliased to txSid and `_id`; rxSid gets its own
  fresh SID.
- **Responder**: server-derives `EndpointUrl` and server-mints the per-pair
  bearer (`IssueSstpPairToken`, covering both SIDs). An operator-supplied
  `endpoint_url` or `authorization_header` on a responder is **rejected**.
- **Initiator**: the operator **must** supply `authorization_header` (the bearer
  the peer responder minted); `endpoint_url` is operator-supplied or learned via
  the cascade response.
- `EndpointUrl` is validated **syntactically only** — scheme `https` (or `http`
  when `I2SIG_INSECURE_SSTP_HTTP=true`), non-empty host, no query/fragment. No
  network probe; reachability is the runner's concern (matching push/poll).
- Each half needs a non-empty URI-shaped `iss` and `aud` and a recognized
  `mode`. **No reciprocity is enforced between halves**, so asymmetric/multi-hop
  pairs are first-class.
- `Status`/`InboundStatus` are always `Enabled` at create — the runner
  self-pauses on first failure. There is **no "pending" state**.

## Peer cascade

When `peer_server_alias` is present, the service **cascades the mirrored
bootstrap to the peer** using the stored `Server` credentials (the same
foreign-server credential path the rest of goSignals uses; requires `admin`).
The mirror **flips the role** (initiator↔responder) and **swaps the two
directions**, so the peer's `primary` is this node's `inbound`. On success the
local record records the peer's `PairId` in `SstpMethod.PeerPairId`.

Rollback is **role-asymmetric**:

- **Responder** writes its local row first, then cascades; a cascade failure
  rolls the local row back (ReceivePush-style).
- **Initiator** cascades first; no local row exists until the peer returns, so a
  cascade failure writes nothing — nothing to roll back (ReceivePoll-style).

Omitting `peer_server_alias` provisions only the local half; peer connectivity is
patched later via UPDATE.

## Mode semantics per direction

`mode` is per direction and maps to the existing `RouteMode`
(`SstpModeToRouteMode`):

| Mode | RouteMode | Behaviour |
| :--- | :-------- | :-------- |
| `FORWARD` | `RouteModeForward` | Preserve the upstream `iss`; the SET is forwarded **verbatim** (no re-sign). |
| `PUBLISH` | (re-sign) | Re-sign with goSignals' issuer key for that direction (`iss`/`aud` from the direction's config). |
| `IMPORT` | (local) | Keep events local. |

Because mode is per direction, a pair can FORWARD outbound while PUBLISH-ing
inbound, etc.

## Delivery runtime

### Client (initiator) side

- Owned by one node via the `sstp-client:<PairId>` Mongo lease (30 s lease, 10 s
  heartbeat), mirroring the push-transmitter lease. A jittered takeover delay
  spreads thundering-herd after a cluster blip.
- The outbound queue reuses an `EventPollBuffer`; recovery after takeover reads
  the persisted pending JTIs directly from the provider when the buffer is empty.
- One HTTP cycle drains the outbound buffer, delivers via `DeliverSstp`, and
  classifies the response with the `goSetSstp` classifier:
  - **OK / per-JTI**: ack the peer-acknowledged JTIs that we actually sent
    (a stray ack for an unsent JTI is ignored; an empty ack list means
    "all sent SETs accepted"). Increments the outbound counter
    (`tfr=SSTP`, `stream_id=txSid`).
  - **4xx (request error)**: **pause only the outbound direction**. Inbound keeps
    running independently.
  - **5xx / transport**: exponential backoff per `POLL_RETRY_*`; **does not
    pause**.
- **Push-while-poll-held**: when the primary long-poll cycle is held open, a
  *second* parallel POST (with `returnEvents=false`) flushes newly-queued
  outbound SETs without disturbing the held cycle. At most one secondary push is
  in flight per pair.

### Server (responder) side

- Takes **no lease** — every node can answer `POST /sstp/{id}`, so the receiver
  side scales horizontally.
- Inbound ingest (governed by `InboundStatus`): each SET is byte-identical to an
  RFC 8935 SET and parsed with `goSetPush.ParseReceivedSET`, then persisted via
  `HandleEvent` keyed on rxSid (so the inbound counter carries
  `tfr=SSTP`, `stream_id=rxSid`). A duplicate JTI is swallowed by the #153
  ingestion short-circuit but still acked so the sender stops resending.
- Outbound long-poll drain (governed by `Status`): waits on the pair's outbound
  `EventPollBuffer` for the request duration, reusing
  `I2SIG_POLL_DEFAULT_TIMEOUT` / `I2SIG_POLL_MAX_TIMEOUT` (no SSTP-specific
  knob). The wait does **not** honor request-context cancellation — it waits the
  full buffer timeout even if the client aborts, symmetric with the RFC 8936
  poll-transmitter handler.
- A **paused (or disabled) direction returns 200 with `returnEvents=false`**, so
  the cycle keeps running and resumes on unpause. A 4xx is reserved for the
  **deleted/unknown pair** case — HTTP status is the primary error signal.

### Cluster wake-ups

Two routes mirror `/_cluster/wake-transmitter`, kept separate for telemetry; both
reuse the wake-transmitter auth (SPIFFE mTLS peer cert, else the
`I2SIG_CLUSTER_INTERNAL_TOKEN` shared-HMAC bearer) and the same coalescing
window:

- `POST /_cluster/wake-sstp-client` — body `sid` = **PairId**. Broadcast when a
  node receives an inbound event whose target client pair is owned by a different
  node, so the lease owner drains it into the next outbound cycle.
- `POST /_cluster/wake-sstp-server` — body `sid` = **txSid**. Broadcast when an
  outbound event matches an SSTP-server pair, so a held long-poll returns it
  immediately.

See `docs/Cluster.md` for the lease/wake-up internals.

## The HTTP endpoint

`POST /sstp/{id}` where `{id}` is the **PairId** (on-wire `stream_id`):

- POST-only (other methods → 405 with `Allow: POST`).
- Strict `Content-Type: application/sstp+json` (parameters such as `; charset=utf-8`
  are accepted; a mismatch → 415).
- Unknown/deleted pair → 404.
- Authorization is **defense-in-depth**: the bearer carries
  `StreamIds=[txSid, rxSid]` (the internal SIDs), **not** the PairId on the path.
  The handler resolves the record via `FindByPairId`/`GetStreamStateByPairId`
  and authorizes against the actual txSid/rxSid for `scope=event`. A token minted
  for a different pair cannot act on this one. See `docs/security_model.md`.

## Operator runbook

### Create a pair

From the **client (initiator)** side; the named server alias's stored
credentials cascade the mirrored half to the responder:

```bash
# Symmetric (same iss/aud/events/mode both directions):
goSignals create stream sstp <client-alias> <server-alias> \
    --iss https://issuer.example \
    --aud https://peer.example \
    --events urn:ietf:params:SCIM:event:prov:create:full \
    --mode PUBLISH \
    --name my-pair

# Asymmetric / multi-hop (full SstpPairBootstrap with per-direction primary/inbound):
goSignals create stream sstp <client-alias> <server-alias> \
    --bootstrap-file ./pair.json
```

> **Flag note:** the asymmetric input flag is `--bootstrap-file` (**not**
> `--config` — the global `--config` flag, GOSIGNALS_HOME, already owns that
> name). A `.yaml`/`.yml` extension is parsed as YAML; anything else as JSON.
> `--bootstrap-file` and the symmetric flags are mutually exclusive.

The command prints the `PairId`, both pair SIDs, and the resolved
`EndpointUrl`s. The issuing side plays `initiator`; the named server alias is the
responder the bootstrap cascades to.

### Status — per direction

SSTP pairs appear in the **existing flat `GET /states` listing** — there is no
`/pairs` endpoint. Tools expand each pair record into two rows (txSid + rxSid)
grouped client-side by `PairId`.

`GET /status?stream_id=<sid>` reports exactly the direction named:

- `stream_id=<txSid>` → `Status` + `ErrorMsg` (outbound).
- `stream_id=<rxSid>` → `InboundStatus` + `InboundErrorMsg` (inbound).

The two directions report independently. (`disabled` is a pair-level lifecycle
state and couples both directions.)

### Pause / resume — per direction

Per-direction status writes route the same way (`UpdateStreamStatus` keyed by the
`stream_id` you name): pausing txSid pauses **only** the outbound direction;
inbound keeps running, and vice versa. A paused direction's `POST /sstp/{id}`
returns 200 with `returnEvents=false` so the cycle resumes cleanly on unpause.

UPDATE enforces a **patchable-fields whitelist**: `Role`, an already-set
`EndpointUrl`/`PeerPairId`, and all IDs are immutable, so a live pair can never
be accidentally repointed at a different peer. Delete is the only sanctioned way
to break a pair's peer binding.

### Verify — per direction

`POST /verify` with `{"stream_id": "<sid>"}` targets the **outbound side of the
direction the SID names**, emitting an SSF verification SET scoped to that
direction's `iss`/`aud`:

- `stream_id=<txSid>` → verifies the transmit direction from this node.
- `stream_id=<rxSid>` → verifies the inbound direction's outbound leg.

**Reverse-direction verification** (confirm the leg the *peer* transmits into
your inbound side) is ordinary SSF transmitter-initiated verification pointed at
the peer: resolve the peer's transmitter config and `POST <peer>/verify` with
`{"stream_id": "<peer's txSid>"}` (= your rxSid's upstream), authenticated with
the bearer the peer accepts. The peer emits the verify SET, which arrives on your
rxSid. No new local route is needed.

### Delete — with or without cascade

Local cleanup **always proceeds and never blocks on peer reachability** (ADR
0020). Peer cleanup is a **courtesy**, opt-in via `?cascade_peer=true`:

```bash
# Local-only delete (peer untouched): 200
DELETE /stream/<sid>

# Courtesy peer delete too:
DELETE /stream/<sid>?cascade_peer=true
```

- Without `cascade_peer` (or no resolvable peer `Server`): no peer call;
  `LocalDeleted=true` → **200**.
- With `cascade_peer=true`: a courtesy `DELETE` is sent to the peer's stream-config
  endpoint for `SstpMethod.PeerPairId`.
  - Peer accepts → **200**.
  - Peer fails / declines / is unreachable, or `PeerPairId` was never learned →
    the local row is **already gone**; the per-side error is reported and the
    handler answers **207 Multi-Status** with the outcome body. Read the body to
    distinguish a clean cascade from a partial one.

## Configuration knobs

SSTP reuses the poll long-poll and retry knobs — there are **no SSTP-specific
timeout knobs**:

| Variable | Used by SSTP for |
| :------- | :--------------- |
| `I2SIG_POLL_DEFAULT_TIMEOUT` | server-side outbound long-poll timeout |
| `I2SIG_POLL_MAX_TIMEOUT` | server-side outbound long-poll cap |
| `I2SIG_POLL_RETRY_BASE_DELAY` / `_MAX_DELAY` / `_BACKOFF_FACTOR` | client-side transport/transient backoff |
| `I2SIG_INSECURE_SSTP_HTTP` | allow an `http`-scheme `endpoint_url` at create (dev only; default `false`) |

See `docs/configuration_properties.md` for the full catalogue.

## Related

- `docs/specs/draft-hunt-secevent-sstp-00.txt` — the source spec.
- ADR 0018 — one bidirectional `StreamStateRecord` per pair.
- ADR 0019 — the create bootstrap DTO + peer cascade.
- ADR 0020 — delete: local proceeds, `cascade_peer` opt-in, 207 partial.
- `docs/Cluster.md` — `sstp-client` lease + wake-up endpoints.
- `docs/security_model.md` — pair bearer / `StreamIds[]` / `FindByPairId`.
- `docs/Metrics.md` — `tfr=SSTP` counter label.

---

<!-- gosignals-brand-footer -->
<p align="center"><sub>(C)2026 Independent Identity Inc.</sub></p>
