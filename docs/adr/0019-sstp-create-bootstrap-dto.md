<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 19. SSTP create bootstrap DTO

Date: 2026-06-07

## Status

Accepted

## Context

ADR 0018 settled the storage shape for an SSTP pair: one bidirectional
`StreamStateRecord` per node, with a transmit-side `StreamConfiguration` (the
primary), a receive-side `SstpInbound`, pair-scoped connectivity in `SstpMethod`,
and a `PairId` that is the on-wire SSF `stream_id`. What it did not settle is the
*create API*: how an operator (or `cmd/goSignals`, or goSignalsAdmin) asks a node
to provision that bidirectional record, and how the two nodes of a pair get
provisioned with one command.

The existing `POST /stream` body is an SSF-flavoured `StreamConfiguration` (wrapped
in a `StreamStateRecord` so goSignals operator knobs ride alongside without
leaking into the SSF wire shape). That body describes exactly one direction. An
SSTP pair needs two directions plus pair-level connectivity, and several of its
fields are *derived* rather than operator-supplied:

- The responder is the HTTP server, so it must derive its own `EndpointUrl`
  (`/sstp/<PairId>`) and mint its own bearer — an operator-supplied value on the
  responder is a copy-paste hazard at best and an injection vector at worst.
- The initiator is the HTTP client; it receives the bearer the responder minted,
  so on the initiator the operator *must* supply it.
- `iss`/`aud` are not derivable from goSignals' own identity. For FORWARD and
  multi-hop routing the issuer is an upstream party, so iss/aud are
  business-plane inputs that ride per direction.

Reusing `StreamConfiguration` for this would mean overloading its fields with
SSTP-specific meaning and pushing the derive-vs-supply asymmetry into per-field
conditionals on a type that four other delivery methods already share. It would
also give us nowhere clean to express "provision both nodes in one call."

## Decision

`POST /stream` accepts a **second body shape, `SstpPairBootstrap`,
discriminated on shape** alongside the existing `StreamConfiguration`. A body is
an SSTP bootstrap when it carries a top-level `role` of `initiator`/`responder`
together with at least one per-direction `primary`/`inbound` object — none of
which appear on a `StreamConfiguration`. The discriminator
(`model.IsSstpBootstrapBody`) returns false for a malformed body so the caller
falls through to the `StreamConfiguration` path and reports its error there.

The DTO carries pair-level connectivity plus per-direction business-plane inputs:

- Pair-level: `role`, `endpoint_url`, `authorization_header`,
  `peer_server_alias`, `peer_pair_id`, `description`.
- Per direction (`primary` = transmit, `inbound` = receive): `iss`,
  `iss_jwks_url`, `aud`, `events`, `mode`. `mode` accepts
  `FORWARD | PUBLISH | IMPORT` and maps to the existing `RouteMode`
  (`SstpModeToRouteMode`): `FORWARD` preserves the upstream `iss`, `PUBLISH`
  re-signs with goSignals' `iss`, `IMPORT` keeps events local.

`StreamService.CreateSstpPair` expands a validated bootstrap into the bidirectional
record described by ADR 0018:

- `PairId` is a fresh `bson.NewObjectID().Hex()`; it is aliased to the transmit-side
  `StreamConfiguration.Id` and to the Mongo `_id` (the ADR-0018 aliasing
  invariant). The inbound side gets its own fresh SID.
- `Role` is **required, with no default** — the easy "both peers responder"
  misconfiguration is rejected at create.
- **Responder**: server-derives `EndpointUrl` via `getFullUrl(/sstp/<PairId>)`
  and server-mints the per-pair bearer (`IssueSstpPairToken`, covering both
  SIDs). An operator-supplied `endpoint_url` or `authorization_header` on a
  responder is rejected.
- **Initiator**: the operator must supply `authorization_header` (the peer
  responder minted it); `endpoint_url` is operator-supplied or learned via the
  cascade response.
- `EndpointUrl` is validated **syntactically only** — `url.Parse`, scheme `https`
  (or `http` when `I2SIG_INSECURE_SSTP_HTTP=true`, a new env var defaulting to
  false), non-empty host, no query or fragment. No network probe; reachability
  is the runner's concern, matching push/poll create semantics.
- Each half is validated for a non-empty, URI-shaped `iss` and `aud` and a
  recognized `mode`. **No reciprocity is enforced between halves** so asymmetric
  multi-hop pairs are legitimate. `events` is accepted loosely (no URI-registry
  check, empty allowed); `EventsDelivered` is recomputed. `Status` is always
  `Enabled` at create — the runner self-pauses on first failure.

When `peer_server_alias` is present, the service **cascades the mirrored
bootstrap to the peer** using the stored `Server` credentials, fetching the
peer's `configuration_endpoint` from its well-known SSF configuration. The mirror
flips the role (initiator↔responder) and swaps the two directions, so the peer's
`primary` is this node's `inbound`. A responder-originated cascade hands the peer
the responder's endpoint and bearer; an initiator-originated cascade lets the peer
responder derive its own. On success the local record records the peer's
`PairId` in `SstpMethod.PeerPairId`.

The rollback policy is **role-asymmetric**, reusing the existing intentional
asymmetry between ReceivePush and ReceivePoll auto-registration:

- **Responder** writes its local row first, then cascades; a cascade failure
  rolls the local row back (ReceivePush-style).
- **Initiator** cascades first; because no local row exists until the peer
  returns, a cascade failure writes nothing — there is nothing to roll back
  (ReceivePoll-style).

Omitting `peer_server_alias` provisions only the local half; peer connectivity is
patched later via UPDATE (slice #162).

## Consequences

### Positive

- **One create surface, two shapes.** Operators and goSignalsAdmin keep posting
  to `POST /stream`; the discriminator routes SSTP bodies without a new endpoint.
- **Derive-vs-supply asymmetry is explicit and enforced.** The responder cannot
  be handed an endpoint or bearer; the initiator cannot omit its bearer. The
  "both responder" footgun is impossible.
- **Single-command pair bootstrap.** `peer_server_alias` + the stored `Server`
  credential cascades the mirror, so one call on either side provisions both
  nodes, reusing the foreign-server provisioning path SSTP already depends on.
- **Asymmetric pairs are first-class.** iss/aud per direction with no reciprocity
  check supports FORWARD and multi-hop routing.
- **Create semantics match push/poll.** Syntactic-only `EndpointUrl` validation
  and always-`Enabled` status keep the lifecycle identical to the existing
  methods; the runner owns reachability and self-pausing.

### Negative

- A second body shape on `POST /stream` adds a discrimination step and a parallel
  expansion path to maintain. Mitigated by keeping the discriminator a small pure
  function and the expansion in one cohesive `CreateSstpPair`.
- The mirror logic (role flip + direction swap) is subtle; a wrong swap would
  cross-wire the pair. Covered by the cascade test asserting the mirrored shape
  the peer receives.
- The responder persists, then cascades, then re-persists the learned
  `PeerPairId` — two writes on the happy path. Acceptable: the second write is a
  single-document update and the alternative (deferring the local write until
  after the cascade) would lose the ReceivePush-style rollback symmetry.

## Related

- PRD #154 — SSTP as a third delivery method (Q27, Q28, Q29, Q30, Q31, Q33, Q34,
  Q44, Q48).
- Issue #161 — `SstpPairBootstrap` DTO + `CreateStream` discriminator (this ADR).
- ADR 0018 — the bidirectional `StreamStateRecord` this DTO expands into.
- ADR 0009 — foreign-server provisioning requires admin; the `Server`-alias
  credential path the cascade reuses.
- ADR 0011 — environment-variable taxonomy; `I2SIG_INSECURE_SSTP_HTTP` follows it.
- `pkg/ssfModels/model_sstp_pair_bootstrap.go`,
  `internal/services/stream_service_sstp.go`, draft-hunt-secevent-sstp-00.
