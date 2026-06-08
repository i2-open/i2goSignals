<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# Architecture Decision Records

This directory is the canonical home for i2goSignals design decisions. Each ADR
records one non-trivial decision — its context, what was decided, and the
consequences — so the rationale survives and the same fix or regression is not
re-attempted. (It replaces the old append-only `DECISIONS_LOG.md`; routine bug
fixes now live in git history, not here.)

## When to write an ADR

Write one for non-trivial architecture, or a dependency or definition
requirement that should be remembered. A routine bug fix does not need an ADR —
git history is enough.

## Convention

- **Filename:** `NNNN-kebab-case-title.md`, where `NNNN` is the next sequential
  number.
- **Header:** the shared brand hero `<picture>` block (see any existing ADR).
- **Body:** `# N. Title`, then `Date:`, then `## Status` (Accepted / Superseded /
  …), `## Context`, `## Decision`, `## Consequences` (Positive / Negative), and
  `## Related` (links to sibling ADRs, issues, and the operator-facing docs).
- A decision that revises an earlier one either supersedes it (mark the old one
  `Superseded by NNNN`) or is folded in as a dated `## Update` section when it is
  a refinement rather than a reversal.

All ADRs below are **Accepted** unless noted.

## Index

| # | Title | Summary |
|---|-------|---------|
| [0001](0001-per-service-keycloak-clients.md) | Per-service Keycloak clients with client roles | Each realm-authenticated service gets its own client + client roles; realm roles stay for cross-cutting identity. (Incl. Grafana SSO-only update.) |
| [0002](0002-subject-filtering-at-delivery-time.md) | Subject filtering applied at delivery time, not routing time | The §8.1.3 filter is consulted when a stream's buffer drains, pinned to the lease owner — not at ingest-time routing. |
| [0003](0003-split-subject-filter-storage.md) | Subject filter storage and matching at scale | Filters split by subject kind: simple subjects hash-indexed (O(1)), complex linear-scanned; results cached short-TTL. |
| [0004](0004-event-source-type.md) | Event-source Type as a transmitter declaration | `event_source.type` (DIRECT/AUDIENCE/EXPLICIT) is a config-time guard; `source_stream_ids` is the runtime relay-target witness. |
| [0005](0005-delegated-cli-authentication-rfc9728.md) | Delegated CLI authentication via RFC 9728 (no built-in AS) | The CLI delegates auth to an external OIDC AS discovered via RFC 9728 PRM; goSignals ships no authorization server. |
| [0006](0006-key-scope-and-closing-anonymous-iat.md) | The `key` scope and closing anonymous `/iat` | Closes anonymous `/iat`; adds the narrow `key` scope and a bootstrap-secret grant for unattended deployments. |
| [0007](0007-track-token-redemption-not-issuance.md) | Track token redemption, not issuance | Record where a token is *used* (redemption / last-seen IP), not where it was minted. |
| [0008](0008-two-revocation-endpoints.md) | Two revocation endpoints: RFC 7009 `/revoke` and `DELETE /token/{jti}` | Holders revoke by token string (RFC 7009); admins revoke by JTI from the management table. |
| [0009](0009-foreign-server-provisioning-requires-admin.md) | Foreign-server provisioning requires admin scope | `/server` CRUD and `tx_alias` stream-create are `admin`-only; plain local stream-create is unchanged. |
| [0010](0010-provider-decomposition.md) | Provider decomposition — the god-interface and god-object are retired | `DbProviderInterface`/`BaseProvider` deleted; per-domain services + `ClusterCoordinator` + `Storage` seams, string IDs, rebindable Mongo collections. |
| [0011](0011-environment-variable-taxonomy.md) | Environment-variable taxonomy (`I2SIG_<AREA>_*`) | Every server knob renamed under `I2SIG_<AREA>_*`; `envcompat` shim keeps old names working with a deprecation WARN. |
| [0012](0012-scope-checks-via-hasscope-not-eat.md) | Authorization scope checks read shape-aware predicates, not `AuthContext.Eat` | Scope-check via `HasScope`/`IsAuthorizedForStream` (Eat is nil for OAuth); OAuth callers gated on `admin`; OAuth bearer validation hardened. |
| [0013](0013-resilient-spiffe-mtls.md) | Resilient SPIFFE mTLS — dual-validation client, dual-certificate server | SPIFFE-meshed peers, file-cert-only nodes, and plain external HTTPS interoperate over the same endpoints. |
| [0014](0014-configurable-long-poll-timeouts.md) | Configurable long-poll default and inbound max timeout | `I2SIG_POLL_DEFAULT_TIMEOUT`/`_MAX_TIMEOUT` default + cap (silent clamp, RFC 8936-compliant) defend poll-stream resources. |
| [0015](0015-stream-remote-address-tracking.md) | Stream `remote_address` tracking | Last-seen peer IP captured post-auth for all four delivery modes; informational only, feeds the token-redemption view. |
| [0016](0016-subject-filter-relay-and-grace.md) | Subject-filter relay modes, §9.3 removal grace, and anti-oracle posture | PASSTHRU/HYBRID/LOCAL relay semantics, grace-aware HYBRID relay, and no subject-existence oracle on the endpoints. |
| [0017](0017-jti-is-the-event-dedup-key.md) | JTI is the event dedup key | `eventCol.jti` becomes the persistence-layer dedup key (sparse-unique in Mongo, map check in memory); duplicates surface as `interfaces.ErrDuplicateJTI` and the router short-circuits. |
| [0018](0018-bidirectional-pair-record.md) | One bidirectional StreamStateRecord per SSTP pair | An SSTP pair is a single record carrying both directions (`SstpInbound` for receive, `SstpMethod` for connectivity, `PairId` as the wire SID); marker-only delivery keeps secrets off the wire; `FindByInboundSID`/`FindByPairId` ride sparse-unique indexes. |
| [0019](0019-sstp-create-bootstrap-dto.md) | SSTP create bootstrap DTO | `POST /stream` accepts an `SstpPairBootstrap` body (discriminated on shape) and expands it server-side into the bidirectional record; responder server-derives endpoint + mints bearer, initiator supplies bearer; iss/aud ride the business plane; TxAlias cascade mirrors the bootstrap to the peer with role-asymmetric rollback. |
| [0020](0020-pair-delete-local-proceeds-cascade-peer-opt-in.md) | Pair delete: local proceeds, cascade_peer opt-in, 207 partial | SSTP pair delete always removes the local row regardless of peer reachability; `?cascade_peer=true` opts into a courtesy peer `DELETE` via stored `Server` credentials; a peer failure after local success is a 207 Multi-Status with per-side outcomes, never a failed local delete. UPDATE keeps `Role`/already-set endpoint/IDs immutable so delete is the only sanctioned peer-rebind. |
