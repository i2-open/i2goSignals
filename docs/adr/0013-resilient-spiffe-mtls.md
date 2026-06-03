<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 13. Resilient SPIFFE mTLS — dual-validation client, dual-certificate server

Date: 2026-04-10

## Status

Accepted

## Context

Strict SPIFFE ID validation (`tlsconfig.AuthorizeMemberOf(td)` in
`NewClusterMTLSClientConfig`) was too narrow for a cluster that is only
partially in the SPIRE mesh:

- **External endpoints** (JWKS loaders, public HTTPS APIs) have no SPIFFE SVID
  and were rejected.
- **Legacy nodes** not yet in the SPIRE mesh were rejected.
- On the server side, **legacy/Java clients** doing strict hostname verification
  failed against goSignals, because the SPIFFE SVID it presents often lacks the
  DNS SANs (e.g. `goSignals1`) those clients require — especially without SNI.

## Decision

A two-sided "resilient / dual" strategy that lets SPIFFE-meshed peers,
file-cert-only nodes, and plain external HTTPS all interoperate over the same
endpoints.

**Client — `NewResilientMTLSClientConfig` (dual-validation).** Extract a SPIFFE
ID from the peer certificate; if it belongs to the cluster trust domain,
validate it against the SPIRE trust bundle. Otherwise fall back to standard
X.509 verification (hostname + chain) against the combined Root CA pool (system
+ global CA + SPIRE bundle). Internal `http.Client` instances and database
providers MUST use the resilient config when SPIFFE is enabled, and the
`VerifyConnection` callback MUST NOT return `nil` without performing either a
valid SPIFFE check or a valid hostname check.

**Server — `GetCertificate` (dual-certificate selection).** On SNI, try to match
the name against the SPIFFE SVID first, then the file-based certificate. With no
SNI or no match, prefer the **file-based certificate** as the default — it is
signed by the global CA and carries all the DNS SANs legacy hostname-checking
clients need. SPIFFE-aware peers receiving the file cert handle it via the
resilient client fallback (standard X.509 against the combined pool).

## Consequences

**Positive**

- One TLS posture serves the internal SPIFFE mesh, external HTTPS endpoints, and
  file-cert-only legacy nodes without per-peer special-casing.

**Negative**

- The server must be configured with both `TLS_ENABLED=true` and
  `SPIFFE_ENDPOINT_SOCKET` for the dual-certificate behaviour, and the file-based
  certificate MUST carry the hostnames (DNS SANs) used by legacy clients.

## Related

- `docs/security_model.md`, `docs/spiffe_support.md`.
- The operational SPIRE-agent self-healing, MongoDB certificate-rotation, and
  cluster-monitor alignment fixes from the same period are runbook material and
  live in git history, not as ADRs.
