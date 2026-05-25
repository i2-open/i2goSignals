<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# Per-service Keycloak clients with client roles

When adding Grafana SSO to the `gosignals` Keycloak realm, we gave Grafana its
own confidential OAuth client (`grafana`) with **client roles**
(`admin`/`editor`/`viewer`, surfaced as `resource_access.grafana.roles`) rather
than mapping Grafana's authorization off the realm-wide `admin`/`user` roles.
This establishes the pattern for every service that authenticates against the
realm: each gets its own client, and per-service authorization lives in that
client's roles, so a single user account can hold different privilege levels in
different services (e.g. Grafana-admin but goSignals-viewer). Realm roles stay
reserved for genuinely cross-cutting identity.

## Considered options

- **Reuse realm `admin`/`user` roles for Grafana** — rejected: it conflates
  Grafana access with goSignals API access, so a future reader sees the realm
  roles and wonders why Grafana ignores them, and you cannot grant a user
  Grafana access without also granting the coarse realm role.
- **Reuse the `goSignals*Role` roles** — rejected: those model goSignals API
  scopes (streams, events), and overloading them onto Grafana mixes two
  authorization domains.

## Consequences

- Each new realm-authenticated service repeats this shape: its own confidential
  client + client roles. Keycloak's built-in `roles` client scope emits
  `resource_access.<client>.roles` automatically, so no custom protocol mapper
  is required.
- TLS posture note (recorded here rather than as a separate ADR): inter-container
  traffic uses **server-side TLS only**, verified against the local dev CA.
  Mutual TLS remains scoped to the existing SPIFFE inter-cluster path; it was
  not extended to the observability/web tier because, on a single-host bridge
  network, it adds fiddly client-cert configuration for little gain.

---

<!-- gosignals-brand-footer -->
<p align="center"><sub>(C)2026 Independent Identity Inc.</sub></p>
