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

## Update (2026-05-16): Grafana is SSO-only — local password form disabled

Issue #78 originally kept Grafana's local `admin/grafana` username/password form
enabled as a break-glass fallback alongside Keycloak SSO. That fallback is
removed: every compose stack now sets `GF_AUTH_DISABLE_LOGIN_FORM=true`, so the
`gosignals` realm is the only interactive login path (the generic-OAuth button
reads **Sign in with GoSignals Realm**). The TLS + SSO configuration (cert mount,
HTTPS, generic-OAuth env block) is applied uniformly to all six compose files;
the three that #78 left unconfigured would otherwise fail Grafana datasource
provisioning against the shared `config/monitor/grafana/datasource.yml`.

- **API Basic Auth is deliberately *not* disabled.** `GF_AUTH_DISABLE_LOGIN_FORM`
  removes only the interactive UI form; Grafana's API Basic Auth is a separate
  setting and stays on, so `scripts/verify-observability.sh` (`-u admin:grafana`)
  can still inspect `/api/datasources` without driving a full OIDC flow.
- **Invariant:** a `POST /login` to Grafana with otherwise-valid credentials MUST
  NOT return `200` — asserted by `scripts/verify-observability.sh` section 14.

---

<!-- gosignals-brand-footer -->
<p align="center"><sub>(C)2026 Independent Identity Inc.</sub></p>
