<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# goSignalsServer

This package exposes the community goSignals strategic gateway's REST **admin**
route surface (stream / server / key / issuer CRUD plus subject management) as a
`pkg/`-importable handler set that an external Go module can mount onto its own
`*mux.Router`.

It is the community-side enabler for the enterprise REST-coexistence binary
(GH #215, PRD i2goSignalsAdmin#164): the enterprise admin REUSES the community
admin handlers — byte-identical behavior — rather than re-implementing them, and
toggles their registration behind a runtime flag.

Usage:
* Build the public services (`pkg/services` over `pkg/dao`) — no `internal/`
  import is required of the caller.
* Implement a `StreamStateSink` (`UpdateStreamState` / `RemoveStream` /
  `NotifySubjectFilterChange`) and construct (or inject) a
  `*services.SubjectRelayService`.
* Call `NewAdminSurface(AdminSurfaceConfig{...})` and mount `AdminRoutes()`;
  omitting them leaves the paths unregistered (route-not-registered 404) — the
  flag-off behavior.

This package does NOT export the always-on peer plane (`/.well-known/*`,
`/health`, OAuth, event delivery, bootstrap): those require the
event/cluster/storage seam and are served by the binary directly. See
[`docs/adr/0027-pkg-admin-route-surface.md`](../../docs/adr/0027-pkg-admin-route-surface.md).

---

<!-- gosignals-brand-footer -->
<p align="center"><sub>(C)2026 Independent Identity Inc.</sub></p>
