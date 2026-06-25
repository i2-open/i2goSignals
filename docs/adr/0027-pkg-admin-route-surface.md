<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 27. A pkg/-importable admin-route surface for enterprise REST coexistence

Date: 2026-06-24

## Status

Accepted (GH #215).
Builds on ADR 0021 (lift `internal/services` to `pkg/services` — the public service
handles this surface is assembled from) and is a sibling of the delivery seam
(ADR 0010 provider decomposition / the `PushDelivery` seam): both expose a narrow,
caller-owned injection point so an out-of-tree consumer can reuse the gateway's
behavior without dragging the cluster/storage runtime in.

## Context

The community goSignals strategic gateway (`cmd/goSignalsServer`, the
`internal/server` handler tree behind `*SignalsApplication` + `routers.go`) owns
the REST admin surface: stream / server / key / issuer CRUD plus the
subject-management family. That surface lives entirely under `internal/`, so an
external Go module cannot mount it.

The enterprise REST-coexistence binary (`I2SIG_REST_ADMIN=on`, enterprise #76,
PRD `i2goSignalsAdmin#164`) must register the **community** REST admin handler
families and omit them (route-not-registered 404) when off — and per enterprise
ADR 0009/0042 it must **reuse** the community handlers, not re-implement them.
Re-implementation would fork the admin contract: two copies of stream-create
validation, subject-filter relay, rotate-on-GET, drifting over time exactly as
the receiver-stream predicate drifted between DAO adapters before PRD #39.

ADR 0021 already lifted the service layer to `pkg/services`, so the building
blocks an admin handler needs (`StreamService`, `KeyService`, `ServerService`,
`TokenService`, `SubjectFilterService`, `SubjectRelayService`, the
`authSupport.AuthIssuer`) are public. What was still trapped under `internal/`
was the *binding* of those services to the admin HTTP handlers and the route
table. The handlers also reach two collaborators an external mount cannot supply
from public inputs: the `eventRouter.EventRouter` (the stream-mutation handlers
call `UpdateStreamState`/`RemoveStream`; `handleSubjectChange` additionally calls
`NotifySubjectFilterChange`) and — for HYBRID/PASSTHRU subject relay — the
already-public `*services.SubjectRelayService`. The full peer/event/cluster plane
(`/.well-known/*`, `/health`, OAuth, event delivery, bootstrap) needs the
event/cluster/storage seam and is out of scope; enterprise serves its own.

## Decision

Add a community `pkg/goSignalsServer` wrapper that exposes the admin-route subset
as a `pkg/`-importable handler set an external module mounts on its own
`*mux.Router`. The handler bodies stay in `internal/server` and are reused
byte-identically; only the way the application they run against is constructed
changes.

1. **Admin/peer route split** (`internal/server/routers.go`). `getRoutes()` is
   partitioned into `peerRoutes()` (the always-on Q16 exclusion list) and
   `adminRoutes()` (the 22-route admin family), with `getRoutes()` their pure
   union. `(*SignalsApplication).AdminRouteTable()` returns the admin Routes bound
   to a given application's handler methods. Membership is pinned by
   `internal/server/routers_split_test.go#TestAdminRoutesMembership`, so a future
   edit cannot silently reclassify a route across the seam.

2. **A reduced admin application** (`internal/server/admin_surface.go`).
   `NewAdminApplication(AdminAppDeps)` assembles a `*SignalsApplication` from
   PUBLIC service handles only — no `dbProviders.Persistence`, no background sync,
   no cluster server, no live receivers. The receiver-bookkeeping maps are
   initialized so the StreamDelete cascade is safe (no live receivers ⇒ inert).

3. **A 3-method `StreamStateSink`** (`UpdateStreamState`, `RemoveStream`,
   `NotifySubjectFilterChange`) — the exact router surface the admin family
   touches, audited against the handler call sites. The wrapper injects a
   caller-supplied sink via `adminRouterAdapter`, which adapts the 3 methods up to
   the full `eventRouter.EventRouter` interface and panics on the other ~17
   methods (a guardrail: they belong to the peer/event plane and can only be
   reached if a non-admin route were ever bound onto an admin application by
   mistake). The in-binary gateway passes its real `*eventRouter.EventRouter`,
   which already satisfies the narrow sink — so wiring through the sink does not
   change gateway behavior.

4. **`*services.SubjectRelayService` injected directly**, not folded into the
   sink: the subject-management handler drives HYBRID/PASSTHRU upstream relay
   through it, and it is already `pkg/`-public (ADR 0021), so no new lift.

5. **The public wrapper** (`pkg/goSignalsServer/admin_surface.go`):
   `NewAdminSurface(AdminSurfaceConfig) *AdminSurface` taking only `pkg/`-exported
   handles, and `(*AdminSurface).AdminRoutes() Routes`. An external caller builds
   the public services (`pkg/services` over `pkg/dao`), supplies a
   `StreamStateSink`, and mounts `AdminRoutes()`; omitting them leaves the paths
   unregistered (404) — the registration toggle the enterprise REST-admin flag
   relies on. The caller wraps the handlers for auth/audit; the surface itself
   does not impose middleware (each handler validates the bearer inline against
   the injected `AuthIssuer`).

The contract names — `pkg/goSignalsServer`, `NewAdminSurface`,
`AdminSurfaceConfig`, `StreamStateSink`, `AdminRoutes() Routes`, the 22-route
admin family — are pinned; neither side renames them unilaterally (the #215 ⇄ #76
contract handshake).

## Considered alternatives

- **Full lift of the `internal/server` admin handlers into `pkg/` (option A).**
  Cleaner long-term, but a large mechanical move with broad blast radius across
  the handler tree, and it would have to lift or re-home the application object
  too. Deferred; this wrapper keeps the handlers in place and reuses them.
- **Stub the full 20-method `eventRouter.EventRouter` for the caller to
  implement.** Forces every external consumer to implement (or no-op) 17 methods
  that the admin family never calls — noise that also hides which methods the
  admin surface actually depends on. Rejected in favor of the narrow 3-method
  sink the route audit proved sufficient.
- **Re-implement the admin handlers in enterprise.** Forks the admin contract
  (validation, relay, rotate-on-GET) into two drifting copies — exactly what
  enterprise ADR 0009/0042 says to avoid. Rejected.
- **Expose the surface through `pkg/goSsfServer`.** That package is the test-only
  SSF simulator, not the strategic gateway; reusing its name would also collide
  with the `i2goSignalsAdmin` project. A dedicated `pkg/goSignalsServer` follows
  the same `internal/server`-import-within-the-module precedent without the name
  clash.

## Consequences

**Positive**

- The enterprise REST-coexistence binary mounts the community admin routes from
  public inputs, behind one flag, with byte-identical handler behavior — reuse,
  not re-implementation. No `internal/` import is required of the external caller
  (proven by `pkg/goSignalsServer/admin_surface_test.go`, an external
  `goSignalsServer_test` package importing only `pkg/...`).
- The admin/peer split is a pure partition guarded by tests, so the seam cannot
  silently drift.
- The 3-method sink documents, and the route-audit test pins, exactly which
  router transitions the admin family emits; the caller forwards just those into
  its own control-stream/event state.
- The peer/event/cluster plane stays out of the public surface — enterprise
  serves it itself, flag-independently — so the export does not leak the
  storage/cluster seam.

**Negative / accepted trade-offs**

- `pkg/goSignalsServer` imports `internal/server` within the module (the
  `pkg/goSsfServer` precedent) — a deliberate, scoped `pkg → internal` edge that
  the ADR 0021 CI boundary gate does not cover (the gate is scoped to
  `pkg/services`, `pkg/dao`, `pkg/authSupport`). The external *caller* still needs
  no `internal/` import; the edge is internal to the wrapper.
- The reduced admin application is a second construction path for
  `*SignalsApplication` alongside `NewApplication`; the `adminRouterAdapter`'s
  panic-on-unsupported guardrail is the safety net that keeps a mis-bound
  non-admin route from silently no-oping.

## Related

- GH #215 — this surface (community side); enterprise #76 — the consumer.
- PRD `i2goSignalsAdmin#164` — the admin-UI / REST-coexistence parent.
- ADR 0021 — lift `internal/services` to `pkg/services` (the public handles this
  surface is built from).
- ADR 0010 — provider decomposition / the `PushDelivery` seam (sibling
  caller-owned injection point).
- ADR 0009 (enterprise) / ADR 0042 (enterprise) — REST coexistence must reuse
  community handlers and pin the community module by SHA/tag.
- `internal/server/routers.go` — `peerRoutes()` / `adminRoutes()` /
  `AdminRouteTable()`.
- `internal/server/admin_surface.go` — `NewAdminApplication`,
  `AdminStreamStateSink`, `adminRouterAdapter`.
- `pkg/goSignalsServer/admin_surface.go` — `NewAdminSurface`,
  `AdminSurfaceConfig`, `StreamStateSink`, `AdminRoutes`.
- `internal/server/routers_split_test.go`,
  `pkg/goSignalsServer/admin_surface_test.go` — the partition and external-consumer
  pins.
