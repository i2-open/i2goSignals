<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 21. Lift internal/services to pkg/services

Date: 2026-06-08

## Status

Accepted

## Context

The service layer (`internal/services/` — stream, key, event, server, token,
client, and subject-filter services) was the last large unit of reusable
business logic still trapped under `internal/`, so no out-of-tree consumer
could build a SET router on top of it. PRD #175 lifts it to `pkg/services` so
the service API becomes a stable, importable surface.

The lift was sequenced behind four prerequisite slices that made the transitive
dependencies public and decoupled the services from environment glue:

- #176 — `dao/ids` → `pkg/dao/ids`.
- #177 — `dao/interfaces` → `pkg/dao` (package `dao`; many callers alias it
  `interfaces "…/pkg/dao"`).
- #178 — `authUtil` → `pkg/authSupport` (`AuthIssuer` gained an
  `OAuthServersLookup` func field).
- #179 — services decoupled from `internal/envcompat` and from
  `internal/dao/memory` *in production*; constructors now take `pkg/dao`
  interfaces plus config structs.

After #176–#179 the only remaining `pkg → internal` edge from a moved service
file was in the **test** files: 16 of the service `_test.go` files build their
fixtures with `internal/dao/memory` (`memory.NewStreamDAO()`,
`memory.NewKeyDAO()`, …). Moving those tests to `pkg/services` unchanged would
make them illegal `pkg → internal` importers.

PRD #175 had originally intended `internal/dao/memory` to stay internal. That
intent is in tension with the invariance gate for this slice — the service
tests travel as-is, and they need the memory DAO.

## Decision

`internal/services/` is relocated wholesale to `pkg/services/` via `git mv`
(history preserved; `git log --follow` traces every file back). The package name
becomes `services` at the new path. The exported API is identical to the old
`internal/services` — no signature changes beyond those #179 already made. All
~21 caller files (eventRouter, server handlers, both providers, server test
helpers) are migrated by mechanical import-path rewrite, and the pre-existing
`pkg → internal/services` boundary violation in
`pkg/goSsfServer/ssf-application.go` is healed in the same pass.

**Deviation from PRD #175 (recorded deliberately):** `internal/dao/memory` is
*also* lifted to `pkg/dao/memory`, contrary to PRD #175's stated intent to keep
the memory DAO internal. Rationale:

- The 16 lifted service test files build their fixtures with the memory DAO. The
  invariance gate requires those tests to travel with only import-path/package
  rewrites; keeping the memory DAO internal would force a non-mechanical rewrite
  of every fixture (a new public test double, or a relocation of the tests) —
  exactly the kind of behavioural change this slice is meant to avoid.
- `internal/dao/memory` has **zero** `internal/*` dependencies (verified), so the
  lift is clean: it imports only public packages (`pkg/dao` interfaces,
  `pkg/dao/ids`, `pkg/ssfModels`, …).
- A public, file-backed in-memory DAO is independently useful as a reusable test
  double for the now-public service API — the same consumers that can import
  `pkg/services` can wire it against `pkg/dao/memory` without standing up Mongo.
- `internal/dao/mongo` does **not** import `memory` and stays exactly where it is
  (internal). The parity tests at `internal/dao/token_parity_test.go` remain
  internal; only their `memory` import path is rewritten.

A **scoped** CI boundary gate is added to `.github/workflows/ci.yml`: a grep step
that fails if any `*.go` under `pkg/services`, `pkg/dao` (including `pkg/dao/ids`
and `pkg/dao/memory`), or `pkg/authSupport` imports
`github.com/i2-open/i2goSignals/internal/`. The gate is intentionally scoped to
the PRD-cleaned packages — the repo still carries pre-existing, out-of-scope
`pkg → internal` violations (`pkg/nodeid`, `pkg/tlsSupport`, `pkg/oauthClient`,
and some `pkg/goSsfServer` tests) that a blanket gate would falsely fail.

## Consequences

### Positive

- The service layer is a public, importable API; an out-of-tree consumer can now
  build on the stream/key/event/server/token/client/subject-filter services.
- `pkg/dao/memory` is a public, Mongo-free test double for that API.
- `pkg/goSsfServer` no longer reaches into `internal/services` — one fewer
  boundary violation in the tree.
- The scoped CI gate makes the cleaned boundary self-enforcing: a future
  `pkg → internal` regression in these packages fails CI rather than silently
  re-accreting.

### Negative

- The memory DAO is now public surface area to maintain, a deliberate deviation
  from PRD #175's original "memory stays internal." Accepted for the test-fixture
  and reusable-double reasons above.
- The CI gate is scoped, not blanket; the remaining out-of-scope
  `pkg → internal` violations are not yet addressed and are not gated.

## Related

- PRD #175 — Lift internal/services to pkg/services.
- Issues #176, #177, #178, #179 — prerequisite lifts/decoupling (all merged on
  the release-0.12.0 branch).
- Issue #180 — this capstone lift.
- ADR 0010 (provider decomposition) — the DAO seam these services ride on.
- ADR 0017 (JTI dedup) — references the pre-lift `internal/services` /
  `internal/dao/memory` paths in its narrative.
