# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

`i2goSignals` is a Go-based Security Event Token (SET) router/gateway implementing the OpenID Shared Signals Framework (SSF). It bridges SET transmitters and receivers across protocols and domains, persists streams/events in MongoDB, and runs as a horizontally scaled cluster coordinated by MongoDB-backed leases.

The project must remain compatible with these standards (see `.junie/guidelines.md` and `.claude/CLAUDE.md` for the exhaustive list):
RFC8417 (SET), RFC8935 (push delivery), RFC8936 (poll delivery), the OpenID SSF spec, and the SCIM/RISC/CAEP event-type profiles.

## Build, test, run

The Makefile is the primary entry point. `go` commands also work directly.

```bash
make build              # check-certs + console-build + server-build + docker-build
make console-build      # builds cmd/goSignals (CLI)
make server-build       # builds cmd/goSignalsServer -> bin/goSignalsServer
make generate-certs     # runs cmd/genTlsKeys (auto-invoked by check-certs if missing)
make clean              # remove bin/, top-level binaries, dev volumes

# Dev stack with Delve debugger on ports 2345-2347
make dev-build-image    # build image used by docker-compose-dev
make dev-up             # docker compose -f docker-compose-dev.yml up -d
make dev-rebuild        # rebuild + restart goSignals1, goSignals2, goSsfServer
make dev-logs           # follow goSignals1 logs
make dev-down           # stop the dev stack
make dev-clean          # down -v + clean-scim (wipes mongo + scim configs)

# Variants
make run                # build + bring up docker-compose.yml demo cluster
make run-spiffe-demo    # SPIFFE/SPIRE-enabled compose stack
make dev-reset-spiffe   # full SPIFFE dev stack reset (down -v, clean, up)
```

Docker images are built via `sh ./build.sh -n <tag>` (multi-arch with `-m`). `docker-build` is part of `make build`, so a full `make build` requires Docker.

### Tests

```bash
go test ./...                                   # everything
go test -race ./...                             # required when touching concurrent code
go test ./internal/services/...                 # one package
go test -run TestStreamServiceRegistration ./internal/services/...  # one test
go test -v -run TestPollRecovery ./pkg/goSignals/server/...
```

Integration tests use `github.com/stretchr/testify/suite`. Race-tested code should still complete within ~5 minutes — tune timeouts/lock detection accordingly. Some tests (notably under `pkg/goSignals/server`) spin up a full server and Mongo provider; they're slower than pure unit tests.

## Planning vs Implementation

When asked for a plan or design exploration, do NOT begin implementing code until I explicitly approve. Produce the plan first and wait for confirmation.

## Commit Hygiene

Never include unrelated whitespace/formatting reformats in a commit. Verify the diff is scoped to the intended change before committing.

## Design & Grilling

During grilling/design interviews, ground each recommendation in the codebase and avoid overspecifying requirements (e.g., persistence, dedup, dual-write). Confirm assumptions before treating them as decided.

## TDD & Slicing

Before doing TDD slices, write tests first and run the full gate suite before marking ready-for-review; verify scope matches the issue.

## Architecture (the parts you need to read multiple files to understand)

### Two binaries, one library

- `cmd/goSignalsServer` — the SSF server. Wires HTTP routers (`pkg/goSignals/server/routers.go`) on top of an `EventRouter`, a `DbProviderInterface`, and an `application` lifecycle (`pkg/goSignals/server/application.go`). Most HTTP handlers live in `pkg/goSignals/server/api_*.go` (transmitter, receiver, stream management, cluster, verify, out_of_band).
- `cmd/goSignals` — the admin CLI. Talks to the server's management APIs.
- `pkg/goSet`, `pkg/goSetPush`, `pkg/goSetPoll` — protocol libraries that know nothing about `internal/`. They handle SET creation/parsing and the RFC8935/RFC8936 wire formats. Server and CLI both use them.

Other `cmd/` binaries are tools: `cluster-monitor`, `genTlsKeys`, `healthcheck`, `metrics`, `generator`, `testUrl`, `goSsfServer` (a stripped-down receiver for demos).

### EventRouter is the heart of delivery

`internal/eventRouter/event_router.go` owns all in-flight delivery. For each stream it maintains a `*buffer.EventPushBuffer` or `*buffer.EventPollBuffer` (`internal/eventRouter/buffer/`). Key flows:

- **Inbound** (`HandleEvent`) persists the event, then matches it against every registered push/poll stream via `StreamEventMatch` (issuer/audience/event-type filtering).
- **Push** (`PushStreamHandler` → `runPushLoop` → `pushEvent` → `goSetPush.PushSET`) wraps the loop in a MongoDB lease (`push-transmitter:<sid>`). Failed pushes leave the JTI unacked; recovery is implicit via the `backfillTicker` (default 1s) which re-reads pending JTIs only when the buffer is empty. RFC8935 `DeliveryErr` (HTTP 400 with parsed body) pauses the stream; transport errors and other HTTP statuses are not paused and not logged at the router layer.
- **Poll** (`PollStreamHandler`) reads from the poll buffer in response to receiver poll requests, signs the SETs (or forwards raw, depending on `RouteMode`), and acks on the next request.
- **Cluster wake-ups** — when a router receives an event whose stream's transmitter lease is held by a *different* node, it sends `POST /_cluster/wake-transmitter` to that node so the owner can pull the new event from Mongo immediately. Authenticated via shared HMAC (`I2SIG_CLUSTER_INTERNAL_TOKEN`) or SPIFFE mTLS when configured.

### Persistence is pluggable but Mongo is canonical

`internal/providers/dbProviders/provider_interface.go` defines the full `DbProviderInterface` — keys, streams, events, and cluster leases all flow through it. Two implementations:

- `mongo_provider/` — the production path. Use this as the reference for any new provider methods. Lease coordination, change-stream watcher (`WatchPending`), and remote-address tracking all live here.
- `memory_provider/` — file-backed in-memory provider for tests/demos.

`factory.go` selects the provider at startup. New persistence methods must be added to the interface, both providers, and a test in `factory_test.go`.

### Clustering model

Per-stream singleton ownership via Mongo `cluster_leases` (atomic `FindOneAndUpdate`, 30s lease, 10s heartbeat). Both push transmitters and poll *receivers* take leases; poll *transmitters* (serving incoming polls) do not — every node can serve them. Node identity comes from `NODE_ID`, then `POD_NAME`, then `hostname-timestamp`. See `docs/Cluster.md` for the full lease/wake-up design.

### Configuration

All server config is environment-variable driven (no config file). `docs/configuration_properties.md` is the source of truth. Notable knobs that change runtime behavior in non-obvious ways:

- `I2SIG_TRANSMITTER_BACKFILL_INTERVAL` / `_BATCH` — push retry cadence and batch size.
- `I2SIG_MONGO_WATCH_ENABLED` — opt-in MongoDB change-stream watcher (deprecated; default off, wake-ups + backfill are preferred).
- `POLL_RETRY_*` — exponential backoff for the poll *receiver* (separate from push retry which has none).
- `SPIFFE_ENDPOINT_SOCKET` — presence enables SPIFFE mode (mTLS for inter-cluster + optionally MongoDB).
- `OAUTH_SERVERS` — comma-separated OIDC discovery URLs for inbound bearer-token validation.

## Project conventions

- **Indentation: 4 spaces, never tabs.** External formatters/linters in this repo may reformat tabs, but our own edits stay 4-space.
- **Logging:** use `internal/logger` (wraps `slog`). Create sub-loggers per component: `var eventLogger = logger.Sub("ROUTER")`. Log levels via `LOG_LEVEL` env var.
- **Decisions log:** Write an ADR for non-trivial architecture, or dependency or definition requirements that should be remembered.
- **MongoDB code:** follow patterns in `internal/providers/dbProviders/mongo_provider/`. The provider is responsible for lease semantics — don't reach into Mongo from `eventRouter` or service layers.
- **Pre-existing `go vet` warnings** in `internal/model`, `pkg/goScim`, and `cmd/goSignals` (duplicate JSON tags, mutex copies). Don't be alarmed by them; don't add new ones.
- **Package boundary:** `pkg/goSet*` packages must not import anything under `internal/`. They are intended as standalone libraries.
- **Don't commit `__debug_bin*`, certs under `config/certs/`, or anything in `.aiignore`** (`.mongo/` and a few WiredTiger files). Don't read or modify files matched by `.aiignore`.
- **Git:** the AI guidelines (`AGENTS.md`, `.junie/guidelines.md`) explicitly forbid AI-driven `git commit`s — only commit when the user asks.

## Where to look for more

- `README.md` — getting started, docker-compose matrix, debugger setup.
- `docs/Cluster.md` — lease + wake-up internals.
- `docs/configuration_properties.md` — every env var.
- `docs/security_model.md` — auth flows and SPIFFE.
- `docs/Metrics.md` — Prometheus/Grafana integration.

## Claude Development work cycle

### Issues and Work Management
1. Each new idea starts with the /grill-me or /grill-with-docs skill in plan mode to work to a common understanding, or begins with /triage on issues marked "needs-triage" in github (advancing them through the needs-triage → ready-for-agent / ready-for-human labels).
2. /to-prd to write a PRD and commit to Github for complex issues
3. /to-issues to create Github issues (slices) or to update a simple issue such as a bug.

### Development Workflow Cycle
Claude orchestrates this cycle directly: it runs the skills below in sequence and dispatches a subagent (the Task tool) per independent slice when work can run in parallel, pausing at the approval (step 2) and HITL (step 6) gates. Executing this cycle is the standing authorization to commit and push on the PRD/slice branches it creates — never commit to `master`, and never open the PR (step 7) until explicitly asked.
1. Create a new branch for the identified PRD or specific set of issues (the "PRD branch"). Every issue in the PRD or set becomes part of one common PR off this branch.
2. Request approval for the workflow sequence and the agents to be run.
3. Implement each issue: for a single issue, use /tdd directly on the PRD branch; for multiple, run /slice per issue — each slice on its own branch, committed (no push) and labelled ready-for-review. Independent issues (no dependency or file overlap) may be worked by parallel /slice sub-agents; overlapping issues are serialized.
4. Integrate and QA. If slices were used, run /merge-slices to rebase each ready-for-review slice onto the PRD branch, resolve conflicts in line with the PRD, and run a combined QA gate. Then confirm every issue's PRD acceptance criteria are met — `go test -race ./...` plus /verify to check the change in the running app.
5. Complete a /review cycle.
6. Request HITL QA approval.
7. Open the PR and check CI. If green, ask to have it merged.
8. Upon successful merge, clean up the PRD and slice branches and switch back to `master`.

## Git & Issue Operations

Only perform the exact git/branch/issue operations I authorize. Do not bundle extra actions (e.g., remote branch deletion, closing issues) into a step unless explicitly requested.

## Agent skills

### Issue tracker

Issues and PRDs live as GitHub issues at `i2-open/i2goSignals`. Use the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Default canonical strings (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). `needs-triage` and `wontfix` already exist in the repo; create the other three with `gh label create` when first needed. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` + `docs/adr/` at repo root. See `docs/agents/domain.md`.