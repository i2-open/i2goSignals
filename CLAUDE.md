# CLAUDE.md

Guidance for Claude Code working in this repo (the **community** `i2-open/i2goSignals`).

`i2goSignals` is a Go Security Event Token (SET) router/gateway implementing the OpenID Shared Signals Framework (SSF) — it bridges SET transmitters/receivers across protocols, persists streams/events in MongoDB, and runs as a MongoDB-lease-coordinated cluster. Must stay compatible with RFC8417 (SET), RFC8935 (push), RFC8936 (poll), the OpenID SSF spec, and the SCIM/RISC/CAEP event-type profiles (SCIM events: RFC9967).

## Build, test, run

The Makefile is the primary entry point; `go` commands also work directly. `make help` lists targets.

```bash
make build              # check-certs + console-build + server-build (no docker)
make console-build      # build the goSignals CLI (cmd/goSignals)
make server-build       # build bin/goSignalsServer (cmd/goSignalsServer)
make generate-certs     # cmd/genTlsKeys (auto-run by check-certs if certs missing)
make licenses-check     # verify Go deps use permissive licenses
make clean              # dev-clean + remove bin/ and top-level binaries
make run                # build + build-docker + bring up docker-compose.yml demo cluster

# Docker image (production distroless, buildx) — not part of `make build`
make build-docker            # local host-arch image -> i2gosignals:<ver> + :latest
make build-docker-multiarch  # multi-arch validate-only; PUSH=1 to publish

# Dev stack with Delve debugger (ports 2345-2347)
make dev-up             # docker compose -f docker-compose-dev.yml up -d
make dev-rebuild        # rebuild image + restart goSignals1, goSignals2, goSsfServer
make dev-logs           # follow goSignals1 logs
make dev-down           # stop the dev stack
make dev-clean          # down -v + clean-scim (wipes mongo + scim configs)
make run-spiffe-demo    # SPIFFE/SPIRE-enabled compose stack
make dev-reset-spiffe   # full SPIFFE dev stack reset (down -v, clean, up)
```

```bash
go test ./...                                              # everything
go test -race ./...                                        # required when touching concurrent code
go test ./internal/services/...                            # one package
go test -run TestStreamServiceRegistration ./internal/services/...   # one test
```
Integration tests use `testify/suite`; some (notably under `internal/server`) stand up a full server + Mongo provider and are slow. Race-tested code should still finish within ~5 minutes.

## Architecture for debugging

`CONTEXT.md` is the architecture glossary (provider chain, EventRouter / `EventService.MatchesStream`, `ClusterCoordinator` leases + fencing tokens, `PushDelivery` seam, subject filtering, auth planes). Read it before chasing a bug rather than re-deriving from the code. Deeper internals: `docs/Cluster.md` (lease + wake-up), `docs/security_model.md` (auth/SPIFFE), `docs/configuration_properties.md` (every env var). Server handlers live in `internal/server`; DAOs in `internal/dao/{interfaces,memory,mongo}`; services in `internal/services`; the composition root is `dbProviders.OpenPersistence`.

## Project conventions

- **Indentation:** Go files are gofmt-canonical **tabs** — run `gofmt -w` on any `.go` file you touch; a commit must leave `gofmt -l` clean. Non-Go files (YAML, Markdown, shell, JSON) use **4 spaces, never tabs**. Do not author Go with 4-space indentation expecting a formatter to fix it.
- **Logging:** use `pkg/logger` (wraps `slog`); create per-component sub-loggers (`var eventLogger = logger.Sub("ROUTER")`). Levels via `LOG_LEVEL`. Log-level policy (WARN vs ERROR discipline) is in `CONTEXT.md`.
- **Package boundary:** `pkg/goSet*` packages must not import anything under `internal/` — they are standalone libraries.
- **Pre-existing `go vet` warnings** in `internal/model`, `pkg/goScim`, `cmd/goSignals` (duplicate JSON tags, mutex copies) — don't be alarmed, don't add new ones.
- **Don't commit** `__debug_bin*`, certs under `config/certs/`, or anything matched by `.aiignore` (`.mongo/` + some WiredTiger files). Do not read or modify `.aiignore`-matched files.
- **Git:** `AGENTS.md` / `.junie/guidelines.md` forbid AI-driven `git commit`s — only commit when the user asks.
- **Decisions log:** write an ADR (`docs/adr/`) for non-trivial architecture/dependency decisions worth remembering.

## Where to look for more

- `README.md` — getting started, docker-compose matrix, debugger setup.
- `docs/Cluster.md` — lease + wake-up internals.
- `docs/configuration_properties.md` — every env var.
- `docs/security_model.md` — auth flows and SPIFFE.
- `docs/Metrics.md` — Prometheus/Grafana integration.

*Family coordination, the cross-repo write boundary, the dev work cycle, working rules, and agent conventions (issue tracker / triage labels / domain docs) live in `~/.claude/CLAUDE.md`. Update the coordination plan via `/update-plan`.*
