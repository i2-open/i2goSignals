# SSF Receiver Conformance — 2026-06-17 (partial; blocked on stale suite container)

| | |
|---|---|
| SUT image | `i2gosignals:conformance-dev` (built from `release-0.12.0` working tree) |
| SUT URL | https://localhost.emobix.co.uk:9443 |
| Suite container | `openid-conformance-suite-server-1` (uptime ~2 days at run time) |
| Source repo HEAD | `c32acfc50` (April 2026 receiver fixes present in source) |
| Last successful module | none |

## Outcome

All six receiver-test-plan modules failed at startup with
`Got an HTTP request to '.well-known/ssf-configuration' that wasn't expected`
in the suite's `handleHttp` (not `handleWellKnown`) path. This rejection
comes from `AbstractTestModule.handleHttp` (the base default that throws),
meaning the running suite container does **not** have the receiver
module's well-known override (commit `c13fd9d1a`, 2026-04-14) that the
source tree includes. The container needs to be rebuilt from the
working-tree source before another run.

```bash
cd ~/git/openid-conformance-suite
docker compose down
docker compose build server     # picks up c13fd9d1a + later receiver fixes
docker compose up -d
```

After that, re-run:

```bash
cd ~/git/i2goSignals/conformance
./run-receiver-plan.sh "openid-ssf-receiver-test-plan[ssf_delivery_mode=push]"
```

## Landed this session

### Conformance harness (working tree, uncommitted)

| File | Purpose |
|---|---|
| `conformance/run-receiver-plan.sh` | new — fresh-alias receiver driver; wipes SUT, polls suite ssf-configuration, drives `add server` + `create stream` + `delete stream` cycles via `docker exec /app/goSignals` |
| `conformance/run-all-plans.sh` | new — full matrix runner (4 tx + 4 rx) with aggregate Markdown summary |
| `conformance/Dockerfile.conformance` | adds `goSignals` CLI binary to the image so `run-receiver-plan.sh` can drive create/delete cycles inside the SUT container |
| `conformance/README.md` | documents both scripts, env knobs, and full-matrix mode |

### CLI fixes (cmd/goSignals — required for the receiver recipe to work at all)

| Fix | Reason |
|---|---|
| `commands.go:AddServerCmd` preserves the host URL's path prefix when computing the discovery URL | the conformance suite's emulated transmitter lives under `/test/a/<alias>/.well-known/ssf-configuration`; old code stripped the prefix and discovered the suite's own metadata instead |
| `commands.go:getHttpClient` honors `I2SIG_TX_TLS_SKIP_VERIFY=true` | the suite's dev cert has no matching SAN for `localhost.emobix.co.uk`; the SUT server already honored this knob, the CLI did not |
| `config.go:checkConfigPath` auto-creates the parent directory when `GOSIGNALS_HOME` points at a missing path | needed for any non-default config home (matches the default-path branch's existing behavior) |

## Outstanding (next attempt, gated on suite-container rebuild)

1. Rebuild the conformance suite Docker image from the current source so
   the receiver-module well-known and supported-events handlers ship.
2. Re-run `./run-receiver-plan.sh` for each (push|poll) × (default|caep-interop)
   variant and verify the driver advances every module.
3. If the suite still flags missing receiver actions, follow up on:
   - whether `I2SIG_RCV_VERIFY_ON_ESTABLISH` fires soon enough to satisfy
     the `stream-verification` module's expectation window,
   - whether the CLI's `create stream push receive` registration body
     supplies a usable push endpoint URL (CreatePushReceiverCmd currently
     sends no `EndpointUrl`).

## Findings, recorded for next iteration

- The OpenID conformance suite holds an alias in `INTERRUPTED` state for
  ~3 min after a failed plan and refuses re-use during that window.
  `run-receiver-plan.sh` now mints a unique alias per run (`<base>-<HHMMSS>`)
  and rewrites the imported config file in place, so back-to-back runs no
  longer deadlock.
- A pre-WAITING discovery probe poisons the test (the suite's pre-WAITING
  default `handleHttp` throws on any inbound request). The driver now
  gates `add server` on `"issuer":"http..."` appearing in the discovery
  response — but the suite must already be exposing the well-known path
  for that to be safe (see blocker above).
