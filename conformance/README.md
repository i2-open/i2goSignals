# SSF Conformance Testing — goSignalsServer

A minimal, single-SUT deployment of **goSignalsServer** for running the
[OpenID conformance suite](https://gitlab.com/openid/conformance-suite) **Shared
Signals Framework (SSF)** test plans against it — both **Transmitter** and
**Receiver** roles, over both **PUSH** and **POLL** delivery.

## How the pieces fit

```
 host (127.0.0.1)
 ├─ OpenID conformance suite (native Spring Boot)   https://localhost.emobix.co.uk:8443
 │     plays Receiver  -> drives goSignals' transmitter   (transmitter plans)
 │     plays Transmitter <- goSignals registers a stream  (receiver plans)
 │
 └─ this deployment (docker-compose-conformance.yml)
        ├─ gosignals  goSignalsServer (SUT)  published 127.0.0.1:9443  (container :8888)
        │     BASE_URL / issuer = https://localhost.emobix.co.uk:9443
        │     extra_hosts: localhost.emobix.co.uk -> host-gateway   (PUSH callback)
        └─ mongo      single-node replica set rs0 (+ one-shot mongo-init)
```

Two facts about the suite make this simple (verified in
`AbstractCondition.java`): its HTTP client **trusts all TLS certs** and uses a
**no-op hostname verifier**. So goSignals' self-signed `config/certs/server-cert.pem`
is accepted as-is, and the issuer host need not match the cert. The hostname
`localhost.emobix.co.uk` is real public DNS that resolves to `127.0.0.1`.

## Authorization model (read this before POLL)

The suite (STATIC auth mode) sends one bearer — `ssf.transmitter.access_token` —
for **every** call. goSignals' scope requirements:

| Operation | Scope accepted |
|---|---|
| Create / Get / Update / Replace / Delete stream, Get/Update status | `stream` (or `admin`/`root`) |
| Verify | `event` or `stream` |
| **`/poll` (POLL delivery)** | **`event`** |

So the token must carry **both `stream` and `event`**:
- **PUSH** runs work with a plain `stream` management token (the suite receives
  pushes; it never calls `/poll`).
- **POLL** runs need a **`stream`+`event`** token. The default `/register` path
  mints a `stream`-only token; supply a combined token via `GOSIGNALS_TOKEN`
  (see step 2).

## Prerequisites

- `make build-docker` in the repo root → produces `i2gosignals:latest`.
- Docker / Docker Compose.
- The OpenID conformance suite running at `https://localhost.emobix.co.uk:8443`
  (its own `devenv up` / `docker-compose-dev`).

## 1. Start goSignals

```bash
cd conformance
docker compose -f docker-compose-conformance.yml up -d
# verify metadata is reachable from the host the way the suite will fetch it:
curl -k https://localhost.emobix.co.uk:9443/.well-known/ssf-configuration | jq .
```
Expect `issuer`, `configuration_endpoint`, `status_endpoint`,
`verification_endpoint`, `jwks_uri`, `delivery_methods_supported`,
`authorization_schemes`, and `spec_version: "1_0"`, all on
`https://localhost.emobix.co.uk:9443`.

### Testing local fixes (build from source)

The default stack runs the published release image. While iterating on a fix,
layer the build override to compile the SUT from the working tree instead — each
rebuild picks up your latest changes:

```bash
docker compose \
  -f docker-compose-conformance.yml \
  -f docker-compose-conformance.build.yml \
  up -d --build
```

`--build` recompiles `goSignalsServer` + `healthcheck` (see
`Dockerfile.conformance`) and tags them `i2gosignals:conformance-dev`. The Go
module cache is reused across rebuilds, so after the first build only changed
packages recompile. Use the same two `-f` flags for any later
`up`/`down`/`logs` on this variant.

## 2. Mint the access token

```bash
# PUSH-only (stream-scoped token is sufficient):
./bootstrap-token.sh

# POLL (and combined PUSH+POLL): supply a stream+event token issued by goSignals:
GOSIGNALS_TOKEN="eyJ..." ./bootstrap-token.sh
```
Writes `suite-configs/ssf-transmitter-gosignals.local.json` with the token filled
in, and prints the token.

## 3. Run the Transmitter plans (suite plays Receiver)

Import `suite-configs/ssf-transmitter-gosignals.local.json` on the suite's
`schedule-test.html`, or use the CLI test runner. Variants:

- `ssf_server_metadata = discovery`  (suite fetches `<issuer>/.well-known/ssf-configuration`)
- `ssf_auth_mode = static`
- `ssf_delivery_mode = push`  then  `poll`
- `ssf_profile = default`  then  `caep_interop`

Suggested order (fail fast, then widen):
1. `openid-ssf-transmitter-test-plan[push]` → run **`openid-ssf-transmitter-metadata`**
   then **`openid-ssf-stream-control-happy-path`**.
2. Stream verification + subject control modules.
3. `openid-ssf-transmitter-caep-test-plan[push]` → CAEP event delivery
   (`openid-ssf-transmitter-stream-caep-interop`).
4. Repeat the applicable modules with `[poll]`.

### PUSH callback trust
For PUSH, goSignals POSTs SETs back to the suite at
`https://localhost.emobix.co.uk:8443`. The container reaches the host via
`extra_hosts`, but must also **trust the suite's TLS cert**. Append the suite's
root CA into the mounted CA file before `up` (or point `I2SIG_TLS_CA_CERT` at a
bundle):

```bash
# example: the suite uses a mkcert cert
cat "$(mkcert -CAROOT)/rootCA.pem" >> ../config/certs/ca-cert.pem
docker compose -f docker-compose-conformance.yml up -d --force-recreate gosignals
```
POLL needs no callback and no extra CA.

## 4. Run the Receiver plans (suite plays Transmitter)

Here goSignals is the **receiver** and must register a stream against the
suite's emulated transmitter, which is exposed under the suite base URL + the
config alias:

- Transmitter metadata (emulated by suite):
  `https://localhost.emobix.co.uk:8443/test/a/gosignals-ssf-rx/.well-known/ssf-configuration`

Drive the goSignals CLI against the running container (the bearer it presents to
the suite must equal `ssf.transmitter.access_token` in
`suite-configs/ssf-receiver-gosignals.json`, i.e. `ssf-conformance-rx-token`):

```bash
docker exec -it ssfconf-gosignals /app/goSignals
# then, inside the CLI:
#   add server suite https://localhost.emobix.co.uk:8443/test/a/gosignals-ssf-rx
#   create stream push receive suite --events="*"     # for PUSH receiver tests
#   create stream poll  receive suite --events="*"    # for POLL receiver tests
```
Import `suite-configs/ssf-receiver-gosignals.json` and run
`openid-ssf-receiver-test-plan` / `openid-ssf-receiver-caep-test-plan`. The suite
waits for goSignals to create/manage/poll the stream.

## 5. CI-style runner (optional)

From the conformance-suite checkout, the transmitter/receiver config paths above
can be passed to `.gitlab-ci/run-tests.sh --ssf-tests` plan specs (see the
suite's `makeSsfTests()` for the `plan[variant]:module{...}config` syntax).

### Plan-isolated runs (`run-plan.sh`, `run-receiver-plan.sh`)

The suite plans are not hermetic — modules create streams that aren't always
deleted at cleanup. A zombie stream from a prior plan will fire goSignals' T3
idle-keepalive (default 5 min) at the suite's push endpoint without an
`Authorization` header, and the *currently active* plan attributes that push to
itself and reports a spurious header-missing failure (see `results/run-2026-06-17.md`
§F1).

`run-plan.sh` runs one **transmitter** plan against a freshly-wiped SUT:

```bash
./run-plan.sh "openid-ssf-transmitter-test-plan[ssf_delivery_mode=push][ssf_server_metadata=discovery][ssf_auth_mode=static]"
```

It runs `docker compose down -v` (drops the Mongo volume → no zombie streams),
brings the SUT back up, waits for SSF metadata, re-mints the token, and invokes
the upstream `scripts/run-test-plan.py`. CAEP plans auto-launch
`trigger-caep.sh` for the operator-driven delivery window.

`run-receiver-plan.sh` runs one **receiver** plan the same way and additionally
spawns a background driver that loops `add server suite … --token=<RX_TOKEN>` +
`create stream {push|poll} receive suite --events='*'` + `delete stream` inside
the SUT container once per module. SUT-side knobs in
`gosignals-conformance.env` (`I2SIG_RCV_MANAGEMENT_EXERCISE=true`,
`I2SIG_RCV_VERIFY_ON_ESTABLISH=true`) take care of the GET/PATCH/PUT/POST-status
and `/verify` calls the suite expects:

```bash
./run-receiver-plan.sh "openid-ssf-receiver-test-plan[ssf_delivery_mode=push]"
./run-receiver-plan.sh "openid-ssf-receiver-caep-test-plan[ssf_delivery_mode=poll]"
```

Env (both scripts): `SUITE_REPO` (default `~/git/openid-conformance-suite`),
`SUITE_URL`, `EXTRA_RUNNER_ARGS`, pass-through of `GOSIGNALS_TOKEN` to
`bootstrap-token.sh`. Receiver-specific: `RX_TOKEN` (default
`ssf-conformance-rx-token` — must match `ssf.transmitter.access_token` in
`suite-configs/ssf-receiver-gosignals.json`), `RX_DRIVER_INTERVAL`,
`RX_DRIVER_WINDOW`, `GOSIGNALS_CONTAINER`.

### Full-matrix run (`run-all-plans.sh`)

To execute every transmitter + receiver plan and aggregate the results into a
single Markdown summary under `results/`:

```bash
./run-all-plans.sh
# or, filter to a subset by substring match on the plan spec:
PLANS_FILTER='transmitter' ./run-all-plans.sh
PLANS_FILTER='receiver-caep' ./run-all-plans.sh
```

The aggregator writes `results/run-<UTC-ts>.md` (the table) plus one
`results/run-<UTC-ts>-<plan-slug>.log` per plan. It never short-circuits on a
failing plan — every plan in the matrix runs so a single regression does not
hide the rest. Each per-plan run still drops a signed `.zip` into `results/`
(the OpenID Foundation submission artifact). All env knobs above are
forwarded to the underlying per-plan scripts.

## Interpreting results

- The transmitter plan's **negative modules** (invalid token, unknown stream id,
  malformed JSON, duplicate config) expect goSignals to *reject* the request —
  those rejections are **passes**.
- Items the suite tags as expected warnings/skips are not failures.

Per-run reports land under `results/`. Latest: [`run-2026-06-17.md`](results/run-2026-06-17.md).

## Teardown

```bash
docker compose -f docker-compose-conformance.yml down -v
```
Each run starts from clean in-database state (the `-v` drops the Mongo volume).

## Files

| File | Purpose |
|---|---|
| `docker-compose-conformance.yml` | goSignals + single-node Mongo |
| `docker-compose-conformance.build.yml` | override: build the SUT from source for local-fix testing |
| `Dockerfile.conformance` | multi-stage source build used by the override |
| `gosignals-conformance.env` | goSignalsServer environment |
| `bootstrap-token.sh` | mint the suite's access token, template the tx config |
| `trigger-caep.sh` | inject CAEP events during a CAEP-interop plan window |
| `run-plan.sh` | run one **transmitter** plan against a freshly-wiped SUT |
| `run-receiver-plan.sh` | run one **receiver** plan + drive CLI create/delete cycles |
| `run-all-plans.sh` | full matrix runner + aggregate Markdown summary |
| `suite-configs/ssf-transmitter-gosignals.json` | suite config (token placeholder) |
| `suite-configs/ssf-receiver-gosignals.json` | suite config for receiver plans |
