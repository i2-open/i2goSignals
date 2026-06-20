# SSF Conformance Testing — goSignalsServer

A self-contained harness for running the
[OpenID conformance suite](https://gitlab.com/openid/conformance-suite) **Shared
Signals Framework (SSF)** test plans against **goSignalsServer** — both
**Transmitter** and **Receiver** roles, over both **PUSH** (RFC 8935) and
**POLL** (RFC 8936) delivery.

The whole loop is driven by the **`Makefile`** in this directory. Read
["Networking"](#networking-read-this) below at least once — it is the single
non-obvious thing that, if missed, makes every transmitter plan fail with no
useful error.

---

## TL;DR

```bash
cd conformance

make all          # deploy suite + SUT, verify networking, run the full matrix
# …or step by step:
make ready        # deploy suite (with networking fix) + SUT, verify reachability
make test         # run the full plan matrix → results/run-<ts>.md
make status       # what's running, which SUT image, suite->SUT reachability
make refresh-suite# git pull + rebuild the suite jar + redeploy (get latest)
make help         # every target
```

`make all` is the one-command path: it brings up the conformance suite **with
the networking overlay**, builds and starts the goSignals SUT from the current
working tree, verifies the suite can actually reach the SUT, then runs every
transmitter + receiver plan and aggregates the results.

---

## How the pieces fit

```
 host (macOS, Docker Desktop)
 │
 ├─ OpenID conformance suite        (its own docker-compose-dev.yml, RUN IN DOCKER)
 │    project "openid-conformance-suite"
 │    ├─ nginx    :8443 / :8444 / :8445   <- the suite's public base URL
 │    ├─ server   the Spring Boot test engine (makes the outbound calls)
 │    └─ mongodb
 │       plays Receiver    -> drives goSignals' transmitter   (transmitter plans)
 │       plays Transmitter <- goSignals registers a stream    (receiver plans)
 │
 └─ goSignals SUT                   (docker-compose-conformance.yml + .build.yml)
        project "i2gosignals-ssf-conformance"
        ├─ gosignals  goSignalsServer (SUT)  published 127.0.0.1:9443 (container :8888)
        │     BASE_URL / issuer = https://localhost.emobix.co.uk:9443
        │     extra_hosts: localhost.emobix.co.uk -> host-gateway   (so the SUT
        │                  can PUSH back to / poll the suite at :8443)
        └─ mongo      single-node replica set rs0 (+ one-shot mongo-init)
```

`localhost.emobix.co.uk` is real public DNS that resolves to `127.0.0.1`. The
suite's HTTP client **trusts all TLS certs** and uses a **no-op hostname
verifier** (see `AbstractCondition.java`), so goSignals' self-signed
`config/certs/server-cert.pem` is accepted and the issuer host need not match the
cert.

---

## Networking (READ THIS)

**The problem.** The conformance suite runs **in Docker**. It fetches the SUT's
transmitter metadata at `https://localhost.emobix.co.uk:9443/.well-known/...`.
That hostname resolves to `127.0.0.1` — but inside the suite's `server`
container `127.0.0.1` is the **container's own loopback**, not the host. The SUT
is published on the **host's** `127.0.0.1:9443`, so from inside the suite it is
invisible:

```
Unable to fetch server configuration from
https://localhost.emobix.co.uk:9443/.well-known/ssf-configuration/issuer1
- Connect to https://localhost.emobix.co.uk:9443 failed: Connection refused
```

Every transmitter module then **interrupts at the first condition**
(`OIDSSFGetDynamicTransmitterConfiguration`), so a run shows all modules
`INTERRUPTED` (status `I`, not a real `FAILED`) — which looks like a total SUT
regression but is purely a reachability problem. (When the suite runs *natively*
on the host instead of in Docker, `127.0.0.1` **is** the host and this does not
arise — that was the original setup the harness assumed.)

**The fix.** Map `localhost.emobix.co.uk` to the Docker host gateway inside the
suite `server` container. On Docker Desktop the gateway (`192.168.65.254`)
reaches host loopback-published ports, so `:9443` (SUT) **and** `:8443` (the
suite's own nginx) both resolve. This is what `suite-overlay.yml` does:

```yaml
services:
  server:
    extra_hosts:
      - "localhost.emobix.co.uk:host-gateway"
```

`make suite-up` always layers this overlay over the suite's
`docker-compose-dev.yml`, so you never bring the suite up without it. The SUT
side already uses the same `extra_hosts` trick for the reverse (PUSH/poll)
direction.

**The guard.** `check-suite-reaches-sut.sh` execs `curl` *inside* the suite
container and asserts it gets `HTTP 200` from the SUT metadata. It runs as:

- `make net-check` (and inside `make ready` / `make status`), and
- a preflight at the top of every transmitter plan in `run-plan.sh`.

If it fails it prints the one-line remediation (`make suite-up`). This is the
check whose absence let the break go silent.

---

## Authorization model (read before POLL)

The suite (STATIC auth mode) sends one bearer — `ssf.transmitter.access_token` —
for **every** call. goSignals' scope requirements:

| Operation | Scope accepted |
|---|---|
| Create / Get / Update / Replace / Delete stream, Get/Update status | `stream` (or `admin`/`root`) |
| Verify | `event` or `stream` |
| **`/poll` (POLL delivery)** | **`event`** |

So the token must carry **both `stream` and `event`**. The per-plan scripts mint
exactly that via `/iat` → `/register` (`bootstrap-token.sh`) on **every** run —
they have to, because each plan does `down -v` + a fresh `up`, which wipes the
previously registered client. So for a normal `make test` / `make all` you never
mint a token by hand.

To mint one yourself — e.g. to import the transmitter config into the suite's
web UI — run the script directly (it needs the SUT already up):

```bash
./bootstrap-token.sh                       # mints stream+event, templates the config
GOSIGNALS_TOKEN="eyJ..." ./bootstrap-token.sh   # use a token minted out-of-band, verbatim
```

---

## Prerequisites

- **Docker / Docker Compose** (Docker Desktop on macOS — the `host-gateway`
  reachability of host loopback ports is what makes the networking fix work).
- **The conformance suite checkout** at `$(SUITE_REPO)` (default
  `~/git/openid-conformance-suite`), with its Python runner venv at
  `.venv/` (install `scripts/requirements.txt`).
- **Java 21** for `make suite-build` (the suite jar targets Java 21; the Makefile
  selects it via `/usr/libexec/java_home -v 21`). Not needed for plain
  `make suite-up` if the jar is already built.

Everything else (the SUT image) is built from the working tree on demand.

---

## Make targets

| Target | Does |
|---|---|
| `make all` | `ready` + `test` — the full end-to-end run |
| `make ready` | `suite-up` + `sut` + wait + `net-check` (deploy & verify, no tests) |
| `make full` | `refresh-suite` + deploy + `net-check` + `test` (pull/rebuild suite first) |
| `make suite-up` | start the suite in Docker **with the networking overlay** |
| `make suite-pull` | `git pull --ff-only` the suite checkout |
| `make suite-build` | rebuild the suite fat jar (Java 21, tests/pmd skipped) |
| `make refresh-suite` | `suite-pull` + `suite-build` + `suite-up` (get latest) |
| `make sut` | build the SUT from the working tree and start it |
| `make net-check` | assert the suite container can fetch the SUT metadata |
| `make wait-suite` / `wait-sut` | block until the suite / SUT answers |
| `make test` | run the full matrix (honors `PLANS_FILTER`) |
| `make status` | running containers + SUT image + suite→SUT reachability |
| `make down` | stop the SUT (drops its Mongo volume) |
| `make clean` | stop SUT **and** suite |

Override any variable on the command line, e.g.
`make all SUITE_REPO=/path/to/suite PLANS_FILTER=transmitter`.

---

## Which SUT image is under test?

The SUT stack is two compose files:

- `docker-compose-conformance.yml` — base; pins the **published** image
  (`independentid/i2gosignals:…`, overridable via `GOSIGNALS_IMAGE`).
- `docker-compose-conformance.build.yml` — override; **builds from the working
  tree** and tags it `i2gosignals:conformance-dev`.

The Makefile and the per-plan scripts **always layer both** and pass `--build`,
so a run **always tests your local working tree**, never a stale pull. Confirm
at any time:

```bash
docker inspect --format '{{.Config.Image}}' ssfconf-gosignals
#  i2gosignals:conformance-dev          -> local build (what the runner uses)
#  independentid/i2gosignals:0.12.0.…   -> a fixed published tag
```

`make status` prints this. To deliberately test a **published** tag instead,
bypass the runner and bring up only the base file:
`docker compose -f docker-compose-conformance.yml up -d`.

---

## The plan matrix

`run-all-plans.sh` runs eight plans and scores each from the suite's signed
export zip (the authoritative per-module result), writing
`results/run-<UTC-ts>.md` plus a per-plan log and the `.zip` artifacts:

| # | Role | Plan |
|---|---|---|
| 1–2 | Transmitter | `openid-ssf-transmitter-test-plan[ssf_delivery_mode=push\|poll][ssf_server_metadata=discovery][ssf_auth_mode=static]` |
| 3–4 | Transmitter | `openid-ssf-transmitter-caep-test-plan[…push\|poll…]` |
| 5–6 | Receiver | `openid-ssf-receiver-test-plan[ssf_delivery_mode=push\|poll][ssf_auth_mode=static]` |
| 7–8 | Receiver | `openid-ssf-receiver-caep-test-plan[…push\|poll…]` |

> **Receiver variant note (suite ≥ v5.1.45):** receiver modules now require
> `ssf_auth_mode`. With `ssf_auth_mode=static` the suite marks `client_auth_type`
> *not applicable* (the receiver presents a pre-shared bearer), so it is omitted.
> Dropping `ssf_auth_mode` fails **plan creation** with *"requires a value for
> variant 'client_auth_type'"* and produces **no export**. Earlier suite
> versions rejected `ssf_auth_mode` on receiver plans; that is no longer true.

Per-plan isolation is deliberate: the suite plans are **not hermetic** — modules
create streams that aren't always deleted. A zombie stream from a prior plan
fires goSignals' T3 idle keepalive (default 5 min) at the suite's push endpoint
*without* an `Authorization` header, and the currently active plan attributes
that push to itself → spurious header-missing failure (see
`results/run-2026-06-17.md` §F1). So each plan brackets itself with
`docker compose down -v` (drops the Mongo volume → no surviving streams) + a
fresh `up -d --build`.

Run a subset by substring on the plan spec:

```bash
make test PLANS_FILTER=transmitter
make test PLANS_FILTER=receiver-caep
```

### Single-plan scripts

```bash
./run-plan.sh "openid-ssf-transmitter-test-plan[ssf_delivery_mode=push][ssf_server_metadata=discovery][ssf_auth_mode=static]"
./run-receiver-plan.sh "openid-ssf-receiver-test-plan[ssf_delivery_mode=poll][ssf_auth_mode=static]"
```

`run-plan.sh` wipes + rebuilds the SUT, **runs the suite→SUT net-check**, mints
the token, and invokes the upstream `scripts/run-test-plan.py`. CAEP plans
auto-launch `trigger-caep.sh` for the operator-driven delivery window.
`run-receiver-plan.sh` additionally drives the goSignals CLI through
create/manage/delete cycles per module and checks the suite is reachable first.

---

## Interpreting results

Status precedence per plan (worst-of): **FAIL > REVIEW > WARNING > PASS**. Module
counts are `P/W/R/F/I/S` = passed / warning / review / failed / interrupted /
skipped.

- **`I` (interrupted) across the board** → harness problem, not a SUT
  regression. The usual cause is the networking break above — run
  `make net-check`.
- **`no-export`** on a plan → the suite couldn't even create it (usually a
  variant mismatch after a suite upgrade — see the receiver note above).
- Transmitter **negative modules** (invalid token, unknown stream id, malformed
  JSON) expect goSignals to *reject* the request — those rejections are
  **passes**.
- Items the suite tags as expected warnings/skips are not failures.

---

## Files

| File | Purpose |
|---|---|
| `Makefile` | end-to-end orchestration (start here) |
| `suite-overlay.yml` | compose overlay adding the suite's `localhost.emobix.co.uk -> host-gateway` networking fix |
| `check-suite-reaches-sut.sh` | preflight gate: assert the suite can fetch the SUT metadata |
| `docker-compose-conformance.yml` | SUT: goSignals + single-node Mongo (published image) |
| `docker-compose-conformance.build.yml` | override: build the SUT from the working tree |
| `Dockerfile.conformance` | multi-stage source build used by the override |
| `gosignals-conformance.env` | goSignalsServer environment |
| `bootstrap-token.sh` | mint the suite's `stream`+`event` token, template the tx config |
| `trigger-caep.sh` | inject CAEP events during a CAEP-interop plan window |
| `run-plan.sh` | run one **transmitter** plan against a freshly-wiped SUT |
| `run-receiver-plan.sh` | run one **receiver** plan + drive CLI create/delete cycles |
| `run-all-plans.sh` | full matrix runner + aggregate Markdown summary |
| `suite-configs/ssf-transmitter-gosignals.json` | suite config template (token placeholder) |
| `suite-configs/ssf-receiver-gosignals.json` | suite config for receiver plans |
| `results/` | per-run `.md` summaries, `.log` per-plan output, signed `.zip` exports |
