<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../brand/logo/gosignals-hero-primary.svg"><img src="../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# Operations Guide

This guide explains how SET delivery streams behave at runtime, how the system
responds to failures, and how operators recover from each failure class. It is
the canonical vocabulary reference for stream lifecycle and error handling.

If you are configuring a deployment for the first time, read
`docs/configuration_properties.md` for the full env-var reference and
`docs/Cluster.md` for clustering. This document focuses on **operational
behavior** once the system is running.

## Contents

1. [Delivery semantics invariant](#delivery-semantics-invariant)
2. [Stream lifecycle and states](#stream-lifecycle-and-states)
3. [Push delivery: failure classes and responses](#push-delivery-failure-classes-and-responses)
4. [Receiver-status interrogation](#receiver-status-interrogation)
5. [Idle keepalive (verify events)](#idle-keepalive-verify-events)
6. [Operational events](#operational-events)
7. [Recovery playbook](#recovery-playbook)
8. [Configuration knobs](#configuration-knobs)

## Delivery semantics invariant

> **An acknowledged event is a delivered event.** Auto-recovery never invents
> acks. The system treats RFC8417 / RFC8935 / RFC8936 acknowledgement as a
> contract: a JTI is only marked delivered when the receiver confirmed receipt
> (HTTP `202` for push; explicit poll-acknowledgement for poll).

This is the load-bearing rule for everything that follows:

- Push failures **never** ack the JTI on the wire. Failed JTIs stay in
  MongoDB's pending list.
- Recovery (auto or operator-driven) does not rewrite history. It only
  controls **whether** a stream attempts delivery and **with what cadence**.
- The only retransmission lever in the system is the operator-controlled
  `ResetDate` / `ResetJti` mechanism on `StreamConfiguration`. See the
  [recovery playbook](#recovery-playbook).

If a stream goes from `enabled` to `disabled` after exhausting retries, every
JTI that was unacked at the time of disable remains pending. Re-enabling the
stream replays them in order. Auto-recovery does **not** drop, dead-letter, or
silently ack any event.

## Stream lifecycle and states

Every stream — push or poll, transmitter or receiver — exposes a `status`
field with one of three values. The semantics are intentionally narrow so
that dashboards and alerts can be written against unambiguous meanings.

| State | Meaning | Self-healing? | Operator action required? |
|---|---|---|---|
| `enabled` | actively delivering | n/a | no |
| `paused` | the *remote endpoint* has self-paused; this side is waiting | yes | no |
| `disabled` | this side has given up; will not deliver until re-enabled | no | yes |

### `enabled`

Normal steady state. Push transmitters drain the buffer and POST events as
they arrive. Poll receivers poll on schedule. Any single failure may transition
the stream to `paused` (if the remote reports it) or initiate retry/recovery
(see [failure classes](#push-delivery-failure-classes-and-responses)). If the
stream eventually exhausts its retry budget, it transitions to `disabled`.

### `paused`

**The local stream is in `paused` only because the remote endpoint reported
itself as `paused`** via its `/status` endpoint. The local side stops
attempting delivery, persists the reason in `ErrorMsg`, and periodically
re-checks the remote status (every `I2SIG_PUSH_PROBE_INTERVAL` for push;
the equivalent `I2SIG_POLL_PROBE_INTERVAL` for poll). When the remote
re-enables, the local stream auto-resumes. **No operator action is required.**

If the remote pause persists indefinitely, the local stream stays in `paused`
indefinitely. This is intentional — the remote owns its state, and the local
side is correctly reflecting it. Operators may inspect why the remote paused
itself but cannot move *this* side out of `paused` other than by waiting for
the remote.

### `disabled`

Terminal state for this side. Reached via one of:

- **Retry cap exceeded.** Transport errors and 5xx responses retried for
  `I2SIG_PUSH_RETRY_LIMIT` (default 6h). 401 retried for
  `I2SIG_PUSH_AUTH_RETRY_LIMIT` attempts (default 10).
- **HTTP 403** — immediate disable. The receiver has revoked our authorization.
- **HTTP 4xx other than 401/403/429** (404, 410, 422, etc.) — immediate disable.
  The endpoint is wrong, has been removed, or is rejecting our shape.
- **RFC8935 §2.4 protocol error** — immediate disable. The receiver has
  rejected the SET as malformed/unauthorized/etc. (See
  [RFC8935 protocol errors](#rfc8935-protocol-errors).)
- **Remote `/status` reports `disabled`** — local side mirrors the remote's
  terminal state.

`disabled` is the system's signal that **operator attention is required**.
The stream's `ErrorMsg` field contains the diagnostic. Re-enabling the stream
replays all unacked JTIs that accumulated while it was failing.

## Push delivery: failure classes and responses

When a push attempt completes, the response is classified into one of the
buckets below. The classification drives the response.

| Push response | What it means | System response | Cap |
|---|---|---|---|
| **HTTP 202 Accepted** | success | ack JTI; reset backoff and idle timer | — |
| **Transport error** (DNS, refused, TLS, timeout) | network or cert problem | exp backoff; retry until cap; then `disabled` | `I2SIG_PUSH_RETRY_LIMIT` (6h default) |
| **HTTP 5xx** (500/502/503/504) | server-side problem | same as transport error | 6h |
| **HTTP 401 Unauthorized** | auth rejected | bounded retries with fixed delay; then `disabled` | `I2SIG_PUSH_AUTH_RETRY_LIMIT` × `I2SIG_PUSH_AUTH_RETRY_DELAY` (10 × 15s default) |
| **HTTP 403 Forbidden** | auth forbidden | `disabled` immediately | — |
| **HTTP 429 Too Many Requests** | rate-limited | honor `Retry-After`; if absent, exp backoff; **no cap** (peer back-pressure) | none |
| **HTTP 4xx other** (404/410/422/...) | unexpected protocol | `disabled` + verbose log | — |
| **RFC8935 §2.4 error** | receiver rejected the SET | see [RFC8935 protocol errors](#rfc8935-protocol-errors) | — |
| **Remote `/status` = `enabled`** | healthy | resume normal operation | — |
| **Remote `/status` = `paused`** | remote self-paused | local `paused`; re-check every `I2SIG_PUSH_PROBE_INTERVAL` | — |
| **Remote `/status` = `disabled`** | remote disabled | local `disabled` | — |

### Backoff curve

For transport errors and 5xx, the backoff is:

```
delay_n = min( BASE * FACTOR^n , MAX )
```

with defaults `BASE=1s`, `FACTOR=2.0`, `MAX=5m`. The cap is total elapsed
time (`RETRY_LIMIT`, default 6h), not attempt count — this prevents a
flapping receiver from accumulating an unbounded retry budget.

When the cap is reached, the stream transitions to `disabled` with
`ErrorMsg` recording the elapsed time and the last failure class.

### RFC8935 protocol errors

RFC8935 §2.4 defines a small set of error codes the receiver returns in a
`400 Bad Request` body when it rejects a SET:

- `authentication_failed`
- `invalid_request`
- `invalid_audience`
- `invalid_issuer`
- `invalid_key`
- `jws_signature_failed`
- `jwe_decryption_failed`

**All RFC8935 §2.4 errors are deterministic per-SET.** The same signed token
will produce the same error every time it is re-pushed. There is no value in
retrying the same SET. The system therefore transitions the stream to
`disabled` on first occurrence and persists the offending `JTI`, error code,
and description in `ErrorMsg`. Operators see the failure immediately rather
than after a long retry budget elapses.

**Single exception — `jws_signature_failed`:** this can also indicate that
the receiver's JWKS does not yet have our current signing key — a key
rotation race. The system handles this by:

1. Invalidating the local issuer-key cache for the affected stream.
2. Reloading the signing key.
3. Re-signing the SET.
4. Retrying **once**.

If the retry succeeds (`202 Accepted`), the JTI is acked normally. If the
retry returns any 400 (including another `jws_signature_failed`), the stream
transitions to `disabled` — the problem is not a transient cache miss.

There is **no dead-letter path** for RFC8935 errors. Operationally, every
RFC8935 §2.4 code reflects a configuration problem (wrong audience, wrong
issuer, missing key, etc.) and the operator must intervene. See the
[recovery playbook](#recovery-playbook) for how to triage.

## Receiver-status interrogation

The push transmitter actively interrogates the receiver's `/status` endpoint
in three situations:

### T1 — Reactive on push failure

When a push fails (transport or 5xx), the transmitter fetches the receiver's
`/status` to disambiguate the failure:

- Remote `enabled`, our push still failing → continue exp backoff (it really
  is a transport problem).
- Remote `paused` → transition to local `paused` and enter the status-check
  loop.
- Remote `disabled` → transition to local `disabled`.

This mirrors the poll receiver's `handleTransmitterStatus` behavior.

### T2 — Pre-flight at lease acquisition

When a node acquires a push stream's cluster lease (see `docs/Cluster.md`), it
fetches the receiver's `/status` **before** sending the first event. If the
receiver is already `paused` or `disabled`, no events are wasted — the local
side enters the matching state immediately.

This means after a node failover, a paused receiver does not get hammered
with retry attempts on the new owner.

### T3 — Idle keepalive

See [Idle keepalive (verify events)](#idle-keepalive-verify-events) below.

### Status endpoint discovery

The push transmitter discovers the receiver's `/status` URL via the SSF
well-known configuration (`/.well-known/ssf-configuration`) on the
receiver's host. If well-known discovery fails, the transmitter falls back
to a derived URL based on the configured push endpoint (replacing the path
segment).

The status fetch reuses the same authorization the push uses.

## Idle keepalive (verify events)

If a push stream goes idle — no successful push for
`I2SIG_PUSH_KEEPALIVE_INTERVAL` (default 5 min) — the transmitter
generates a real SSF verify event as an end-to-end heartbeat:

1. The verify event is created via the standard
   `https://schemas.openid.net/secevent/ssf/event-type/verification` event
   type.
2. It is persisted as an [operational event](#operational-events) (with
   `Operational=true`).
3. It is submitted directly to the target stream's push buffer (it does not
   fan out via the matcher).
4. It flows through the normal push path. The receiver responds with `202`
   on success.
5. The idle timer resets on every successful push, including the verify
   event itself.

If the verify event push fails, the failure is classified and dispatched
exactly like a business event would be (T1 takes over). This is what makes
the verify event a meaningful heartbeat: it tests the **full delivery path**
(auth, signing, network, receiver), not just receiver liveness.

The idle timer is suppressed during recovery (no verify events are emitted
while the stream is in `paused` or actively backing off — the recovery
sub-loop is already probing the receiver via `/status`).

Idle state is local to the node holding the push lease. Failover resets the
idle clock to "now."

## Operational events

The system distinguishes **business events** from **operational events**:

- **Business events**: SCIM, RISC, CAEP, custom event types — the actual
  payload the system exists to deliver. Routed through the matcher; subject
  to `ResetDate`/`ResetJti` replay.

- **Operational events**: `verification` (SSF verify) and `stream-updated`
  (SSF stream-updated). Generated **for** a specific stream, not routed to
  other streams. Persisted for audit but excluded from operator-initiated
  replay.

Operational events follow three rules:

1. **Persisted for audit.** They are stored in the event store like any
   other event. The `Operational=true` flag distinguishes them.
2. **Scoped to a single SSF endpoint relationship.** Each operational event
   is generated for one specific stream and submitted directly to that
   stream's buffer. It is **never matched** against other streams, even if
   `iss`/`aud` would otherwise overlap. This is a strict point-to-point
   communication, consistent with the RFC8935 / SSF model where verify is
   semantically a per-relationship probe.
3. **Excluded from replay.** When an operator sets `ResetDate` or
   `ResetJti`, the replay query returns only business events. Stale
   operational events from prior days are not replayed — they are
   operationally meaningless after the fact and would pollute a recovery
   operation.

If the system later introduces additional auto-generated event types, they
should be marked `Operational=true` and they will inherit all three
behaviors automatically.

## Recovery playbook

This section walks through the three most common recovery scenarios.

### Scenario A: stream stuck in `disabled` after RFC8935 protocol error

**Symptom.** A push stream is `disabled`. `ErrorMsg` contains an RFC8935
error code such as `invalid_audience` or `authentication_failed` along with
the JTI of the offending event.

**What happened.** The receiver explicitly rejected a SET as malformed,
unauthorized, or otherwise unacceptable. The system did not retry because
the same SET would produce the same error on every attempt.

**How to triage:**

1. Read the JTI from `ErrorMsg` and inspect that event in the event store.
2. Identify the cause from the error code:
   - `authentication_failed` → wrong Authorization header on push config.
     Update the stream's push delivery method and re-enable.
   - `invalid_audience` → stream's `aud` does not match what the receiver
     expects. Update stream config and re-enable.
   - `invalid_issuer` → stream's `iss` does not match what the receiver
     expects. Update stream config and re-enable.
   - `invalid_key` / `jws_signature_failed` (after the single auto-retry
     exhausted) → receiver's JWKS does not have our `kid`. Either ask the
     receiver to refresh its JWKS, or rotate to a key the receiver does
     know.
   - `invalid_request` → likely a malformed SET payload. Inspect the event
     content; this is rare and usually points to a transmitter bug.
3. Decide what to do with the offending event:
   - **Most cases**: fix the configuration and re-enable. The unacked JTI
     replays automatically and now succeeds.
   - **The event itself is bad** (rare): delete it from the event store
     before re-enabling, OR set `ResetJti` on the stream to skip past it.

### Scenario B: stream stuck in `disabled` after exhausting retry cap

**Symptom.** A push stream is `disabled`. `ErrorMsg` indicates the retry
cap was exceeded (e.g., "transport recovery exceeded 6h" or "401 attempts
exhausted").

**What happened.** The receiver was unreachable or rejecting authorization
for an extended period. The system retried with exp backoff up to the cap,
then disabled the stream so the database stops accumulating un-deliverable
events.

**How to triage:**

1. Determine why the receiver was unreachable: DNS gone? Cert expired?
   Network partition? Credentials revoked? Receiver actually offline?
2. Fix the underlying cause (rotate credentials, fix DNS, restore network,
   etc.).
3. Re-enable the stream. All unacked JTIs that accumulated during the
   outage replay in order.

### Scenario C: receiver pauses then re-enables

**Symptom.** The local stream's `status` flips to `paused` then back to
`enabled`. No operator action was needed.

**What happened.** The remote receiver's operator paused the stream from
their end. The local side detected this via `/status` interrogation,
stopped attempting delivery, and periodically re-checked. When the remote
re-enabled, the local side resumed automatically.

**Operator action.** None required. This is the system working as
designed — the `paused` state is *transient and self-healing*.

### Using `ResetDate` / `ResetJti`

`ResetDate` and `ResetJti` are fields on `StreamConfiguration`. They are
**operator-controlled retransmission levers** and are the **only**
mechanism in the system for replaying historical events.

| Field | Effect |
|---|---|
| `ResetDate` | re-mark all (business) events at-or-after this timestamp as pending |
| `ResetJti` | re-mark events from the named JTI forward as pending |

Both are one-shot — the server clears them after applying. Use them when:

- You suspect a downstream consumer lost data and you need to replay.
- You're recovering from a multi-day outage and want to backfill business
  events from a known-good point in time.
- You want to skip past a specific known-bad event by setting `ResetJti`
  to the JTI immediately after it.

Operational events (verify, stream-updated) are **excluded** from replay.
Setting `ResetDate=7-days-ago` returns only business events from that
window — your recovery is not polluted with stale heartbeats.

The system never invokes `ResetDate`/`ResetJti` on its own. Auto-recovery
relies exclusively on the unacked-JTI mechanism (failed JTIs stay pending
and replay automatically when the stream re-enables).

## Configuration knobs

The push state machine is tuned via the following environment variables.
See `docs/configuration_properties.md` for the canonical reference and any
poll-side analogues.

| Env var | Default | Purpose |
|---|---|---|
| `I2SIG_PUSH_RETRY_BASE_DELAY` | `1s` | Base delay for exp backoff on transport/5xx |
| `I2SIG_PUSH_RETRY_BACKOFF_FACTOR` | `2.0` | Multiplier per retry attempt |
| `I2SIG_PUSH_RETRY_MAX_DELAY` | `5m` | Cap on individual sleep |
| `I2SIG_PUSH_RETRY_LIMIT` | `6h` | Total elapsed time before transport recovery exits to `disabled` |
| `I2SIG_PUSH_AUTH_RETRY_LIMIT` | `10` | Max 401 retry attempts before `disabled` |
| `I2SIG_PUSH_AUTH_RETRY_DELAY` | `15s` | Sleep between 401 retries |
| `I2SIG_PUSH_PROBE_INTERVAL` | `30s` | Cadence of `/status` re-checks while in `paused` |
| `I2SIG_PUSH_KEEPALIVE_INTERVAL` | `5m` | Idle threshold before generating a verify-event keepalive |

The existing `I2SIG_PUSH_BACKFILL_INTERVAL` and
`I2SIG_PUSH_BACKFILL_BATCH` continue to govern active-mode buffer
refilling — they are independent of the recovery state machine and remain at
their previous defaults.

---

<!-- gosignals-brand-footer -->
<p align="center"><sub><img src="../brand/logo/gosignals-favicon-simple.svg" width="12" height="12" alt="goSignals"> (C)2026 Independent Identity Inc.</sub></p>
