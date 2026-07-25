<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 29. Event validation mode and the validator registry

Date: 2026-07-24

## Status

Accepted (GH #247, #249)

## Context

goSignals routes SETs content-agnostically: a token that verifies
(signature / `iss` / `aud`) is forwarded, and nothing looks at whether the event
payload inside it actually satisfies the profile that defines that event type. A
receiver that trusts goSignals therefore inherits every malformed payload an
upstream transmitter emits, and an operator has no way to say "if I recognize the
event type, the payload had better be well-formed".

Adding payload checks naively breaks two things at once:

- **Compatibility.** Turning checks on for an existing deployment would start
  rejecting traffic that flows today. The change has to be inert until an
  operator opts in, and it has to have an observability-only step between "off"
  and "rejecting".
- **The package boundary.** The natural place to put validation is next to the
  SET model in `pkg/goSet`, but validation needs to know which event types the
  *stream* negotiated — and stream state lives in `internal/`. A `pkg/` package
  that imports `internal/` violates the standing `pkg/goSet*` boundary rule and
  stops the validation logic being usable by a third-party SSF receiver or an
  embedder that wants to plug in its own vocabulary.

There is also a spec trap. The SSF stream-management events are operational, not
business, signals, and SSF §8.1.5 says outright that a Transmitter MAY send a
Stream Updated event even when it appears in none of `events_supported`,
`events_requested`, or `events_delivered`. A firewall posture derived purely from
the negotiated event set would let a narrowly-scoped stream reject its own
verification handshake.

## Decision

### D1 — A four-value mode enum, defaulting to off

Validation posture is a per-receiver-stream setting with four values:

| Mode | Recognized + malformed | Unsupported / out-of-contract |
| --- | --- | --- |
| `NONE` (default) | forward | forward |
| `WARN` | log at WARN, forward | forward silently |
| `ENFORCE` | reject on the wire | forward |
| `STRICT` | reject on the wire | reject on the wire |

`NONE` is the default, so the feature is inert until an operator opts in and
today's content-agnostic posture is unchanged. `WARN` is the staged-rollout step:
an operator can measure how much of their real traffic would be rejected before
turning on rejection. `ENFORCE` is "what I recognize must be well-formed";
`STRICT` is the firewall posture — every event must be vouched for by a
validator.

Each transport maps a rejection to its own RFC semantics; that mapping is a
wiring concern, not a validation concern.

### D2 — Rejection granularity is the whole SET, worst disposition wins

The router forwards raw signed tokens and never strips a payload, so a
per-payload verdict has nowhere to go. Per-URI dispositions reduce to a single
whole-SET decision by worst-disposition-wins. Under `STRICT`, a SET carrying an
unrecognized extension payload alongside a valid event is therefore rejected
whole. The disposition constants are declared in ascending severity so the
reduction is a plain max.

### D3 — Out-of-contract is *identical* to unsupported

An event URI is unsupported when no validator is engaged for it. That covers two
different-looking situations:

1. nothing in the registry validates that URI, and
2. the URI is out-of-contract — it matches none of the stream's negotiated
   `events_delivered` patterns.

They collapse to one disposition because in both cases the same thing is true:
**nothing vouched for this payload.** Keeping them separate would add a
disposition that no mode treats differently, and would tempt a future mode into
distinguishing "unknown to us" from "not yours", which is a routing question, not
a validation question. Which event *types* flow on a stream remains the job of
`events_requested` ∩ `events_supported`.

### D4 — Validators are keyed by event URI in a registry the caller builds

`pkg/goSetValidate` holds one validator per event-type URI in a `Registry`.
`BuiltinRegistry()` returns a **fresh** registry pre-loaded with the validators
this repo ships; `Register` returns the receiver so packs and embedder
registrations chain. A fresh instance per call is deliberate — an embedder must
not be able to mutate a process-wide singleton another embedder depends on.

`NewValidatorSet(registry, engagedURIs)` narrows a registry to one stream.
**Engagement is derived from the negotiated delivered-event set, but the derivation
happens in the caller and the result is passed in as a plain `[]string`.** The
package never reads stream state. This is what satisfies the import allowlist
(`pkg/goSet`, `pkg/goSet/events`, `pkg/subjectid`, stdlib, `keyfunc`) and the
standing no-`internal/` rule, and it is what makes the package consumable
standalone by a third-party SSF receiver. The alternative — importing stream
state — would have broken both. A consequence: any `events_delivered` glob
expansion is the caller's job, because the matcher lives in `pkg/ssfModels`.

### D5 — The SSF stream-management exception

`NewValidatorSet` unconditionally adds the verification and stream-updated event
URIs to the engaged set, regardless of what the stream negotiated. Basis: SSF
§8.1.5's explicit permission to send a Stream Updated event outside the
negotiated sets, and the operational absurdity of a `STRICT` stream rejecting the
verification event it asked for. These two events are always in-contract and
always validated.

### D6 — The library reports; it never rejects

`pkg/goSetValidate` computes dispositions and returns them. Mode policy, the
disposition-to-wire-error mapping, and the Prometheus counter live in the server
wiring (`internal/server` and the poll receive loop). Modes are deliberately
absent from the package's exported surface. This keeps the library free of
transport and policy coupling, and it means `WARN` mode can log and forward
without the library having any notion of forwarding.

### D7 — Core `goSet.Parse` is untouched; composition happens above it

`Parse` has no receiver context, and `WARN` mode needs the parsed token even when
validation fails — so validation cannot live inside `Parse`. Instead
`ParseAndValidate(tokenString, jwks, vs)` composes verification and validation,
mirroring `Parse`'s parameter shape. A nil validator set degrades to exactly
`goSet.Parse` plus a zero `SetResult`, with identical error behaviour, so a
caller can adopt the seam by threading one extra argument. It composes over the
**verified** `Parse`, never `Peek` (ADR-0066 §D3): a disposition is only ever
computed for a token whose signature already checked out.

## Consequences

- The exported surface is frozen in a Slice Contract —
  [`docs/contracts/spec-247-goSetValidate-surface.md`](../contracts/spec-247-goSetValidate-surface.md)
  — so the wiring slices could be drafted before the package existed. Changing an
  identifier or signature is a contract revision, not a refactor.
- Slice #249 lands the package with no wiring into any transport: after it, the
  server behaves exactly as it did before. All behaviour change is in later
  slices.
- Validation adds a JSON round-trip for in-process typed payloads (structs
  attached via `AddEventPayload` are normalised to a claim map). On the wire path
  the payload is already a map, so the hot path pays nothing.
- Because engagement is caller-supplied, every future consumer must remember to
  expand `events_delivered` globs itself. That is the price of the boundary, and
  it is documented on `NewValidatorSet`.
- Two glossary entries in `CONTEXT.md` — *Event validation mode* and *SSF
  stream-management events* — are the operator-facing statement of D1–D5.
