<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# Slice Contract — `pkg/goSetValidate` exported surface

Spec: [i2-open/i2goSignals#247](https://github.com/i2-open/i2goSignals/issues/247)
Slice: [i2-open/i2goSignals#249](https://github.com/i2-open/i2goSignals/issues/249)
Revision: 1 (2026-07-24)
Decision record: [ADR 0029](../adr/0029-event-validation-mode-and-validator-registry.md)

## Purpose

This document freezes the exported identifiers and signatures of
`pkg/goSetValidate` so the wiring slices of spec #247 (transport receive paths,
mode policy, metrics) can be drafted against a fixed surface without waiting on
the package to be written twice. A change to anything below is a contract
revision, not a refactor: bump the revision, note what moved, and say which
slices are affected.

## Scope boundary

`pkg/goSetValidate` **reports**, it never rejects. It computes a per-event-URI
`Disposition` and a whole-SET reduction, and returns them. The mode policy
(`NONE` / `WARN` / `ENFORCE` / `STRICT`), the mapping from a disposition to a
transport-specific wire error, and the Prometheus counter all live in the server
wiring (`internal/server` plus the poll receive loop) — never in this package.

Modes are therefore deliberately **absent** from the surface below.

## Import allowlist (hard)

`pkg/goSet`, `pkg/goSet/events`, `pkg/subjectid`, the standard library, and
`github.com/MicahParks/keyfunc` (already a `pkg/goSet` dependency).

No `pkg/ssfModels`, no `pkg/services`, and nothing under `internal/` — per the
standing `pkg/goSet*` package-boundary rule. `TestPackageImportBoundary` parses
the package's own sources and fails the build if a new import escapes the list.

Consequence: **the engaged-URI set is computed by the caller and passed in.** The
package never looks at stream state. That is what keeps it consumable standalone
by a third-party SSF receiver, and what lets an embedder register its own
validators through the same interface. Any `events_delivered` glob expansion is
the caller's job, because the matcher lives in `pkg/ssfModels`.

## Frozen surface

```go
package goSetValidate

// --- dispositions -------------------------------------------------------
type Disposition int

const (
    Valid       Disposition = iota // recognized by an engaged validator, well-formed
    Unsupported                    // no validator engaged for the URI (== out-of-contract)
    Malformed                      // recognized by an engaged validator, failed a check
)

func (d Disposition) String() string
```

Constants are declared in ascending severity, so the whole-SET
"worst-disposition-wins" reduction is a max over the per-URI results. `Valid` is
the zero value, so a zero `SetResult` reads as "nothing to report".

```go
type Result struct {
    EventURI    string
    Disposition Disposition
    Claim       string // failing claim name; empty unless Disposition == Malformed
    Detail      string // human-readable reason; empty unless Disposition == Malformed
}

type SetResult struct {
    Disposition Disposition // worst of Results; Valid for a SET with no events
    Results     []Result    // one entry per event URI in the SET
}
```

```go
// --- validators ---------------------------------------------------------
type Validator interface {
    Validate(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result
}

type ValidatorFunc func(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result

func (f ValidatorFunc) Validate(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result
```

A `Validator` MUST tolerate unknown extra claims and MUST NOT fail on an absent
OPTIONAL or RECOMMENDED claim. `payload` is normalised to a claim map whether the
SET carried a wire JSON object or a typed struct attached in-process via
`AddEventPayload`. `set` is supplied because both SSF stream-management events
put a REQUIRED claim (`sub_id`) at the top level.

```go
// --- registry -----------------------------------------------------------
type Registry struct{ /* unexported fields */ }

func NewRegistry() *Registry
func BuiltinRegistry() *Registry
func (r *Registry) Register(eventURI string, v Validator) *Registry
func (r *Registry) Lookup(eventURI string) (Validator, bool)
```

`Register` returns the receiver so built-in packs and embedder registrations
chain; it is the single entry point for the embedder path. `BuiltinRegistry`
returns a **fresh** registry each call, so one embedder's `Register` cannot
mutate another's view.

```go
// --- per-stream engagement ----------------------------------------------
type ValidatorSet struct{ /* unexported fields */ }

func NewValidatorSet(r *Registry, engagedURIs []string) *ValidatorSet
func (vs *ValidatorSet) Validate(set *goSet.SecurityEventToken) SetResult

const (
    SsfVerificationEventUri  = events.VerificationEventUri  // pkg/goSet/events
    SsfStreamUpdatedEventUri = events.StatusUpdatedEventUri // pkg/goSet/events
)
```

- `NewValidatorSet` unconditionally adds `SsfVerificationEventUri` and
  `SsfStreamUpdatedEventUri` to `engagedURIs`, so a narrowly-scoped `STRICT`
  stream never rejects its own verification handshake.
- A nil `*ValidatorSet` is valid: `(*ValidatorSet)(nil).Validate(set)` returns
  `SetResult{Disposition: Valid, Results: nil}`.
- A nil `*Registry` falls back to `BuiltinRegistry()` so the always-in-contract
  rule still holds for a caller that supplies no registry.

```go
// --- convenience --------------------------------------------------------
func ParseAndValidate(tokenString string, issuerPublicJwks *keyfunc.JWKS, vs *ValidatorSet) (*goSet.SecurityEventToken, SetResult, error)
```

Mirrors `goSet.Parse`'s parameter shape. `vs == nil` degrades to exactly
`goSet.Parse(tokenString, issuerPublicJwks)` plus a zero `SetResult`, with
identical error behaviour. It composes over the **verified** `Parse`, never
`Peek` (ADR-0066 §D3), and a parse failure returns the error unchanged with a nil
token and a zero `SetResult`.

## Deliberate clarification to revision 1

The contract text says `SetResult.Results` carries "one entry per event URI in
the SET, in payload order". `goSet.SecurityEventToken.Events` is a
`map[string]interface{}`, which neither preserves JSON payload order nor iterates
deterministically, so payload order is not recoverable. The implementation emits
results in **stable lexicographic URI order** — the only order a caller, a log
line, or a test can rely on. The worst-disposition-wins reduction is
order-independent, so no consumer semantics change.

## Package move

None. `pkg/goSetValidate` is a new package, a sibling of `pkg/goSet` /
`pkg/goSetPoll` / `pkg/goSetPush` / `pkg/goSetSstp`. Nothing is promoted out of
`internal/`, and core `goSet.Parse` is untouched — it has no receiver context,
and `WARN` mode needs the parsed token even when validation fails.

## Binding ADRs

- **ADR 0066 (planning)** — JWKS-required verified parse: `ParseAndValidate`
  composes over the verified `Parse`, never a `Peek`.
- **ADR 0049 r5 (planning)** — `internal/` stays internal where no cross-repo
  consumer exists; hence the caller-supplied engaged-URI set.
- **Standing `pkg/goSet*` boundary rule** — no `internal/` imports.
- **[ADR 0029](../adr/0029-event-validation-mode-and-validator-registry.md)** —
  the mode enum and the registry-derivation decisions recorded for this package.
