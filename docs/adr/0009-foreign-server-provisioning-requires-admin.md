<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 9. Foreign-server provisioning requires admin scope

Date: 2026-05-31

## Status

Accepted

## Context

A self-registered CLI client is capped at `stream`+`event` at the registration
door (ADR 0006: `reg` is privilege-ceilinged; `admin` is provisioned out of
band). That ceiling is correct for the common case — a SCIM receiver or an
unattended IAT bootstrap creating its **own** stream on the local node.

But two related operations are *privileged* and were not consistently gated:

1. **Registering a foreign SSF transmitter** — `POST /server` (and the rest of
   the `/server` CRUD surface). This stores a credential for, and enables remote
   management of, another party's transmitter.
2. **Creating a stream that targets a foreign transmitter** — `POST /stream`
   with `tx_alias` set. The server resolves the stored foreign-server credential
   and provisions a stream on the remote node's behalf (the TxAlias
   auto-registration path).

Issue #139 originally diagnosed this as an "opaque 403" bug: the CLI
`create stream poll receive --tx-alias` flow calls `POST /server` with a
`stream`-only credential and gets a bare 403. The real defects were twofold:
(a) the authorization gate was inconsistent — `/server` accepted `reg`, and
`/stream` had no discriminator for the privileged `tx_alias` shape; and (b) the
denial leaked as an opaque status instead of actionable guidance. This corrects
#139's original misdiagnosis (it is not a 403-rendering bug; it is an
authorization-model bug).

## Decision

We make foreign-server provisioning **admin-only** (`root` rides free via the
`IsScopeMatch` wildcard), with a discriminator on `/stream`:

- **`POST /stream` without `tx_alias`** — UNCHANGED. Requires `stream` (the
  base `reg`/`stream`/`admin` gate). This is the SCIM-receiver /
  unattended-IAT-bootstrap path configuring only the local node's view; it must
  keep working.
- **`POST /stream` with `tx_alias` set** — requires `admin`. After decoding the
  body, `StreamCreateHandler` checks `tx_alias` against the caller's scope using
  the existing `EventAuthToken.IsScopeMatch([admin])` helper and returns a
  plain-text, actionable 403 otherwise.
- **The five `/server` endpoints** (create, get, update, delete, list) — require
  `admin`. The previous `{reg, admin}` acceptor list drops `reg`; `admin` and
  `root` are the only acceptors.

The `/server` endpoints stay **separate** from `/stream` (they are NOT folded
into stream creation). `/server` registers and manages a foreign transmitter's
credential, which has an independent lifecycle from any stream that later
references it; goSignalsAdmin's console depends on that separate contract. A
single tx-alias stream-create still convenience-registers the transmitter
(`POST /server`) first, but the two endpoints remain distinct.

The CLI mirrors the server rule on both sides: a proactive offline precheck
fails fast when the resolved credential decodes to a goSignals ClientToken whose
scopes lack `admin`/`root` (degrading gracefully — an opaque/IdP token it cannot
classify falls through to the network), and a reactive translation turns a
`401`/`403` from `POST /server` into the same actionable message.

## Consequences

**Positive**

- One consistent rule: foreign-server provisioning is `admin` (`root` free),
  anchored to ADR 0006's scope ladder (`key` → `reg` → `stream`/`event`, with
  `admin` out of band).
- The local-only stream-create path (SCIM receiver, unattended IAT bootstrap)
  is untouched — the regression that #139 risked is explicitly guarded.
- The opaque 403 becomes an actionable message both before the call (offline)
  and after (server-returned), so operators know to use an admin credential.

**Negative**

- A caller that previously used a `reg` (IAT) credential against `/server` now
  needs an `admin` credential. This is the intended tightening, not a
  regression, but it is a behavioural change for any such flow.
- The `tx_alias` discriminator lives in the handler (post-decode) rather than in
  the single up-front scope gate, because the required scope depends on the
  request body.

## Related

- ADR 0006 — the `key` scope and the `reg` privilege ceiling (the scope model
  this anchors to).
- `docs/security_model.md` — endpoint → scope table.
- `pkg/authSupport/auth_token.go` — scope constants and `IsScopeMatch`.
- Issue #139.
