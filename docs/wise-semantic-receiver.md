# Experimental WISE semantic Receiver helpers

This repository's SSF Poll receiver validates the SET transport envelope,
signature, issuer and audience. The proposed Workload Identity Security Events
(WISE) profile adds workload-specific event semantics. This page describes an
**experimental, opt-in** semantic helper for a small high-priority WISE subset.
WISE itself is not an adopted OpenID specification, so this is neither a WISE
conformance claim nor a stable protocol commitment.

The current proposal is published at
https://github.com/identitymonk/openid-wise.

## What is provided

`pkg/goSet/events` exposes:

- WISE event URI constants;
- `ParseWISESET`, which parses four high-priority WISE event types and returns
  a `WISERecommendedAction`;
- `ValidateWISESET`, usable as `goSetPoll.ReceiverConfig.SETValidator`.

The supported events are `workload-compromised`, `credential-compromise`,
`credential-revoked` and `trust-anchor-changed`. The helper checks the WISE
required claims for the latter three and requires the profile's primary `uri`
subject format. It accepts valid absolute URI schemes used by the proposal,
including `wimse`, `spiffe` and `https`; it does not invent a receiver-scoped
opaque-subject profile.

```go
response, _, err := goSetPoll.Poll(ctx, request, goSetPoll.ReceiverConfig{
    EndpointURL:  endpoint,
    JWKS:         issuerJWKS,
    SETValidator: events.ValidateWISESET,
})
```

For a failing validator, `Poll` places an `invalid_request` entry in its
`setErrs` result, ready for the next RFC 8936 polling request. A successful
validator merely means the event is understood; the caller still owns durable
processing and acknowledgement.

## Policy boundary

`WISERecommendedAction` is receiver-local guidance, not a command from the
transmitter. In particular, a `workload-compromised` event can recommend
isolation or credential revocation, but it neither grants authority to act nor
proves that an action occurred. A production integration must bind the finding
to its own authorization, audit, retention and incident-response controls.

## JWKS rollover

`goSet.GetJwks` configures the underlying key resolver with
`RefreshUnknownKID: true`. A new signing `kid` can therefore trigger a JWKS
refresh; the unit test in `pkg/goSet/jwks_loader_test.go` covers an old-plus-new
key rollover. Key revocation remains an operational trust-policy decision: a
Receiver must define how it consumes its trust material and handles a
`trust-anchor-changed` finding.

## Deliberate limits

- No transport retry, policy action, or replay store is implemented by this
  helper.
- Unsupported WISE events are reported as unsupported by this selected subset,
  not as invalid under the WISE proposal.
- Maintainers must decide whether the API and supported subset belong in this
  project before it can be called a maintained WISE Receiver.
