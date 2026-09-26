# gRPC bidirectional SET transfer, a JWE routing envelope, and an agent fabric — exploration note

Date: 2026-09-25
Status: exploration only. This is not a spec. No code, ADR or issue follows from it. If it matures, it becomes a planning spec in `~/git/i2gosignals-planning`.

## TL;DR

- **Protocol.**
    - One bidi RPC: `rpc Exchange(stream Frame) returns (stream Frame)`.
    - Both directions carry `Set`, `Ack`, `SetErr`, `Credit`, `Heartbeat`, `Resume` and `Close` frames.
    - Each `Set` frame carries a compact SET, either JWS or JWE, as opaque bytes.
    - The frames map one-for-one onto the SSTP message model: `sets`, `ack` and `setErrs` [pkg/goSetSstp/message.go:16-33]. That lets the router and DAO seams be reused unchanged.
    - It is SSTP with the HTTP cycle removed, not a new event model.
- **Security model: a nested JWE envelope around the signed SET.**
    - The layering is sign-then-encrypt [RFC7519 §11.2].
    - The JWE protected header carries replicated `iss`/`aud`/`sub` routing claims [RFC7519 §5.3]. Those claims are integrity-protected as AAD but **not confidential** [RFC7516 §2].
    - Every hop can read them, so they must be aliases or pseudonyms, never the real subject.
    - Only the final recipient can check the header's integrity. After decrypting, that recipient must check that the header claims match the inner SET.
- **The envelope is not a whole security model.** It does not give:
    - stream or peer authorization — anyone can encrypt to a public key;
    - ack authenticity;
    - resistance to traffic analysis.
    - **Recommendation:** keep TLS on each hop. RFC 8935 requires it [RFC8935 §5.3], ADR 0076 mandates it, and on a persistent stream it costs one handshake. Let the signature and the envelope authorize and protect the content.
- **Fabric.**
    - The originating edge — the one holding the plaintext — runs `MatchesStream` and encrypts once per audience.
    - Intermediate nodes forward on the envelope's `aud` alias alone, in FORWARD mode.
    - Ack is per hop, for durability. An optional signed end-to-end receipt SET confirms delivery.
    - Loops are stopped by a hop count plus a visited set in the frame, plus jti dedup at every node.
- **Latency.**
    - The HTTP cycle and batch wait disappear.
    - Signing (RS256 at about 820 µs [docs/perf/go127-baseline.md:103]) and Mongo `w:majority` remain the floor.
    - RSA-OAEP decryption is a private-key RSA operation, so it would roughly double that crypto cost; this is unverified and needs measuring. ECDH-ES is the likely choice.

## 1. Protocol sketch

### 1.1 What it replaces

SSTP today works like this:

- **The cycle.** It is one HTTP POST per cycle, and that single cycle carries both directions [docs/SSTP.md:4-11].
- **Holding the connection.** It uses a long poll to hold the cycle open [docs/SSTP.md:255-296].
- **Pushing while a poll is held.** When a poll is already held, a push goes as a second POST [docs/SSTP.md:255-296].
- **Measured throughput.**
    - The initiator runs at 424–520 ev/s with a 2–3 s drain [docs/perf/e2e-history.md:6-30].
    - The responder runs at 625–752 ev/s [docs/perf/e2e-history.md:6-30].

The pkg surface is single-cycle by design:

- `Exchange` sends "no retries, no backoff, no goroutines, no sleeps" [pkg/goSetSstp/dialer.go:80-101].
- The acceptor side is `ParseExchangeRequest` / `WriteExchangeResponse` [pkg/goSetSstp/acceptor.go:108, :155].

A gRPC bidi stream keeps one HTTP/2 stream open, with frames flowing both ways independently. The gRPC docs say of bidi streaming: "the two streams operate independently, so clients and servers can read and write in whatever order they like" [GRPC-CORE].

### 1.2 Proto sketch (illustrative)

```proto
syntax = "proto3";
package i2sig.settransfer.v1;

service SetTransfer {
    // Initiator dials; either side may send SETs once Open/Opened completes.
    rpc Exchange(stream Frame) returns (stream Frame);
}

message Frame {
    oneof body {
        Open      open      = 1;  // first frame from initiator
        Opened    opened    = 2;  // first frame from responder
        SetFrame  set       = 3;
        Ack       ack       = 4;
        SetErr    set_err   = 5;
        Credit    credit    = 6;
        Heartbeat heartbeat = 7;
        Close     close     = 8;  // graceful close or pause, with reason
    }
}

message Open {
    bytes  open_token   = 1;  // signed JWT: iss, aud=responder, pair_id, iat, exp, jti, nonce
    string pair_id      = 2;  // == on-wire stream_id (txSid) as in SSTP
    Resume resume       = 3;
    uint32 initial_credit = 4;
}
message Opened {
    bytes  open_token   = 1;  // responder's signed counter-token (binds both nonces)
    Resume resume       = 2;
    uint32 initial_credit = 3;
}
message Resume {
    repeated string unacked_jtis = 1;  // what I sent and never saw acked
    string high_water_jti        = 2;  // advisory: highest UUIDv7 jti I have durably accepted
}
message SetFrame {
    string jti      = 1;  // copy of the inner/outer jti for dedup without parsing
    bytes  token    = 2;  // compact JWS or compact JWE (opaque; RFC 8935 bytes)
    Hop    hop      = 3;  // fabric only (section 4); never inside the token
}
message Hop {
    uint32 hop_count          = 1;
    uint32 max_hops           = 2;
    repeated string visited   = 3;  // node ids
    string origin_jti         = 4;
}
message Ack    { repeated string jtis = 1; bytes signed_ack = 2; }  // signed_ack optional (section 2.5)
message SetErr { string jti = 1; string err = 2; string description = 3; }
message Credit { uint32 n = 1; }
message Heartbeat { int64 unix_ms = 1; }
message Close  { string reason = 1; bool pause = 2; }
```

### 1.3 Semantics

- **Roles.** The SSTP roles are kept unchanged.
    - The initiator dials out, which keeps the design firewall-friendly [docs/SSTP.md:23-31]. It also holds the `sstp-client:<PairId>` lease.
    - The responder takes no lease [docs/SSTP.md:56-65].
    - One `StreamStateRecord` backs the pair: txSid = PairId, plus rxSid [docs/SSTP.md:35-44].
    - The difference is that the initiator's lease now owns a long-lived RPC instead of a cycle loop.
    - Acks and pending deletions carry the lease's fencing token, as today [CONTEXT.md:408-422, :535-543]. A deposed initiator's late acks are rejected.
- **Window.**
    - HTTP/2 already applies per-stream flow control with WINDOW_UPDATE [RFC9113 §5.2, §6.9].
    - That byte window is not a SET window. An application `Credit` gives "you may send N more SETs", which bounds un-acked SETs per direction.
    - The sender stops at zero credit. The receiver grants more credit after durable acceptance, meaning once the body and marker are written with `w:majority` [docs/adr/0038-ingest-durability-contract.md].
    - Credit is what turns backpressure into something the application can see (section 4.4).
- **Ordering.**
    - The UUIDv7 jti is the ordering contract. It is per stream and bounded by clock skew across nodes [docs/adr/0040-set-delivery-ordering-contract.md:57-120].
    - The sender emits in jti order. The receiver does not rely on arrival order, because retries after a resume can interleave; it recovers order by sorting jti, exactly as a poll or SSTP batch does today.
    - When credit is greater than 1, SETs are in flight at the same time, and acks may arrive out of order.
- **Ack.**
    - `Ack.jtis` is the literal list of accepted jtis. The sender deletes only jtis that it actually sent, the same rule as SSTP [docs/SSTP.md:255-296].
    - There is no cumulative ack. A cumulative ack would conflict with per-jti `SetErr` and with sorting across nodes that have clock skew.
- **Errors.**
    - `SetErr` carries the RFC 8935 `err` and `description` [RFC8935 §2.3, §2.4] and the RFC 8936 `setErrs` value [RFC8936 §2.4.4].
    - The disposition is unchanged: `PartitionSetErrs` sorts each error into Clear, Retry, Fatal or Unrecognized [pkg/goSetSstp/setterr_disposition.go:15-80].
    - A Fatal disposition sends `Close{pause:true}`, the same as a 4xx on SSTP pausing the pair [docs/SSTP.md:255-296].
- **Resume.**
    - On reconnect, each side sends the jtis it believes are un-acked.
    - The peer answers with an `Ack` for any jti it already holds. The jti dedup index makes that safe: a duplicate is acked, not re-stored [docs/adr/0017-jti-is-the-event-dedup-key.md:34].
    - The sender then re-reads its pending set from `GetPendingForStream` [pkg/dao/memory/event_dao.go:208] and resends.
    - `high_water_jti` is advisory only, because of the clock skew noted in ADR-0040.
- **Heartbeat and idle.**
    - gRPC keepalive handles the transport [GRPC-KA].
    - The `Heartbeat` frame is for the application: it shows that the peer's delivery loop is alive, not just that the socket is up.
    - The lease uses 30 s with a 10 s heartbeat [CONTEXT.md:408-422], and the frame heartbeat follows the same timing.
- **Reuse of seams.**
    - Inbound `SetFrame.token` goes to the same parse/verify path SSTP uses: `VerifySET` / `VerifyAll` / `VerifySETX5C` [pkg/goSetSstp/verify.go:149; verify_batch.go:26; verify_x5c.go:58], then on to the rxSid ingest path.
    - Outbound draws from the same `EventPollBuffer` [docs/SSTP.md:255-296].
    - The transport would be a new delivery method URN beside SSTP, not a replacement. That matches ADR-0025's "reusable delivery method" framing [planning docs/adr/0025-sstp-as-reusable-delivery-method.md:5].

### 1.4 Coexistence with ADR-0067 (noted once)

- **What ADR-0067 requires.** The SSTP pkg exports single-cycle primitives, with "no loops, goroutines, sleeps, or seam interfaces". Loops are consumer-owned [planning docs/adr/0067-sstp-exchange-pkg-single-cycle-house-pattern.md:41-58].
- **Why this conflicts.** A bidi stream is not a cycle, and grpc-go runs its own goroutines.
- **Compatible reading.** Put a frame codec and the verify primitives in a new `pkg/goSetStream` (or similar). Keep the stream loop, credit policy and resume in the consumer (the server).
- Whether that satisfies ADR-0067 or needs an amendment is a planning decision, not this note's.

## 2. Security: a JWE envelope around the signed SET

### 2.1 Shape

```
JWE (compact)                                  <- confidentiality + recipient binding
  protected header (AAD: integrity-protected, NOT encrypted):
    alg: ECDH-ES+A256KW | RSA-OAEP-256
    enc: A256GCM
    kid: <recipient enc key id>
    cty: "JWT"                                 <- REQUIRED for nested JWTs [RFC7519 §5.2]
    iss: <issuer routing alias>                <- replicated claim [RFC7519 §5.3]
    aud: <recipient/stream routing alias>
    sub: <pseudonymous routing subject>        <- optional; omit unless a hop must route on it
  ciphertext:
    JWS (compact) = signed SET                 <- integrity + origin [RFC7515], typ secevent+jwt [RFC8417 §2.3]
      iss, aud, jti, iat, sub_id/real subject, events{...}
```

- **Order.** Sign first, then encrypt. RFC 7519 recommends this order because it "prevents attacks in which the signature is stripped … as well as providing privacy for the signer" [RFC7519 §11.2].
- **Compact form.** Both layers stay compact. A JWT is always compact [RFC7519 §1]. RFC 8935 bodies are `application/secevent+jwt` [RFC8935 §2.1]. So the envelope fits the existing push and poll byte model and `SetFrame.token` without change.
- **Existing precedent.** The AI project already seals raw evidence as a JWE (ECDH-ES+A256KW / RSA-OAEP-256, A256GCM) to a per-tenant key using go-jose v4, with attribution nested inside [~/git/i2gosignals-ai/docs/adr/AI-0006-sealed-evidence-on-the-up-leg.md].

### 2.2 What the pieces give, and what they don't

| Property | JWS (inner) | JWE envelope | Header claims |
|---|---|---|---|
| Content integrity | yes [RFC7515] | yes (AEAD) | yes, but only for a CEK holder |
| Origin authenticity | yes — issuer key | **no** — anyone can encrypt to a public key | no |
| Confidentiality of payload / real subject | no | yes | **no** — AAD is "integrity protected but not encrypted" [RFC7516 §2] |
| Confidentiality of the signer's identity | no (`kid`/`x5c` visible) | yes — the JWS header is inside | — |
| Verifiable by an intermediate hop | yes, if it has the issuer JWKS | no | **no** — the AAD tag is only checkable after decrypting |
| Replay protection | only with jti/iat policy | no | no |
| Stream/peer authorization, ack authenticity | no | no | no |

Two points in the table decide the design:

- **Header integrity is verified only at the end.**
    - The AAD tag can be checked only with the CEK, so an intermediate hop routes on header claims it **cannot authenticate**.
    - A hostile hop that edits `aud` breaks the tag, and the recipient rejects the SET. So a hop can misroute or drop, but it cannot forge undetectably.
    - Misrouting at an intermediate hop is therefore a denial-of-service risk, not a forgery risk. Treat routing headers as advisory for delivery and never as authorization.
- **The JWE authenticates no sender.**
    - With ECDH-ES or RSA-OAEP, anyone holding the recipient's public key can produce a valid envelope.
    - Origin comes only from the inner JWS. That matches the family canon, "transport carries, signature authorizes" [planning docs/Security-Protocol-Architecture.md:16, :242], and ownership that latches on the verified SET `iss` [planning docs/adr/0062-connection-bearer-is-channel-auth-only.md:102-106].

### 2.3 Minimizing the header (it is visible to every hop)

RFC 7519 §5.3 makes the application responsible for ensuring "that only claims that are safe to be transmitted in an unencrypted manner are replicated" [RFC7519 §5.3]. RFC 8935 notes that "subject identifiers themselves may be considered sensitive information" [RFC8935 §6]. Proposed rules:

- **`aud` is a routing alias, never an endpoint URL or tenant name.**
    - Use the recipient's stream id, a per-stream opaque alias, or simply the recipient `kid`, which is already in the header.
    - The fabric route table maps alias → next hop.
- **`iss` is an alias or is omitted.**
    - Intermediate hops rarely need the issuer to route. It is useful only for a per-issuer rate limit at the edge.
    - The real `iss` stays inside, where ADR-0066 §4 equality is checked against the stream's configured trust root [planning docs/adr/0066-business-stream-l2-menu-and-none-invariant.md:49-53].
- **`sub` is omitted by default.**
    - If a hop must route on subject — for example, sticky ordering per subject (section 4.4) — use a keyed pseudonym: `HMAC(k_stream, canonical(sub_id))`.
    - The key must be per stream or per recipient, so that two streams cannot link the same user.
    - The real `sub_id` stays only in the encrypted payload.
- **Event type is not replicated.**
    - Event type is what `MatchesStream` filters on [CONTEXT.md:507-517]. Putting it in the header would leak "this is a credential-compromise event" to every hop.
    - Filtering on event type therefore moves to the edge that holds the plaintext (section 4.2).
- **No `zip`.**
    - Compression before encryption leaks length information about the plaintext.
    - The envelope profile should forbid `zip`. This is marked unverified as a specific attack on JWE, but it is the general CRIME class of attack.

### 2.4 Header-substitution / confused-deputy check

- **The rule.** After decryption, RFC 7519 §5.3 says the receiver "SHOULD verify that their values are identical, unless the application defines other specific processing rules" [RFC7519 §5.3]. Because the header uses aliases, the profile must define those rules:
    1. Verify the inner JWS against the stream's configured trust root. No unverified parse and no `alg=none` [planning docs/adr/0066-business-stream-l2-menu-and-none-invariant.md:44-47].
    2. `alias(inner.iss)` must equal `header.iss`, if the header carries `iss`.
    3. `inner.aud` must contain the audience that the header alias maps to on **this** stream, and that must be this receiver.
    4. If `header.sub` is present, it must equal `HMAC(k_stream, inner.sub_id)`.
    5. `header.kid` must be a current `enc` key of this receiver.
    6. Run jti dedup on the **inner** jti.
- **The attack these rules stop.** Mallory captures a genuine signed SET addressed to Bob's stream. She re-encrypts it to Alice's public key and puts `aud=<alice-alias>` in the header.
    - The JWE is valid. The inner signature is valid.
    - Only check 3 stops Alice from processing an event that was never addressed to her.
    - This is the same confused-deputy rule that ADR-0062 already applies to bearers: channel credentials do not decide who authorized the event; the SET does [planning docs/adr/0062-connection-bearer-is-channel-auth-only.md:88-101].
- **Failure codes.** A mismatch is a hard `SetErr`: `invalid_request` for claim mismatch, or `invalid_key` for a rejected encryption key [RFC8935 §2.4]. The pkg already has `ErrJwe` for decryption failure [pkg/goSetSstp/errcode.go:20-22] and maps `ErrJweDecryptionFailed` onto it [pkg/goSetSstp/adapter.go:42-43].

### 2.5 What the envelope still does not cover

| Gap | Why | What covers it |
|---|---|---|
| Who may open a stream / consume credit | Anyone can encrypt to a public key and flood a queue | Signed `Open` token bound to a configured peer, plus TLS/mTLS peer auth |
| Ack authenticity | Acks are control frames, not SETs. A forged `Ack` makes the sender delete events: **silent loss** | Acks ride an authenticated channel (TLS plus the `Open` binding). Optionally a signed ack JWT over `{pair_id, jtis[], fencing}`, costing one sign per ack batch, not per event |
| Replay | The envelope has no freshness | Inner jti dedup [docs/adr/0017-jti-is-the-event-dedup-key.md:34] plus an `iat` window |
| Traffic analysis | Sizes, timing, frequency and the stable header aliases link events | Only partly addressable: padding buckets, alias rotation, TLS hiding headers from on-path observers |
| Downgrade | A peer sends a plain JWS where a JWE was expected | Per-stream policy `require_jwe`. Plain JWS is refused with `SetErr` and never silently accepted |
| Key compromise at the recipient | All past envelopes to that `kid` become readable | Rotation (2.6). ECDH-ES gives no forward secrecy against a static recipient key |

### 2.6 Recipient key discovery and rotation

- **What already exists.**
    - Key records carry `Use` "sig" | "enc" [pkg/dao/dao_interfaces.go:298].
    - The JWKS publisher sets `use: enc` for enc records [pkg/services/key_service.go:981-985].
    - The `KeyState` lifecycle is active / suspended / revoked / expired / not-yet-valid, with `StatusAt` derived from the clock [pkg/dao/dao_interfaces.go:506-527].
- **What is missing.**
    - `CreateKeyPair` mints RSA only [pkg/services/key_service.go:134-140], so encryption today would be RSA-OAEP-256. ECDH-ES+A256KW needs an EC enc key type.
    - There is no JWE producer or consumer in the codebase. The AI project noted there was no producer at community alpha.17 [~/git/i2gosignals-ai/docs/adr/AI-0006-sealed-evidence-on-the-up-leg.md], and a code search found no `NewEncrypter` in this repo.
    - SSF transmitter metadata defines a `jwks_uri` [SSF §7]. Whether SSF defines where a **receiver** publishes its encryption keys is unverified; it appears not to. The receiver's encryption key would then need to be stream configuration: a pinned JWK or an `rx_enc_jwks_uri`.
- **Rotation rules.**
    - The encryptor picks only `StatusAt(now) == active` enc keys.
    - The decryptor keeps suspended and expired keys for a grace window, because envelopes in flight and stored may name the old `kid`.
    - Revoked keys decrypt nothing. The sender receives `invalid_key` and re-encrypts to the new key.
    - Stored-then-forwarded envelopes cannot be re-encrypted by an intermediate hop, because it has no plaintext. The origin must re-send them, or the fabric's retention must be shorter than the key grace window.
    - This connects to the i2goSignals#318 validity work reflected in `KeyState`.

### 2.7 Is TLS still worth it per hop? Yes

- **RFC 8935 requires it.** "TLS MUST be used to secure the transmitted SETs. In some use cases, encrypting the SET as described in JWE … will also be required" [RFC8935 §5.3]. The standard treats JWE as additive to TLS.
- **RFC 8417 explains why the two are separate.** Even with JWE end to end, "without (mutual) TLS, there is no assurance that the correct endpoint received the SET" [RFC8417 §5.2].
- **TLS covers what the envelope leaves open.**
    - It hides the routing header, the `Hop` frame, acks and credits from on-path observers.
    - It authenticates the peer, which closes the stream-authorization and ack-authenticity gaps in 2.5 at almost no cost.
- **Cost on a persistent stream.** One handshake per connection. The earlier finding that handshakes were about 17% of CPU was a per-cycle cost that pooling removed [pkg/goSetSstp/dialer.go:182-189].
- **Family canon already mandates it.**
    - Business dials are TLS unless `tx_allow_plaintext` is set [planning docs/adr/0076-business-stream-transport-tls-by-default-dev-overrides-retired.md:39-48].
    - Control streams are mTLS-only [same ADR, :50-53; planning docs/adr/0063-control-stream-mtls-only-channel-auth.md].
    - ADR-0066 §2 allowed L2=None only with L3 enforced [planning docs/adr/0066-business-stream-l2-menu-and-none-invariant.md:37-42]. ADR 0076 now presumes TLS beneath that.
    - "Security from SET/JWT alone" would need `tx_allow_plaintext` on every hop. The envelope does not change that trade, so this note does not argue for it (conflict noted once).
- **Recommendation.**
    - Adopt the envelope as the **content** security invariant: confidentiality of payload and subject end to end, even through untrusted hops.
    - Keep TLS as the per-hop **channel** layer.
    - Let authorization come only from the verified inner SET.
    - The trust-profile layering belongs in planning#94 (layered delivery trust profiles) and #99 (fail-closed defaults), both OPEN.

### 2.8 Cost

- **Existing crypto costs.**
    - Signing already dominates the crypto budget: RS256 sign costs about 820 µs per SET [docs/perf/go127-baseline.md:103].
    - An ML-DSA sign costs 352 µs and a verify 99 µs; an RS256 parse costs 31 µs [docs/perf/go127-baseline.md:309].
    - In PB (re-sign) route mode, RSA re-signing was 41% of goSignals1 CPU [docs/perf/e2e-benchmark.md:263-275].
- **What the envelope adds per event per audience.** All figures below are unverified and need measuring.
    - **RSA-OAEP-256.** Encrypting is a public-key operation and cheap, tens of µs. **Decrypting is a private-key RSA-2048 operation**, costing roughly as much as an RS256 sign — about 1 ms. With RSA enc keys, the recipient's crypto cost roughly doubles.
    - **ECDH-ES+A256KW (P-256).** One ephemeral scalar multiplication plus ECDH to encrypt, and one ECDH to decrypt. That is likely tens to low hundreds of µs each side, far below RSA decryption.
    - **A256GCM** over a few-KB SET is negligible (µs).
- **Net effect.**
    - With EC enc keys and a non-RSA signer (ES256 or ML-DSA), the envelope adds less than the current RS256 signing.
    - With RSA enc keys it is the most expensive step at the recipient.
    - Hop-by-hop TLS adds only AES-GCM record cost once the stream is up.
- **Where the cost lands.** It is paid once at the origin (per audience) and once at the final recipient. **Intermediate hops pay nothing**: they parse a base64 JSON header without verifying or decrypting. That is cheaper than today's FORWARD hop, which already skips signing [CONTEXT.md:196-240].

## 3. Latency

- **Where the win comes from.**
    - **The HTTP cycle and batch wait are removed.** The responder currently acks the previous batch, fetches and signs the next, and only then answers. The initiator waits for that answer before its next request [docs/perf/e2e-benchmark.md:244-261]. On a bidi stream, acks and new SETs flow independently: the RTT stops being paid per batch and is paid once per window.
    - **Pipelining.** A credit window lets N SETs be in flight. The strictly sequential push loop (sign, deliver, ack, one at a time) was called "the largest remaining structural gain" [docs/perf/e2e-benchmark.md:286-290]. Push measured 108 ev/s serial against 398 pooled [docs/adr/0040-set-delivery-ordering-contract.md].
    - **No per-exchange framing.** There is no per-exchange HTTP request/response or JSON envelope parse. This is small beside the crypto and Mongo costs.
- **What does not move.**
    - Ingest p50/p99 is 16.6–24.9 / 52–94 ms [docs/perf/e2e-history.md:6-30], and it is bounded by Mongo durability and signing.
    - The earlier per-event Mongo round trip of about 10 ms bounded each leg to about 100 ev/s [docs/perf/e2e-benchmark.md:275-281].
    - gRPC saves transport milliseconds but not durability milliseconds.
    - The envelope adds the costs in 2.8.
- **What to benchmark against the e2e baseline.** Use the same harness and topology [docs/perf/e2e-benchmark.md:10, :63-67] and the SSTP-by-role rows.
    1. **ev/s and drain after ingest**, per role, for SSTP against gRPC. The same 5000 events, concurrency 16.
    2. **Per-SET delivery latency**, from ingest 202 to receiver `events_in_total`: p50/p99. This needs a timestamp per jti, not only drain.
    3. **Ack RTT distribution**, from `SetFrame` send to `Ack` receive, and its sensitivity to the credit size (1, 8, 32, 128).
    4. **Envelope cost matrix**: {RS256, ES256, ML-DSA} × {none, RSA-OAEP-256, ECDH-ES+A256KW}. Run as micro-benchmarks, as in go127-baseline, and then end to end.
    5. **Idle cost**: CPU and bytes/s for an idle pair (heartbeat against SSTP long-poll cycling).
    6. **Resume correctness under a kill**: count lost and duplicated jtis across a node kill mid-window.

## 4. Fabric for the AI project

### 4.1 Topology

```
 hook ──(UDS/loopback, Signed Request)──▶ relay (per domain) ══bidi══▶ goSignals node ══bidi══▶ goSignals node ──▶ engine / tenant
 hook ──┘                                   ▲   store-and-forward        (edge: has plaintext?)      (core: routes on aud)
 (Tier 0: local decision, no network)        └── bundles down (AI-0005 per-hop cursor)
```

- **Today.**
    - The hook decides PreToolUse locally, with no network call. It then fire-and-forgets the Decision Event to the relay at `127.0.0.1:4173` [~/git/i2gosignals-ai/README.md:683-697].
    - The relay multiplexes hooks up and bundles down, stores and forwards, and is transitional [~/git/i2gosignals-ai/CONTEXT.md:63-69].
    - There is one relay per operational domain [~/git/i2gosignals-ai/CONTEXT.md:56-61].
    - Both AI binaries are SSTP initiators and goSignals is the responder [~/git/i2gosignals-ai/CONTEXT.md:38-46].
    - The unscheduled ai#14 plans relay-per-domain, two-tier registration and the `instance | domain | tenant | global` scope ladder [planning docs/spec-inventory.md:176-183]. The domain URN is defined in ADR 0075.
- **Fabric proposal.**
    - Each relay holds one persistent bidi stream (section 1) to one or more goSignals nodes. Holding more than one gives failover.
    - goSignals nodes peer over bidi links too — ADR-0025's cluster-gateway use case [planning docs/adr/0025-sstp-as-reusable-delivery-method.md:5].
    - The fabric is a small mesh of long-lived, TLS-protected, credit-controlled links.
- **Load.** It is low: about 9,500 Decision Events per day for a modelled 50-instance tenant, or about 0.11 ev/s on average but bursty [~/git/i2gosignals-ai/docs/research/content-keyed-write-read-2026-09-11.md:134-137]. The design is driven by **latency on the down leg** — halt delivery to the hook — and by resilience, not by throughput.

### 4.2 Routing: content routing at the edge, destination routing in the core

- **The constraint.** With the envelope, a hop that does not hold the recipient key sees only `aud` (and perhaps a pseudonymous `sub`). `MatchesStream` needs direction, iss, aud and event type [CONTEXT.md:507-517], so it cannot run in the core on encrypted content.
- **Edge (the holder of the plaintext).**
    - This is the node where the SET is created, or first decrypted by a trusted node.
    - It runs `EventService.MatchesStream` and the `EventSource` selector (EXPLICIT / DIRECT / AUDIENCE) [CONTEXT.md:196-240].
    - It then encrypts once per matched audience: sign once, encrypt N times (see 4.3).
    - For the AI up-leg, the edge is the hook or relay, which signs as issuer [~/git/i2gosignals-ai/docs/adr/AI-0012-business-sets-pass-through-hook-signs-as-issuer.md].
- **Core (every other hop).**
    - It forwards on `header.aud → next hop` from a route table, as a FORWARD-mode hop. A forwarder "neither verifies nor signs" today [CONTEXT.md:196-240], and now it does not decrypt either.
    - The route table is configuration, alongside stream config, keyed by audience alias.
- **Ownership in the cluster.**
    - Each outbound link is owned through a ClusterCoordinator lease, `sstp-client:<PairId>` or its gRPC analogue.
    - Fencing tokens stop a deposed owner's sends or acks from counting [CONTEXT.md:408-422, :535-543].
    - Inbound links need no lease (responder role). The cluster wake-up route (`/_cluster/wake-sstp-client`, [docs/SSTP.md:297-300]) nudges the lease holder when a new SET is queued for its link.
- **Conflict with AI-0012.**
    - AI-0012 (Proposed) has goSignals **validate** the hook's SET and re-publish in FORWARD mode with the signature intact.
    - Validation needs the plaintext JWS, so if the envelope is encrypted to the engine, goSignals cannot validate.
    - Choose one:
        - (a) encrypt to goSignals as a trusted edge, which decrypts, validates, runs `MatchesStream` and re-encrypts to the engine; or
        - (b) goSignals is a pure core router, and validation moves to the engine.
    - (a) preserves today's routing semantics. (b) is the privacy-maximal fabric.

### 4.3 Fan-out to multiple audiences

| Option | How | Verdict |
|---|---|---|
| JWE JSON serialization, multi-recipient | One ciphertext, one wrapped CEK per recipient [RFC7516 §7.2] | **No.** It is not a JWT: JWTs are compact only [RFC7519 §1], so it breaks the RFC 8935 body model. The shared protected header can carry only one `aud`. Per-recipient headers are **not integrity-protected** [RFC7516 §7.2.1]. Every recipient learns every other recipient's `kid`. Any recipient can use the CEK to fabricate content for the others (the inner JWS still catches it, but confidentiality-of-origin is lost). go-jose also refuses `ECDH-ES` direct mode with multiple recipients [go-jose v4.1.5 crypter.go:255-257] |
| Re-encrypt per audience at the edge | Sign once, then N compact JWEs, each with its own `aud` header | **Yes.** It keeps the compact form, per-audience headers and per-stream jti dedup. The extra cost is N × encrypt, which is cheap with EC keys (2.8) |
| Fan-out at a core hop | The core hop decrypts and re-encrypts | Only when that hop is a trusted edge (4.2 option a) |

The same inner jti in N envelopes is fine. Dedup is per stream, and ADR-0040 ordering is per stream.

### 4.4 Backpressure and ordering across hops

- **Credit is hop-by-hop.** Each link grants credit only as fast as it can durably accept.
    - A core node forwards to its next hop within that hop's credit.
    - Excess is buffered durably, for example in the `EventPollBuffer`/pending store, so a slow downstream fills the intermediate buffer before it pushes back upstream.
    - That is store-and-forward, as the relay already does [~/git/i2gosignals-ai/CONTEXT.md:63-69].
    - End-to-end credit is rejected for the same reason AI-0005 gives: one slow consumer would pace everyone.
- **Fan-out isolation.** Every audience gets its own outbound queue and credit. A stalled audience must not stall its siblings; this is the per-stream isolation the router already has.
- **Ordering.**
    - Ordering is per stream, by UUIDv7 jti, and the receiver recovers it by sorting (ADR-0040).
    - Across hops with failover links, arrival order is not preserved, and the design does not need it to be.
    - If a consumer needs order per subject, the edge can pin a subject to a link using the pseudonymous `sub` hash (2.3).
    - That is the only reason to replicate `sub` into the header.

### 4.5 Loop prevention

- **Hop metadata travels in the `Hop` frame, not in the SET or JWE.** The protected header cannot be changed without breaking the AEAD tag, and hop state must change on every hop.
- **Guards.**
    - `hop_count` / `max_hops` is a hard stop. It sends `SetErr{err:"invalid_request"}` back one hop and logs a WARN.
    - `visited` node ids stop short cycles.
    - `origin_jti` plus the inner jti dedup index is the backstop [docs/adr/0017-jti-is-the-event-dedup-key.md:34]. A node that sees a jti it already holds acks and drops it, which breaks any cycle the first two guards miss.
- **Limit.** The `Hop` frame is unauthenticated between hops beyond TLS. A hostile hop can reset the hop count, but jti dedup still bounds the damage to one extra delivery per node.

### 4.6 End-to-end ack against per-hop ack

- **Per-hop ack means custody transfer.** "I have durably stored it; you may delete it." This is the durability contract, and it matches AI-0005, which explicitly rejects end-to-end acks on the down leg because one offline laptop would pace the domain [~/git/i2gosignals-ai/docs/adr/AI-0005-bundle-cascade-and-directional-validity.md].
- **End-to-end confirmation, where it is wanted.** For example, "the engine has the evidence", or "the hook applied the halt". The final recipient emits a signed **receipt SET** back toward the origin: an event type carrying `origin_jti`, signed by the recipient's key.
    - It is a normal SET, so it rides the same fabric, is authenticated end to end, and needs no new ack semantics.
    - No such event type exists in this repo; it would be a family extension (unverified whether SSF/CAEP defines one).

### 4.7 Untrusted intermediaries: route but not forge

| An intermediate hop can | It cannot |
|---|---|
| Read the routing aliases in the header, sizes and timing | Read the payload or the real subject (JWE) |
| Drop, delay, reorder or duplicate | Forge or alter content (inner JWS, AEAD tag) |
| Misroute by editing `aud` — detected at the recipient as a tag failure | Re-address a genuine SET to a new audience that accepts it (check 2.4.3) |
| Replay | Get a replay accepted (inner jti dedup) |
| Forge a per-hop `Ack` to its upstream | Forge an end-to-end receipt SET (signed) |

So per-hop acks rely on trusting the next hop's custody. Where that trust is absent, the origin keeps the SET until the signed receipt arrives. This is a per-stream policy choice.

### 4.8 Comparison with NATS JetStream and Kafka

| | This fabric | NATS JetStream | Kafka |
|---|---|---|---|
| Unit | Signed/encrypted SET, jti-keyed | Message on a subject | Record in a partition |
| Routing | Edge `MatchesStream`, core by `aud` alias | Subject wildcards [NATS-JS] | Topic/partition key (unverified detail) |
| Ack | Per-hop custody, plus an optional signed e2e receipt | Explicit ack per consumer, with MaxAckPending as the in-flight window ("MaxAckPending set too low limits throughput") [NATS-CONS] | Consumer offsets; cumulative per partition (unverified detail) |
| Dedup | jti unique index (ADR-0017) | Publish dedup window keyed by `Nats-Msg-Id` (unverified — not fetched) | Idempotent producer / transactions (unverified detail) |
| Ordering | Per stream by UUIDv7 sort | Per stream/subject (unverified detail) | Per partition (unverified detail) |
| Payload security | End-to-end JWS + JWE; intermediaries cannot read or forge | TLS/NKeys at the transport; payload opaque unless the app encrypts (unverified detail) | TLS/SASL at the transport; payload opaque unless the app encrypts (unverified detail) |
| Fits SSF/RFC 8935/8936 | Natively, with the same bytes | Would need a gateway | Would need a gateway |
| Ops | Existing Mongo + lease cluster | New cluster | New cluster, heavier |

- **Why a broker is not the answer.** Both brokers are a sound substrate for a single operator's internal bus. But neither provides end-to-end signed and encrypted content across trust domains; the envelope would still be needed on top.
- **Where a broker could fit.** A broker could later replace the core tier (4.2) inside one tenant without changing the envelope, because the core only needs `aud`-keyed forwarding.

## 5. Open questions and next steps

### 5.1 Open questions

1. **Does the bidi stream fit the ADR-0067 house pattern** — a stream-frame codec in `pkg`, with the loop in the consumer — or does ADR-0067 need an amendment? (Planning.)
2. **Should the envelope be encrypted to goSignals (a trusted edge) or to the engine (goSignals as a pure router)?** This decides the AI-0012 validate-then-FORWARD path and whether `MatchesStream` runs in the core (4.2).
3. **Where does a receiver's encryption key come from?** Options are a pinned JWK, an `rx_enc_jwks_uri`, or an SSF metadata extension. Whether SSF defines this is unverified.
4. **Which envelope algorithm profile?** ECDH-ES+A256KW (P-256) is the likely default. RSA-OAEP-256 costs RSA-private per decrypt. A post-quantum KEM for JWE would be a draft only — unverified.
5. **Minimum header claim set per stream profile.** Is `aud`-alias-only enough for AI routing, or is the per-subject pseudonym needed for ordering?
6. **Ack authenticity.** Is TLS plus the `Open` binding enough, or are signed ack batches required for streams that cross untrusted hops?
7. **Retention against key rotation.** How long may a core hop hold an envelope before the recipient's `kid` leaves its decrypt grace window?
8. **Receipt SET event type.** Does an existing profile cover it, or does the family define one?

### 5.2 Prototype scope (smallest useful)

- **Transport.** A two-node gRPC `Exchange` between goSignals1 and goSignals2 in the e2e harness.
    - Frames: `Set`, `Ack`, `SetErr`, `Credit`, `Heartbeat`, `Resume`.
    - It reuses `VerifyAll`, `PartitionSetErrs`, `EventPollBuffer` and `GetPendingForStream`.
    - No fabric, no envelope. Measure items 1, 2, 3, 5 and 6 of section 3.
- **Envelope micro-benchmark** (item 4 of section 3) using go-jose v4, which is already a dependency [go.mod:14], with compact nested JWE and EC and RSA enc keys.
- **Dependency.** `google.golang.org/grpc` is currently only indirect [go.mod:52]. Promoting it to direct needs `make licenses-check`; it is Apache-2.0 (unverified here).
- **Fabric after both.** Three nodes: relay → core → engine. Use `aud`-alias routing and hop guards, kill the core mid-window, and count loss and duplication.

### 5.3 What planning would need (if this matures)

- **Specs.**
    - A **spec** for the gRPC delivery method: URN, frame model, credit, resume, lease ownership.
    - A **spec** for the JWE envelope profile:
        - the header claim rules;
        - the post-decrypt equality checks (2.4);
        - the algorithms;
        - `require_jwe` downgrade policy;
        - receiver enc-key configuration and rotation.
- **ADRs.**
    - The **ADR** on content-layer confidentiality as an invariant beside TLS. Home: planning#94, trust profiles.
    - The **ADR** or amendment for ADR-0067.
    - The **ADR** on edge-content routing against core destination routing for the fabric.
- **Settled inputs, not to be reopened.** ADR 0076 (TLS by default), ADR-0066 (L3 verification, no unverified parse), ADR-0062 (the bearer is channel auth only), ADR-0017 and ADR-0040.
- **Cross-repo seams to flag.**
    - **community**:
        - the frame codec and verify primitives in `pkg`;
        - the JWE producer/consumer (the `ErrJwe` path exists, but no code does);
        - EC enc keys in `KeyService`.
    - **ai**:
        - relay and hook as stream initiators;
        - hook-as-issuer signing (AI-0012);
        - sealed evidence (AI-0006) converging on the same envelope profile;
        - ai#14 domain relay and the ADR 0075 domain URN as the route-table key.
    - **enterprise/tenancy**: per-tenant enc keys and route-table configuration, if the fabric is multi-tenant.
    - **admin**: key `use=enc` management and stream `require_jwe` in the UI.
    - **planning**: #94 and #99, both OPEN, as homes for the trust profile and its fail-closed defaults.

## Unverified claims

- **Crypto costs.**
    - The RSA-OAEP-256 decrypt cost (assumed to be about an RS256 sign, roughly 1 ms) has not been measured.
    - The ECDH-ES P-256 cost ("tens to low hundreds of µs") has not been measured.
    - The AES-GCM cost has not been measured.
- **Compression.** That `zip` before encryption leaks plaintext length in a way that is exploitable for JWE specifically is inferred from the general CRIME class of attack. No JOSE-specific source was fetched.
- **SSF receiver keys.** Whether SSF defines publication of a receiver's encryption key was not found. Only the transmitter `jwks_uri` (SSF §7) was seen.
- **Brokers.**
    - The NATS JetStream `Nats-Msg-Id` dedup window, subject ordering and security model are from knowledge and were not fetched. Only the MaxAckPending sentence was fetched.
    - The Kafka offsets, partition ordering, idempotent producer and security model are from knowledge and were not fetched. The Kafka docs URL resolves.
- **Receipt event.** No check was made for an existing SSF/CAEP "receipt" event type.
- **Licensing.** The grpc-go Apache-2.0 license was not checked against `make licenses-check`.
- **Post-quantum KEM.** A PQ KEM profile for JWE was not researched.
- **The gRPC design as a whole.** No gRPC code was run. All throughput effects in section 3 are hypotheses to benchmark.

## Sources

External:

- [GRPC-CORE] https://grpc.io/docs/what-is-grpc/core-concepts/ — bidirectional streaming; the "two streams operate independently" quote (fetched).
- [GRPC-FC] https://grpc.io/docs/guides/flow-control/ — gRPC flow control (fetched).
- [GRPC-KA] https://grpc.io/docs/guides/keepalive/ — keepalive (URL resolves; content not quoted).
- [GRPC-GO] https://pkg.go.dev/google.golang.org/grpc
- [RFC9113] https://www.rfc-editor.org/rfc/rfc9113 — HTTP/2 §5.2 flow control, §6.9 WINDOW_UPDATE.
- [RFC8417] https://www.rfc-editor.org/rfc/rfc8417 — §2.3 explicit typing; §5.1 "personally identifiable information MUST be encrypted using JWE … or secured for confidentiality by other means"; §5.2 the "without (mutual) TLS" quote (fetched).
- [RFC8935] https://www.rfc-editor.org/rfc/rfc8935 — §2.1 media type; §2.3/§2.4 error codes incl. `invalid_key`; §5.3 "TLS MUST be used … JWE … will also be required"; §6 subject identifiers as sensitive (fetched).
- [RFC8936] https://www.rfc-editor.org/rfc/rfc8936 — §2.4.4 poll with ack and errors.
- [RFC7515] https://www.rfc-editor.org/rfc/rfc7515 — JWS.
- [RFC7516] https://www.rfc-editor.org/rfc/rfc7516 — §2 AAD definition, "integrity protected but not encrypted"; §7.2 / §7.2.1 JSON serialization and the unprotected-header rules (fetched).
- [RFC7518] https://www.rfc-editor.org/rfc/rfc7518 — §4.6 ECDH-ES.
- [RFC7519] https://www.rfc-editor.org/rfc/rfc7519 — §1 compact-only; §5.2 `cty: "JWT"` required for nesting; §5.3 replicating claims as header parameters; §11.2 sign-then-encrypt (fetched).
- [SSF] https://openid.net/specs/openid-sharedsignals-framework-1_0.html — transmitter `jwks_uri` (§7).
- [NATS-JS] https://docs.nats.io/nats-concepts/jetstream
- [NATS-CONS] https://docs.nats.io/nats-concepts/jetstream/consumers — the MaxAckPending sentence (fetched).
- [KAFKA] https://kafka.apache.org/documentation/
- go-jose v4.1.5 module source (`~/go/pkg/mod/github.com/go-jose/go-jose/v4@v4.1.5/crypter.go:86-100, :218-257`) — `ExtraHeaders` / `WithHeader` for replicated claims; `NewMultiEncrypter` rejects `DIRECT` / `ECDH_ES`.

Repository (community `release-0.12.0` @ 17bb532; planning `main` @ ac579d2; ai `main` @ fe3057b):

- `pkg/goSetSstp/message.go:1-33, :64-70`
- `pkg/goSetSstp/dialer.go:26-101, :182-189`
- `pkg/goSetSstp/acceptor.go:66, :108, :155`
- `pkg/goSetSstp/verify.go:149`
- `pkg/goSetSstp/verify_batch.go:26`
- `pkg/goSetSstp/verify_x5c.go:58`
- `pkg/goSetSstp/setterr_disposition.go:15-80`
- `pkg/goSetSstp/errcode.go:20-22`
- `pkg/goSetSstp/adapter.go:42-43`
- `pkg/dao/dao_interfaces.go:298, :506-527`
- `pkg/services/key_service.go:134-140, :981-985`
- `pkg/dao/memory/event_dao.go:208`
- `go.mod:14, :16, :52-53`
- `docs/SSTP.md:4-65, :100-105, :255-300`
- `CONTEXT.md:22-37, :196-240, :408-422, :430-455, :507-517, :535-543`
- `docs/adr/0017-jti-is-the-event-dedup-key.md:34`
- `docs/adr/0038-ingest-durability-contract.md`
- `docs/adr/0040-set-delivery-ordering-contract.md:57-120`
- `docs/perf/e2e-history.md:6-30`
- `docs/perf/e2e-benchmark.md:10, :63-67, :244-290`
- `docs/perf/go127-baseline.md:103, :309`
- `docs/perf/homa-sstp-research.md` — the §8 note that gRPC bidi is a protocol change, not a transport swap.
- planning:
    - `docs/adr/0025-sstp-as-reusable-delivery-method.md:5`
    - `0062-…md:88-106`
    - `0063-control-stream-mtls-only-channel-auth.md`
    - `0066-…md:33-59`
    - `0067-…md:41-58, :79-82`
    - `0075-domain-urn-type-for-agent-fleets.md`
    - `0076-…md:39-53, :85-110`
    - `docs/Security-Protocol-Architecture.md:16, :242`
    - `docs/spec-inventory.md:153, :176-183`
    - issues #94 and #99 (OPEN).
- ai:
    - `CONTEXT.md:38-83, :131-171`
    - `README.md:683-697`
    - `docs/configuration_properties.md:300-315`
    - `docs/adr/AI-0001-relay-is-a-package-and-tier-numbering.md`
    - `AI-0005-bundle-cascade-and-directional-validity.md`
    - `AI-0006-sealed-evidence-on-the-up-leg.md`
    - `AI-0012-business-sets-pass-through-hook-signs-as-issuer.md`
    - `docs/research/content-keyed-write-read-2026-09-11.md:134-137`
