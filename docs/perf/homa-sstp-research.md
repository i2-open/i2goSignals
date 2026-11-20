# Homa / go-homa as an SSTP transport — research note

Date: 2026-09-25
Status: research only. No code, ADR, or issue follows from this note.

## TL;DR

Homa does not fit SSTP, and go-homa is not usable today.

- **Homa's gain is in microseconds; SSTP's latency is in milliseconds.**
    - Homa's measured win is about 8 µs of round-trip time for a 100-byte message on a single-switch datacenter cluster: 15.1 µs against TCP's 23.4 µs [ATC21 Table 2].
    - SSTP end-to-end latency on our benchmark is milliseconds. Ingest p50 is about 12–25 ms and p99 is 22–117 ms [e2e-history]. RSA-2048 signing alone costs about 820 µs per SET [go127-baseline:103].
    - Homa would move the number by less than 0.1%.
- **go-homa is abandoned and ABI-incompatible.**
    - It has had no commits since 2024-02-21.
    - It targets the pre-2025 kernel ABI: protocol number 253 instead of the IANA-assigned 146, recvmsg flags that were removed, old struct layouts, and old ioctl numbers.
    - Its I/O uses blocking raw syscalls outside the Go netpoller.
- **Homa has no encryption.** Using it would break the business-stream TLS floor (ADR-0066 §2 as amended by ADR 0076). Adding encryption to Homa is still academic work (SMT, IEEE S&P 2026).
- **Homa is hard to deploy.**
    - It needs an out-of-tree Linux kernel module, loaded privileged.
    - It is not in mainline Linux. The upstream subset is described by its author as performing "about the same as TCP".
    - It uses a raw IP protocol, and needs specific NICs plus switch priority queues for its headline numbers.
    - It is Linux-only.
- **Recommendation: do not adopt Homa, and do not run a Homa experiment now.** If SSTP latency matters, look at HTTP/2 connection reuse, the signing algorithm, and batching.

## 1. What SSTP does today (the fit baseline)

- **Shape of an exchange.**
    - Each SSTP exchange is one HTTP(S) `POST /sstp/{id}` with `Content-Type: application/sstp+json` [pkg/goSetSstp/http.go:11-18].
    - That one HTTP cycle carries both directions [docs/SSTP.md:9-11].
- **The initiator dials out.** The doc calls this a "firewall-friendly exchange where the initiator dials out" [docs/SSTP.md:28-31].
- **The initiator long-polls.**
    - The long poll reuses `I2SIG_POLL_DEFAULT_TIMEOUT`, and there is a push-while-poll-held path [docs/SSTP.md:255-300, 288-291].
    - In steady state the connection is held open waiting for events, so wire RTT is not what gates latency.
- **The TLS floor is enforced at the dialer.**
    - `DialerConfig.AllowPlaintext` carries the floor [pkg/goSetSstp/dialer.go:26-60].
    - `Exchange` refuses plaintext unless the operator opts in [pkg/goSetSstp/dialer.go:92-101].
    - The operator opt-out is `tx_allow_plaintext` [docs/SSTP.md:101-104].
- **Transports are pooled.**
    - Each transport is a clone of `http.DefaultTransport` with TLS 1.2 minimum, hardened, and `MaxIdleConnsPerHost` set to 64 [pkg/goSetSstp/dialer.go:73-78, 182-230].
    - Pooling was adopted because per-call clients forced a TLS handshake on every cycle, which cost "~17% of the receiver node's CPU in crypto/tls.(*Conn).clientHandshake" [pkg/goSetSstp/dialer.go:182-189].
    - That was a real transport-level win, and it came from connection reuse, not from a new protocol.
- **Measured throughput.**
    - The benchmark topology is harness → goSignals1 → goSignals2, with one SSTP pair, TLS, and MongoDB in the loop [docs/perf/e2e-benchmark.md].
    - SSTP throughput is about 424–520 ev/s on the initiator leg and 625–752 ev/s on the responder leg, with 0.5–3 s drain (spec102, 2026-09-08) [docs/perf/e2e-history.md:10-23].
- **Crypto costs dwarf wire RTT.**
    - JWS sign is about 820 µs (RS256) [docs/perf/go127-baseline.md:103].
    - ML-DSA sign is 352 µs and verify is 99 µs, against 31 µs for an RS256 parse [docs/perf/go127-baseline.md:309].
    - Each of these is 10–100x Homa's entire RTT saving.

## 2. Homa: design and latency claims

- **SIGCOMM'18** [HOMA18]
    - Homa is receiver-driven: SRPT scheduling, grants, and in-network priority queues.
    - Claim: "99th percentile round-trip times less than 15μs for short messages on a 10 Gbps network running at 80% load".
- **USENIX ATC'21**, the Linux implementation [ATC21]
    - Abstract: on a 40-node cluster, short-message P99 is 7–83x lower than TCP/DCTCP. The implementation is limited by software overheads, and another 5–10x is possible.
    - §2: Homa is "designed as a transport for RPC frameworks in datacenters", "optimized for networks with one-way hardware latencies as low as 1–2 µs". It relies on switch priority queues (8 or 16 per port). The paper notes Homa still outperforms TCP with a single priority level.
    - Testbed (Table 1): CloudLab xl170 machines, ConnectX-4 25 Gbps NICs, a Mellanox 2410 switch with all 40 nodes on one switch, and Linux 5.4.80.
    - Unloaded 100-byte RTT (Table 2 / §5.1): Homa 15.1 µs, TCP 23.4 µs, DCTCP 24.1 µs.
        - Most of the gap comes from polling (about 4 µs) and SoftIRQ core selection (about 3–4 µs).
        - Single-flow 500 KB throughput is 10 Gbps for Homa against 20.3 Gbps for TCP.
    - The paper does not mention encryption or security. It names gRPC/Thrift integration as the path to adoption.
- **Position paper** [TCP-DC]
    - "It's Time to Replace TCP in the Datacenter" is scoped entirely to the datacenter.
    - It says Homa can reach widespread use "by integrating it with RPC frameworks" and that "complete replacement of TCP is unlikely anytime soon".
- **HomaModule README** [HM-README:14-21]
    - Claim: "tail latency is more than 10x better than TCP… 99-th percentile latency is usually better than TCP's mean".
    - The incast optimization is not implemented.
    - Without `homa_qdisc`, coexisting with TCP produced about a 4x P99 increase (Jan 2026 note) [HM-README:86].

**Fit.** Every claim is about µs-scale RPC tails on lossless, low-hop datacenter fabrics under load. SSTP is a ms-scale, long-poll exchange carrying signed JSON tokens, often across administrative domains. Its latency is set by poll timing, signing, and MongoDB persistence, not by wire RTT.

## 3. Kernel module and upstreaming status

- **The out-of-tree module (PlatformLab/HomaModule) is active.**
    - Last push 2026-09-25, 417 stars, tags v1.0/v2.0/v2.0.1 [HM-REPO].
    - Licensed "BSD-2-Clause OR GPL-2.0+" [HM-SRC homa_plumbing.c:1].
- **Supported platforms are narrow.**
    - `main` is known to work on Linux 6.17.8, with rhel8 and rhel9.5 branches [HM-INSTALL; HM-README:83,98].
    - Installing needs `sudo insmod homa.ko` and the `homa_prio` daemon [HM-INSTALL].
    - Known-working NICs are Mellanox ConnectX-4/5/6 and Intel E810 [HM-README:35-37].
- **The ABI keeps changing.**
    - v2.0 (Dec 2022) moved to sendmsg/recvmsg [HM-README:136-140].
    - The Oct 2024 IANA protocol number 146 is noted at [HM-README:126], and the README warns that API changes are likely as upstreaming proceeds [HM-README:118-125].
    - Feb 2025: sockets must be bound, and `SO_HOMA_SERVER` was added [HM-README:115-117].
    - Mar 2025: `HOMA_RECVMSG_REQUEST/RESPONSE` were removed and sendmsg args gained flags [HM-README:111-114].
    - May 2025: network namespace support was added [HM-README:104].
    - Apr 2026: the ioctls were renumbered to `_IOWR('h', 0x90..0x92)` [HM-HOMA-H:319-322; commit 8473f51].
    - Sept 2026: the wire protocol changed (START_MSG) [HM-README:79-82].
- **Upstreaming is not done.**
    - Homa is not in mainline: `net/homa` is absent from the torvalds/linux mirror, whose latest tags are v7.3-rc2..rc4 [LINUX].
    - The netdev series "[PATCH net-next v19 00/15] Begin upstreaming Homa transport protocol" was posted 2026-04-28 [NETDEV-V19]. v18 was posted 2026-04-10 [NETDEV-V18] and v17 on 2026-03-16 [NETDEV-V17]; see also [LWN].
        - The cover letter says the series is stripped to about 8,000 of about 20,000 lines.
        - It describes the upstream subset as "functional but its performance is not very interesting (about the same as TCP)".
    - **Unverified:** whether v19 was applied to net-next, or whether a v20+ exists. lore.kernel.org and git.kernel.org returned 403, and no v20 was found.
- **The TCP hijacking mode is a kernel-wide intrusion.**
    - The Jul 2024 `hijack_tcp` sysctl sends Homa packets as `IPPROTO_TCP` so that NIC TSO/RSS apply [HM-README:128-131].
    - It requires Homa to intercept all incoming TCP packets on the host. The man page itself says "Some might object to this interference with the rest of the Linux kernel" [HM-MAN homa.7, `hijack_tcp`].

## 4. go-homa assessment

Repository facts [GOHOMA-REPO]:

- **Activity.** 13 stars and 0 forks, not archived. The last push was 2024-02-21T21:45:38Z. There are 5 commits, from 2024-02-20 to 2024-02-21; the last is `c79be39` "fix: update tests for synchronous io".
- **License and description.** ISC. The description is "A Go Client For The Homa Transport Protocol".
- **Dependencies.** `go 1.21.0`, `golang.org/x/sys v0.17.0`, goioctl, testify, x/sync, and cheggaaa/pb [GOHOMA go.mod].
- **No cgo.** It is pure Go over raw syscalls (`unix.Syscall` for recvmsg/sendmsg) and uses `unsafe` [GOHOMA util.go:45-73].
    - The I/O is blocking and bypasses the Go netpoller, so each blocked receive pins an OS thread. Commit `60ccf6a` moved to "synchronous io".
- **Client and server.** Despite the "client" name, `Socket` exposes `Recv`, `Send`, `Reply`, and `Abort` [GOHOMA socket.go:123,154,191,227].
    - `NewSocket` opens `AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_HOMA` and accepts only `*net.UDPAddr` [GOHOMA socket.go:36+].
    - Only IPv4 is supported.
- **Buffers and message size.** The mmap'd receive region is 1000 × 64 KiB [GOHOMA buffer_pool.go:38]. Messages are capped at 1,000,000 bytes (`HOMA_MAX_MESSAGE_LENGTH`).
- **Tests and CI.**
    - `socket_test.go` has `TestHomaRPC`. There is also `examples/main.go` (a server Recv loop) and `benchmark/main.go`.
    - The CI Earthfile clones HomaModule `main` at `--depth=1`, unpinned, and runs `insmod` under `--privileged`.
- **HomaModule's README still lists it** as "A Go client that works with this module" [HM-README:33]. The ABI comparison below contradicts that.

ABI mismatch, go-homa against current HomaModule `homa.h`:

| Item | go-homa (`homa.go`) | HomaModule main (`homa.h`) |
|---|---|---|
| IP protocol number | `0xFD` (253), commented "not an officially allocated slot" [GOHOMA homa.go:30] | `IPPROTO_HOMA 146` [HM-HOMA-H:16] |
| sendmsg args | 16 bytes (`id`, `completion_cookie`) | 24 bytes (adds `flags` + reserved) |
| recvmsg args | has `flags` + `peer_addr[28]` | no `flags`, no `peer_addr` |
| recvmsg request/response flags | `HOMA_RECVMSG_REQUEST/RESPONSE` | removed Mar 2025 [HM-README:111-114] |
| server sockets | implicit | must bind; `SO_HOMA_SERVER 11` [HM-README:115-117] |
| buffer sockopt | `SO_HOMA_SET_BUF 10` | `SO_HOMA_RCVBUF 10` |
| ioctls | `0x89` `0xe2/0xe3/0xef` | `_IOWR('h', 0x90/0x91/0x92)` [HM-HOMA-H:319-322] |
| wire protocol | pre-START_MSG | START_MSG (Sept 2026) [HM-README:79-82] |

**Conclusion.** go-homa cannot talk to a current HomaModule without a rewrite of roughly its whole syscall layer. Using it would effectively mean forking and maintaining a new binding against a kernel ABI that is still moving.

## 5. Security

- **Homa carries no encryption or authentication.**
    - The `homa(7)` man page has no mention of encryption, TLS, or security [HM-MAN].
    - The module's own TODO list says "Learn about security stuff, and functions that need to be called for this." [HM-NOTES notes.txt:241].
    - ATC'21 does not discuss security [ATC21].
- **Encryption for Homa is research.**
    - SMT (Gao et al., IEEE S&P 2026) extends Homa/Linux with TLS-based, per-message record encryption. It reports "up to 41% [throughput] and latency by up to 35%" improvements over TLS/TCP [SMT].
    - SMT is a research prototype, not part of HomaModule. Whether its code is available and maintained is **unverified**.
- **Host- or NIC-level alternatives exist**, but none carries peer identity to the application the way SSTP's TLS does today.
    - IPsec is host-level.
    - PSP needs PSP-capable NICs [PSP].
    - SMT's paper discusses these trade-offs; its full text was not read here, so that characterisation is **partially verified**, from the abstract and summary only.
- **Impact on i2goSignals.**
    - A Homa transport could not satisfy the business-stream TLS floor [pkg/goSetSstp/dialer.go:95-101; docs/SSTP.md:101-104] without IPsec, PSP, or SMT underneath. It would need a new ADR amending ADR-0066 §2 / ADR 0076.
    - JWS-signed SETs keep integrity and origin authentication end to end over any transport, but not confidentiality.
    - SET payloads carry subject identifiers, so running unencrypted would be a regression.
    - Transport-level peer authentication (TLS/mTLS, SPIFFE) would be lost as well [docs/security_model.md].

## 6. Deployment constraints

- **Datacenter-only assumptions.**
    - The design targets 1–2 µs one-way fabrics with switch priority queues and priorities computed by `homa_prio` [ATC21 §2].
    - The headline numbers come from a single-switch testbed [ATC21 Table 1].
    - Over a WAN, the µs-scale advantage is swamped by ms-scale propagation (inference from the above).
- **Raw IP protocol 146, neither TCP nor UDP.**
    - NAT devices, stateful firewalls, cloud security groups, and L4 load balancers generally handle only TCP/UDP/ICMP. Protocol-146 traffic is therefore likely to be dropped or not translatable.
    - **Unverified:** no per-vendor primary source was checked. This is an inference.
    - `hijack_tcp` disguises Homa as TCP, but connection-tracking middleboxes would not see a valid TCP handshake. Its behaviour through middleboxes is **unverified**.
    - Either way, SSTP's "initiator dials out" firewall story [docs/SSTP.md:28-31] no longer holds.
- **Kernel module in containers, Kubernetes, and managed clouds.**
    - Loading the module needs host root (`insmod`) [HM-INSTALL], and go-homa's own CI runs `--privileged` [GOHOMA Earthfile].
    - Containers share the host kernel, so every node would need the module preinstalled.
    - Managed Kubernetes and serverless platforms generally do not allow loading custom kernel modules (**unverified** per provider).
    - Network namespace support arrived only in May 2025 [HM-README:104].
- **Hardware.** For full performance Homa needs specific NICs [HM-README:35-37] and `homa_qdisc` when coexisting with TCP [HM-README:86].
- **Platforms.** Homa is Linux-only. No macOS or Windows implementation exists: HomaModule is a Linux kernel module [HM-REPO], and no other port was found. Our dev loop runs on macOS.

## 7. Latency budget comparison (order of magnitude)

| Component | Cost | Source |
|---|---|---|
| Homa's saving vs TCP, 100 B RTT, unloaded | ~8 µs | [ATC21 Table 2] |
| ML-DSA verify / RS256 parse | 99 µs / 31 µs | [go127-baseline:309] |
| ML-DSA sign / RS256 sign | 352 µs / ~820 µs | [go127-baseline:103,309] |
| Full TLS handshake (avoided by pooling) | was ~17% of receiver CPU | [dialer.go:182-189] |
| End-to-end ingest p50 / p99 | ~12–25 ms / 22–117 ms | [e2e-history] |
| SSTP drain after a burst | 0.5–3 s (11.1 s worst row) | [e2e-history:10-23] |
| Long-poll hold | `I2SIG_POLL_DEFAULT_TIMEOUT` | [docs/SSTP.md:288-291] |

Even a perfect transport cannot recover more than the wire RTT. Homa's claimed saving is at least three orders of magnitude below the measured end-to-end figure.

## 8. Alternatives that fit SSTP's shape

- **HTTP/2 connection reuse and multiplexing (no new dependency).**
    - Go's `net/http` transparently supports HTTP/2 over HTTPS [GO-HTTP].
    - `DefaultTransport` sets `ForceAttemptHTTP2: true`, and `Clone()` preserves it [GO-HTTP]. So the cloned SSTP transport [pkg/goSetSstp/dialer.go:212-230] should negotiate h2 via ALPN when the peer offers it.
    - With h2, the long poll and the push-while-poll-held POST can share one TCP+TLS connection instead of opening a second one.
    - **Unverified:** whether h2 is actually negotiated between goSignals nodes in practice. The TLS hardening could alter `NextProtos`, and no grep for h2/ALPN was completed. This is the cheapest thing to check.
- **HTTP/3 / QUIC with quic-go** [QUIC-GO; RFC9000; RFC9114]
    - QUIC runs over UDP, so it passes NAT and firewalls better than protocol 146. It has built-in TLS 1.3, which satisfies the floor.
    - It gives 0-/1-RTT resumption and no head-of-line blocking across streams.
    - It helps on lossy or high-RTT WAN links. On the LAN or datacenter benchmark it is unlikely to beat pooled h2.
    - It adds a dependency and UDP firewall requirements.
- **gRPC bidirectional streaming** [GRPC]
    - It is a natural fit for "both directions in one exchange": a persistent bidi stream over h2 with TLS.
    - But it replaces SSTP's HTTP/JSON wire contract (`application/sstp+json`) and would be a protocol change with interop cost. It is not a transport swap.
- **The actual levers, per perf history:**
    - signing algorithm choice (ES256 or ML-DSA instead of RSA-2048);
    - batching SETs per exchange;
    - reducing drain and poll timing;
    - MongoDB persistence costs [docs/perf/e2e-history.md; docs/perf/go127-baseline.md].

## 9. Recommendation

Do not pursue Homa or go-homa for SSTP, not even as an intra-cluster option.

- The benefit is µs-scale, against a ms-scale budget.
- go-homa would have to be rewritten against a moving ABI.
- There is no encryption, which conflicts with the TLS floor.
- It needs a privileged out-of-tree kernel module, a raw IP protocol, and Linux only.
- The upstream subset is "about the same as TCP".

Revisit only if Homa lands in mainline with a stable ABI **and** carries transport encryption, such as SMT upstreamed or a PSP binding.

## 10. Follow-up experiment (optional, cheap, no Homa)

Before any transport work, measure how much of an SSTP cycle is transport at all.

1. Wrap the SSTP `HTTPClient` in the benchmark with `net/http/httptrace`, and record DNS, connect, TLS handshake, time to first byte, and the negotiated protocol (`resp.Proto`) per `Exchange`.
2. Run `goSignalsBench` over the docker-compose-dev stack [docs/perf/e2e-benchmark.md] and report:
    - the share of wall time spent in connect and TLS against server processing;
    - whether h2 is in use.
3. Decide from the result:
    - If transport time is under 5% of the cycle, close the transport question.
    - If h2 is not negotiated, enabling it is the only transport change worth a spec.

A Homa experiment would need a bare-metal Linux 6.17 pair with ConnectX or E810 NICs and a rewritten binding. It is not justified unless step 1 shows transport dominating, which the numbers above make very unlikely.

## Unverified claims (summary)

- Whether the Homa net-next v19 series was applied, and whether v20+ exists (lore and git.kernel.org returned 403).
- The per-vendor behaviour of NAT, firewalls, cloud security groups, and managed Kubernetes towards IP protocol 146 or custom kernel modules. This is inference.
- How `hijack_tcp` behaves through stateful middleboxes.
- The full details of the SMT paper and whether its code is available. Only the abstract was read.
- Whether SSTP negotiates HTTP/2 between nodes in practice.

## Sources

Repository (i2goSignals, branch `release-0.12.0` @ 17bb532):

- `pkg/goSetSstp/http.go`, `pkg/goSetSstp/dialer.go`, `pkg/goSetSstp/acceptor.go`
- `docs/SSTP.md`, `docs/security_model.md`
- `docs/perf/e2e-history.md`, `docs/perf/e2e-benchmark.md`, `docs/perf/go127-baseline.md`

External:

- [HOMA18] Montazeri, Li, Alizadeh, Ousterhout, "Homa: A Receiver-Driven Low-Latency Transport Protocol Using Network Priorities", SIGCOMM 2018 — https://arxiv.org/abs/1803.09615
- [ATC21] Ousterhout, "A Linux Kernel Implementation of the Homa Transport Protocol", USENIX ATC 2021 — https://www.usenix.org/conference/atc21/presentation/ousterhout
- [TCP-DC] Ousterhout, "It's Time to Replace TCP in the Datacenter", arXiv 2210.00714v2 (2023-01-19) — https://arxiv.org/abs/2210.00714
- [HM-REPO] PlatformLab/HomaModule — https://github.com/PlatformLab/HomaModule
- [HM-README] https://github.com/PlatformLab/HomaModule/blob/main/README.md
- [HM-INSTALL] https://github.com/PlatformLab/HomaModule/blob/main/INSTALL.md
- [HM-HOMA-H] https://github.com/PlatformLab/HomaModule/blob/main/homa.h
- [HM-SRC] https://github.com/PlatformLab/HomaModule/blob/main/homa_plumbing.c
- [HM-MAN] https://github.com/PlatformLab/HomaModule/blob/main/man/homa.7
- [HM-NOTES] https://github.com/PlatformLab/HomaModule/blob/main/notes.txt
- [GOHOMA-REPO] dpeckett/go-homa — https://github.com/dpeckett/go-homa (files: `go.mod`, `homa.go`, `socket.go`, `util.go`, `buffer_pool.go`, `socket_test.go`, `examples/main.go`, `benchmark/main.go`, `Earthfile`, `.github/workflows/main.yml`)
- [LINUX] torvalds/linux mirror — https://github.com/torvalds/linux (no `net/homa`)
- [NETDEV-V19] https://ratatoskr.run/netdev/2026/04/11354516/t
- [NETDEV-V18] https://ratatoskr.run/netdev/2026/04/11353189/t
- [NETDEV-V17] https://ratatoskr.run/netdev/2026/03/11350562/t
- [LWN] https://lwn.net/Articles/1005327/
- [SMT] Gao, Ma, Narreddy, Luo, Chien, Honda, "Designing Transport-Level Encryption for Datacenter Networks", IEEE S&P 2026 — https://arxiv.org/abs/2406.15686
- [PSP] https://cloud.google.com/blog/products/identity-security/announcing-psp-security-protocol-is-now-open-source
- [GO-HTTP] Go `net/http` package docs (HTTP/2 support, `Transport.ForceAttemptHTTP2`, `Transport.Clone`) — https://pkg.go.dev/net/http
- [QUIC-GO] https://github.com/quic-go/quic-go
- [RFC9000] QUIC — https://www.rfc-editor.org/rfc/rfc9000
- [RFC9114] HTTP/3 — https://www.rfc-editor.org/rfc/rfc9114
- [GRPC] gRPC core concepts (bidirectional streaming) — https://grpc.io/docs/what-is-grpc/core-concepts/
- [IANA] IP protocol numbers (146 = Homa) — https://www.iana.org/assignments/protocol-numbers
