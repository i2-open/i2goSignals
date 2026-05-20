# GoSignals Security Model

## Shared Signals Framework and GoSignals
The current model is based on the OpenID SSF specification, which enables clients to register to receive events. 
The client may be given an Initial Access Token (IAT) which permits registration. When successful, the client receives
a permanent token used to retrieve events and manage its stream. Of particular note, the SSF endpoints
use a common endpoint with no direct stream identifier; instead, the stream identifier is typically encoded in the access token.

## GoSignals Command Line 
At present, GoSignals only has a command line utility.  It accepts IATs, but if not, it will try to get an IAT.  From
the goSignalsServer perspective, each IAT starts a new project under which one or more streams can be created. 

```shell
goSignals> add server go1 http://localhost:8888
```

To start the process the gosignals command `add server` command is used with the optional parameter --iat which is used to specify a
previously issued access token.  The command line utility will register the client with the goSignals server and in return
will receive an administrative access token.  The command line utility will store the server and token information in 
its local configuration file. If an alias is specified, that alias can be used to refer to the server in the future.  If
an alias is not specified, an alias is automatically generated.

## Docker Compose Set Up

In the demo scenario, there are 2 SCIM servers configured to run as replicas with synchronization being carried out via
goSignals. In the scenario, both SCIM servers in the cluster use goSignals1:8888 as the common events server. 
This is so that when one server issues an event, the replica SCIM server can receive it and synchronize.

In order for the SCIM servers to auto-register, they need an IAT token.  To do this, the service `scimSsfSetup` runs the
goSignals command line utility and does the following goSignals commands:
```shell
add server gosignals1 http://goSignals1:8888
add server gosignals2 http://goSignals2:8889
create iat gosignals1 --output=/scim/iat1.txt
create iat gosignals2 --output=/scim/iat2.txt
exit
```

When complete, the shell script takes iat1.txt and creates the file registration-iat.env which is picked up by services
`scim_cluster1` and `scim_cluster2`.  When these services start they will auto-register with goSignals1.

## Limitations

The current goSignals command line only knows about streams that is has configured to facilitate a demo. 
At present the `show server` command only shows the locally known information and streams. For example, you might choose to 
create a push receiver on goSignals2 and a push publisher on goSignals1 using the `create push connection` command. If you specify
the same audience as the SCIM cluster, you will find that goSignals1 starts automatically forwarding events to goSignals2.
You can monitor the events by creating a poll publisher on goSignals2 and then using the poll command to display incoming events
to the command line utility.

## SPIFFE/SPIRE Mutual TLS

As part of a defense-in-depth strategy, i2goSignals supports [SPIFFE](https://spiffe.io/) (Secure Production Identity Framework for Everyone)
for cryptographic workload identity, implemented via [SPIRE](https://spiffe.io/docs/latest/spire-about/)
and the [`go-spiffe`](https://github.com/spiffe/go-spiffe) library. SPIFFE **augments** the existing
HMAC and OAuth2 mechanisms; deployments without SPIRE continue to operate unchanged.

### What SPIFFE Replaces

| Concern | Without SPIFFE | With SPIFFE |
|---|---|---|
| Inter-cluster wake-up calls | HMAC shared secret (`I2SIG_CLUSTER_INTERNAL_TOKEN`) | X.509-SVID mutual TLS; HMAC retained as fallback |
| SSF stream management (outbound) | OAuth2 CC or static token | SPIFFE mTLS (if `SpiffeConfig` set on server record) |
| MongoDB connections | Username/password | X.509-SVID client certificate (opt-in via `I2SIG_SPIFFE_MONGO_ENABLED`) |

### How It Works

Each node requests its SVID (a short-lived X.509 certificate with a SPIFFE URI SAN) from the
local SPIRE agent via the Workload API. The go-spiffe library watches for rotations automatically;
no restarts are required when SVIDs expire.

**Inter-cluster communication (WakeTransmitter):**
When `SPIFFE_ENDPOINT_SOCKET` is set, the event router builds an mTLS HTTP transport for outbound
wake-up calls using the node's SVID. The receiving `WakeTransmitter` handler checks whether the
TLS connection carries a peer certificate. If the certificate is a valid SVID belonging to the
cluster trust domain (`I2SIG_SPIFFE_TRUST_DOMAIN`), the request is accepted without an HMAC token. If
no certificate is presented, the existing HMAC path is used. This allows a phased rollout.

**SSF stream management (oauthClient):**
Setting `SpiffeConfig` on a `Server` database record causes `GetClientForServer()` to build a
SPIFFE mTLS client. The remote server's SPIFFE ID or trust domain is used to authorize the peer.
If the SPIRE agent is unavailable, the function falls through to OAuth2 or static token auth.

**MongoDB mTLS:**
When `I2SIG_SPIFFE_MONGO_ENABLED=true` and `SPIFFE_ENDPOINT_SOCKET` is set, the MongoDB driver is
configured to use the node's SVID as the client certificate. MongoDB must be configured with the
SPIRE CA bundle as the trusted root. Falls back to password auth if SPIRE is unavailable.

### SPIRE Federation

[SPIRE federation](https://spiffe.io/docs/latest/architecture/federation/readme/) extends the
trust model across organizational boundaries, enabling SPIFFE mTLS for SSF streams that cross
domain boundaries. See [`docs/spiffe_support_plan.md`](spiffe_support.md) and
[`config/spire/registration/register.sh`](../config/spire/registration/register.sh) for setup
instructions.

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SPIFFE_ENDPOINT_SOCKET` | _(unset)_ | SPIRE agent socket path. Enables all SPIFFE features. |
| `I2SIG_SPIFFE_TRUST_DOMAIN` | `cluster.i2gosignals.internal` | Trust domain for cluster peer verification. |
| `I2SIG_SPIFFE_MONGO_ENABLED` | `false` | Enable SPIFFE mTLS for MongoDB. |

See [`docs/configuration_properties.md`](configuration_properties.md) for full details.

## SSF §9 Subject Filtering Security Posture

The OpenID Shared Signals Framework §9 raises three security concerns about the
subject-filtering endpoints. goSignals' posture is summarised below; the
removal-grace mitigation that addresses §9.3 is implemented by the PRD #97
work and is documented under `docs/subject_processing.md`.

### §9.1 Subject Probing

§9.1 warns that a receiver can use Add Subject as an oracle to test whether a
subject is known to the transmitter — a `404 subject not found` response is the
attacker's signal. goSignals offers no such oracle:

- It maintains **no subject directory** to probe. The local per-stream filter
  table is opt-in delivery state, not a record of "subjects known to the
  transmitter"; populating it is the receiver's own act.
- `Add Subject` is treated as a **statement of interest**, not a directory
  lookup. The server records the subject and returns `200` regardless of
  whether the subject has ever been seen on the wire (`defaultSubjects` is
  policy, not a delivery guarantee — see PRD #89).
- The endpoints' only `404` is **feature-disabled** (subject filtering is not
  enabled server-wide, the endpoints are not advertised in discovery, and the
  router refuses to honour them). It is a capability statement, not a
  per-subject answer, and so is not a probing oracle.

### §9.1 on the Relay Path

When a downstream receiver Adds or Removes a subject on a `PASSTHRU` or
`HYBRID` stream, goSignals relays the change to the upstream transmitter.
That upstream may have its own §9.1 mitigation and may answer `404` (or any
other 4xx/5xx). goSignals **logs the upstream response at `WARN` and returns
success to the downstream receiver** — surfacing the upstream status verbatim
would re-create the §9.1 oracle goSignals itself does not expose. The local
filter write (for `HYBRID`) and the receiver's expression of interest are
authoritative; the upstream subscription is best-effort. The receiver's
request is never failed by an upstream's §9.1 posture.

### §9.2 Information Harvesting

§9.2 warns that an attacker who has compromised a receiver can harvest events
by registering subjects of interest and waiting for delivery. goSignals does
not solve this — it is a property of the receiver's authorization model — but
its design contains the blast radius:

- A receiver token is scoped to a single stream; a compromised receiver cannot
  enumerate or harvest from another stream's filter.
- Subject filtering is **opt-in server-wide** (`I2SIG_SUBJECT_FILTERING`), so
  deployments that do not want the harvesting surface can disable it
  entirely.
- The review endpoint that exposes filter state is bound to the goSignals
  **admin scope**, distinct from the per-stream receiver scope used by the
  SSF Add/Remove endpoints. A compromised receiver cannot read the filter.

Active mitigations (rate-limiting Add Subject, anomaly detection on filter
growth) are out of scope.

### §9.3 Malicious Subject Removal

§9.3 — instant blinding by a malicious or coerced subject removal — is
addressed by the removal-grace mechanism described in
`docs/subject_processing.md`. A removal stamps the affected filter entry with
`enforceAt = now + grace`; delivery continues for the grace window so a
hostile removal cannot blind a receiver instantly. The grace defaults to zero
(no behaviour change unless the operator opts in).

## Admin UI Issues

The current command line stores local state and tokens in a local configuration file. The use of tokens for stream management 
is influenced by the SSF specification itself.  When building the admin UI, we need to implement more traditional access control
and API design so we can do things like list all streams.