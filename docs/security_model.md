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
| MongoDB connections | Username/password | X.509-SVID client certificate (opt-in via `SPIFFE_MONGO_ENABLED`) |

### How It Works

Each node requests its SVID (a short-lived X.509 certificate with a SPIFFE URI SAN) from the
local SPIRE agent via the Workload API. The go-spiffe library watches for rotations automatically;
no restarts are required when SVIDs expire.

**Inter-cluster communication (WakeTransmitter):**
When `SPIFFE_ENDPOINT_SOCKET` is set, the event router builds an mTLS HTTP transport for outbound
wake-up calls using the node's SVID. The receiving `WakeTransmitter` handler checks whether the
TLS connection carries a peer certificate. If the certificate is a valid SVID belonging to the
cluster trust domain (`SPIFFE_TRUST_DOMAIN`), the request is accepted without an HMAC token. If
no certificate is presented, the existing HMAC path is used. This allows a phased rollout.

**SSF stream management (oauthClient):**
Setting `SpiffeConfig` on a `Server` database record causes `GetClientForServer()` to build a
SPIFFE mTLS client. The remote server's SPIFFE ID or trust domain is used to authorize the peer.
If the SPIRE agent is unavailable, the function falls through to OAuth2 or static token auth.

**MongoDB mTLS:**
When `SPIFFE_MONGO_ENABLED=true` and `SPIFFE_ENDPOINT_SOCKET` is set, the MongoDB driver is
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
| `SPIFFE_TRUST_DOMAIN` | `cluster.i2gosignals.internal` | Trust domain for cluster peer verification. |
| `SPIFFE_MONGO_ENABLED` | `false` | Enable SPIFFE mTLS for MongoDB. |

See [`docs/configuration_properties.md`](configuration_properties.md) for full details.

## Admin UI Issues

The current command line stores local state and tokens in a local configuration file. The use of tokens for stream management 
is influenced by the SSF specification itself.  When building the admin UI, we need to implement more traditional access control
and API design so we can do things like list all streams.