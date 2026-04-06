# SPIFFE/SPIRE Integration Plan for i2goSignals

## Overview

This document proposes integrating [SPIFFE](https://spiffe.io/) (Secure Production Identity Framework for Everyone) and [SPIRE](https://spiffe.io/docs/latest/spire-about/) (SPIFFE Runtime Environment) into the goSignalsServer and goSsfServer stack. The integration **augments** existing authentication mechanisms (HMAC, OAuth2, static tokens) rather than replacing them, and uses the [`go-spiffe`](https://github.com/spiffe/go-spiffe) library throughout.

SPIFFE provides cryptographically verifiable workload identities (SVIDs — SPIFFE Verifiable Identity Documents) in the form of short-lived X.509 certificates and JWT tokens, issued by the SPIRE server based on node/workload attestation. This eliminates the need for pre-shared secrets, long-lived credentials, or manual certificate management for internal service-to-service communication.

---

## Current Security Architecture

| Concern | Current Mechanism | Location |
|---|---|---|
| Inter-cluster wake-up calls | HMAC-SHA256 shared secret (`I2SIG_CLUSTER_INTERNAL_TOKEN`) | `internal/eventRouter/event_router.go` |
| SSF stream management (outbound) | OAuth2 CC, static Bearer token, or plain TLS | `pkg/oauthClient/client.go:GetClientForServer()` |
| SET signing | RSA-2048 (RS256) keys managed in MongoDB | `internal/services/key_service.go` |
| SET verification | JWKS endpoints (`/jwks.json`, `/jwks/{keyName}`) | `pkg/goSet/jwks_loader.go` |
| MongoDB authentication | Username/password in connection URI | `internal/providers/dbProviders/mongo_provider/provider.go` |
| Outbound TLS (stream/event delivery) | Per-server PEM cert or `InsecureSkipVerify` | `pkg/oauthClient/tls_helpers.go:GetTlsConfigForServer()` |
| Inbound TLS | File-based cert/key via `TLS_ENABLED` env | `pkg/tlsSupport/key.go`, `cmd/goSignalsServer/main.go` |

### Pain Points Addressed by SPIFFE

- The cluster HMAC secret is a static shared secret — compromise of any node exposes the secret for all nodes.
- Per-server TLS certificate management in `ssfModels.Server` requires manual updates when certs rotate.
- MongoDB uses password authentication; mTLS would be stronger and avoids credential rotation.
- Cross-domain SSF federation requires manual trust establishment for each external domain.

---

## SPIFFE/SPIRE Architecture for i2goSignals

### Trust Domains

| Trust Domain | Scope |
|---|---|
| `cluster.i2gosignals.internal` | All nodes in a single goSignals cluster (goSignals1, goSignals1b, goSignals2, goSsfServer) |
| `<partner-domain>.example.com` | Federated external SSF server (for cross-domain stream management) |

### SVID Naming Convention

SPIFFE IDs follow the form `spiffe://<trust-domain>/workload/<role>`:

| Workload | SPIFFE ID |
|---|---|
| goSignalsServer node | `spiffe://cluster.i2gosignals.internal/workload/gosignals-node` |
| goSsfServer | `spiffe://cluster.i2gosignals.internal/workload/gossf-node` |
| MongoDB | `spiffe://cluster.i2gosignals.internal/workload/mongodb` |

### Components Added

```
docker-compose additions:
  spire-server   — SPIRE Server for trust domain (one per cluster)
  spire-agent    — SPIRE Agent sidecar on each workload node (socket at /run/spire/sockets/agent.sock)
```

Each container mounts the SPIRE agent Unix socket:

```yaml
volumes:
  - /run/spire/sockets:/run/spire/sockets
environment:
  - SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/sockets/agent.sock
```

---

## Area 1: Inter-Cluster Communication (WakeTransmitter)

### Current State

`internal/eventRouter/event_router.go` creates a bare HTTP client with no transport-level security:

```go
// event_router.go:106
httpClient: &http.Client{Timeout: 5 * time.Second},
clusterSecret: os.Getenv("I2SIG_CLUSTER_INTERNAL_TOKEN"),
```

`callWakeupAPI()` adds an HMAC `Authorization: Bearer <token>` header but makes no TLS verification of the remote node's identity.

### Proposed Change

Replace the plain HTTP client with an mTLS client using `go-spiffe`'s workload API, falling back gracefully to the existing HMAC mechanism when SPIFFE is not configured (i.e., `SPIFFE_ENDPOINT_SOCKET` is not set).

#### Key go-spiffe APIs

```go
import (
    "github.com/spiffe/go-spiffe/v2/spiffeid"
    "github.com/spiffe/go-spiffe/v2/spiffetls"
    "github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
    "github.com/spiffe/go-spiffe/v2/workloadapi"
)

// Create an X.509 source that auto-rotates from the SPIRE agent
x509Source, err := workloadapi.NewX509Source(ctx)

// Build an mTLS transport that authorizes only SVIDs from the cluster trust domain
clusterID := spiffeid.RequireTrustDomainFromString("cluster.i2gosignals.internal")
transport := &http.Transport{
    TLSClientConfig: tlsconfig.MTLSClientConfig(x509Source, x509Source,
        tlsconfig.AuthorizeMemberOf(clusterID)),
}
httpClient = &http.Client{Timeout: 5 * time.Second, Transport: transport}
```

On the server side (`pkg/goSignals/server/api_cluster.go`), `WakeTransmitter` validates the HMAC token. With SPIFFE the mTLS handshake provides peer identity; the HMAC check can be relaxed to optional when mTLS is confirmed (peer SVID belongs to the cluster trust domain).

#### Implementation Locations

| File | Change |
|---|---|
| `internal/eventRouter/event_router.go` | `NewRouter()`: optionally build SPIFFE-backed `http.Client`; fallback to current plain client |
| `internal/eventRouter/event_router.go` | `callWakeupAPI()`: no change needed — uses `router.httpClient` |
| `pkg/goSignals/server/api_cluster.go` | `WakeTransmitter()`: when peer cert is a valid cluster SVID, relax HMAC requirement |
| `pkg/tlsSupport/key.go` | Add `NewSpiffeX509Source()` helper shared by server and router |

#### Fallback Logic

```
if SPIFFE_ENDPOINT_SOCKET is set:
    use SPIFFE mTLS transport (HMAC still computed but server may not require it)
else:
    use current HMAC-only plain HTTP client
```

No change to `I2SIG_CLUSTER_INTERNAL_TOKEN` behaviour — operators can keep using pure HMAC if SPIFFE is not deployed.

---

## Area 2: SSF Stream Management via oauthClient

### Current State

`pkg/oauthClient/client.go` provides `GetClientForServer(ctx, server *model.Server)` as the unified entry point for getting an authenticated HTTP client when talking to remote SSF/transmitter servers. Auth priority:

1. OAuth2 Client Credentials (`OAuthClientConfig` populated)
2. Static Bearer token (`ClientToken` populated)
3. Base TLS-only client (fallback)

`pkg/ssfModels/model_server.go` defines `Server` with `TLSCertificate` and `TLSSkipVerify` for custom TLS, and `OAuthClientConfig` for OAuth2.

### Proposed Change

#### 1. Add `SpiffeConfig` to `ssfModels.Server`

```go
// pkg/ssfModels/model_server.go
type SpiffeConfig struct {
    // TrustDomain of the remote server's SPIFFE trust domain.
    // Used to authorize the peer SVID during mTLS.
    // Example: "partner.example.com"
    TrustDomain string

    // SpiffeID is an optional specific SPIFFE ID to authorize.
    // If empty, any SVID from TrustDomain is accepted.
    // Example: "spiffe://partner.example.com/workload/ssf-server"
    SpiffeID string
}

type Server struct {
    // ... existing fields ...
    SpiffeConfig *SpiffeConfig `bson:"spiffeConfig,omitempty" json:"spiffeConfig,omitempty"`
}
```

Auth mode in `GetAuthMode()` gains a new priority:

```
SPIFFE > OAuth Client Credentials > IaT > Static Token > STS
```

#### 2. Add `GetSpiffeClient()` to `pkg/oauthClient/`

New file `pkg/oauthClient/spiffe_client.go`:

```go
// GetSpiffeClient returns an http.Client using SPIFFE mTLS to authenticate
// to the remote server identified by server.SpiffeConfig.
// The local SVID is obtained from the workload API socket at SPIFFE_ENDPOINT_SOCKET.
func GetSpiffeClient(ctx context.Context, server *ssfModels.Server) (*http.Client, error) {
    socketPath := os.Getenv("SPIFFE_ENDPOINT_SOCKET")
    if socketPath == "" {
        return nil, errors.New("SPIFFE_ENDPOINT_SOCKET not configured")
    }
    x509Source, err := workloadapi.NewX509Source(ctx,
        workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
    if err != nil {
        return nil, fmt.Errorf("spiffe x509 source: %w", err)
    }

    var authorizer tlsconfig.Authorizer
    if server.SpiffeConfig.SpiffeID != "" {
        id, err := spiffeid.IDFromString(server.SpiffeConfig.SpiffeID)
        if err != nil {
            return nil, err
        }
        authorizer = tlsconfig.AuthorizeID(id)
    } else {
        td, err := spiffeid.TrustDomainFromString(server.SpiffeConfig.TrustDomain)
        if err != nil {
            return nil, err
        }
        authorizer = tlsconfig.AuthorizeMemberOf(td)
    }

    transport := &http.Transport{
        TLSClientConfig: tlsconfig.MTLSClientConfig(x509Source, x509Source, authorizer),
    }
    return &http.Client{Timeout: 30 * time.Second, Transport: transport}, nil
}
```

#### 3. Update `GetClientForServer()` in `pkg/oauthClient/client.go`

Add SPIFFE as the first check in `GetClientForServer()` (line ~501):

```go
func (m *Manager) GetClientForServer(ctx context.Context, server *model.Server) (*http.Client, error) {
    if server.SpiffeConfig != nil {
        client, err := GetSpiffeClient(ctx, server)
        if err == nil {
            return client, nil
        }
        // log warning and fall through to next mode
        logger.Warn("SPIFFE client failed, falling back", "err", err)
    }
    // ... existing OAuth CC, static token, base client logic unchanged ...
}
```

This means all callers in `internal/services/stream_service.go` (`CreateStream`, `UpdateStream`, `DeleteStream`) and `internal/eventRouter/event_router.go` (`pushEvent`) automatically use SPIFFE when `SpiffeConfig` is populated on a server record — no changes needed in those files.

#### 4. Server Management API

The existing stream management API should allow setting `SpiffeConfig` when registering or updating a remote server entry. The management UI/CLI can populate `TrustDomain` from the partner's SSF configuration discovery response.

---

## Area 3: SPIRE Federation

SPIRE federation enables goSignals nodes in one trust domain to authenticate to SSF servers in a different organizational trust domain, enabling cross-domain stream management without pre-shared credentials.

### How Federation Works

1. Each SPIRE server exposes a **federation bundle endpoint** (HTTPS) that serves its trust bundle (CA certificate set).
2. Peer organizations exchange their SPIRE server's bundle endpoint URL and bootstrap bundle (first-time only, out-of-band).
3. Each SPIRE server is configured with the peer's endpoint URL; it then automatically fetches and refreshes the peer's trust bundle on a configurable interval.
4. Workloads receiving a registration entry with `federates_with` obtain both their own SVID and the federated trust bundle — allowing them to verify SVIDs from the partner domain.

### SPIRE Server Configuration (per cluster)

```hcl
# spire-server.conf
server {
  trust_domain = "cluster.i2gosignals.internal"

  federation {
    bundle_endpoint {
      address = "0.0.0.0"
      port    = 8443
      # Use SPIFFE auth: our own SVID authenticates the endpoint
      profile "https_spiffe" {
        endpoint_spiffe_id = "spiffe://cluster.i2gosignals.internal/spire/server"
      }
    }

    federates_with "partner.example.com" {
      bundle_endpoint_url = "https://spire.partner.example.com:8443"
      bundle_endpoint_profile "https_spiffe" {
        endpoint_spiffe_id = "spiffe://partner.example.com/spire/server"
      }
    }
  }
}
```

### Bootstrap Procedure (one-time per federation)

```bash
# On our SPIRE server — export our bundle
spire-server bundle show -format spiffe > our-bundle.json

# On partner's SPIRE server — import our bundle
spire-server bundle set -format spiffe -id spiffe://cluster.i2gosignals.internal < our-bundle.json

# Repeat symmetrically (partner exports their bundle, we import it)
spire-server bundle set -format spiffe -id spiffe://partner.example.com < partner-bundle.json
```

After bootstrap, SPIRE automatically refreshes bundles at the configured interval (default: per the SPIFFE bundle's `refresh_hint`).

### Registration Entry for Federated Workloads

```bash
spire-server entry create \
  -spiffeID spiffe://cluster.i2gosignals.internal/workload/gosignals-node \
  -parentID spiffe://cluster.i2gosignals.internal/spire/agent/docker/gosignals1 \
  -selector docker:label:com.i2gosignals.role:gosignals-node \
  -federatesWith spiffe://partner.example.com
```

Workloads registered with `-federatesWith` receive the partner's trust bundle automatically, enabling `tlsconfig.AuthorizeMemberOf(partnerTrustDomain)` to work in `GetSpiffeClient()`.

### docker-compose Integration

```yaml
# Addition to docker-compose-dev.yml

  spire-server:
    image: dhi.io/spire-server:1.14.4-dev
    container_name: spire-server
    hostname: spire-server
    networks:
      - backend
    ports:
      - "8081:8081"   # SPIRE gRPC API
      - "8443:8443"   # Federation bundle endpoint
    volumes:
      - ./config/spire/server:/etc/spire/server
      - spire_data:/var/lib/spire/server
    entrypoint: ["/usr/local/bin/spire-server", "run", "-config", "/etc/spire/server/server.conf", "-socketPath", "/run/spire/sockets/registration.sock"]

  spire-token-gen:
    image: dhi.io/spire-server:1.14.4-dev
    container_name: spire-token-gen
    networks:
      - backend
    depends_on:
      spire-server:
        condition: service_healthy
    volumes:
      - spire_sockets:/run/spire/sockets
      - spire_tokens:/run/spire/tokens
    entrypoint:
      - "sh"
      - "-c"
      - |
        until /usr/local/bin/spire-server healthcheck -socketPath /run/spire/sockets/registration.sock; do sleep 1; done;
        TOKEN_OUT=$$(/usr/local/bin/spire-server token generate -socketPath /run/spire/sockets/registration.sock -output json);
        if echo "$$TOKEN_OUT" | grep -q '"value"'; then
          echo "$$TOKEN_OUT" | sed 's/.*"value": *"\([^"]*\)".*/\1/' > /run/spire/tokens/agent.token;
          echo "Token generated successfully";
        else
          echo "Failed to generate token: $$TOKEN_OUT";
          exit 1;
        fi

  spire-agent:
    image: dhi.io/spire-agent:1.14.4-dev
    container_name: spire-agent
    networks:
      - backend
    depends_on:
      spire-server:
        condition: service_healthy
      spire-token-gen:
        condition: service_completed_successfully
      spire-setup:
        condition: service_completed_successfully
    volumes:
      - ./config/spire/agent:/etc/spire/agent
      - spire_agent_data:/var/lib/spire/agent
      - spire_sockets:/run/spire/sockets   # shared with workloads
      - /var/run/docker.sock:/var/run/docker.sock  # Docker workload attestation
      - spire_bin:/opt/spire/shared_bin    # Shared volume for binaries
      - spire_tokens:/run/spire/tokens
    entrypoint:
      - "sh"
      - "-c"
      - |
        echo "Starting spire-agent entrypoint..."
        cmp -s /usr/local/bin/spire-agent /opt/spire/shared_bin/spire-agent || cp /usr/local/bin/spire-agent /opt/spire/shared_bin/spire-agent
        chmod +x /opt/spire/shared_bin/spire-agent
        echo "Binary copied to shared volume"
        echo "Starting spire-agent daemon..."
        exec /usr/local/bin/spire-agent run -config /etc/spire/agent/agent.conf -joinTokenFile /run/spire/tokens/agent.token
    pid: "host"

  spire-registration:
    image: dhi.io/spire-server:1.14.4-dev
    container_name: spire-registration
    networks:
      - backend
    depends_on:
      spire-server:
        condition: service_healthy
      spire-agent:
        condition: service_started
    volumes:
      - ./config/spire/registration:/etc/spire/registration
      - spire_sockets:/run/spire/sockets
    entrypoint:
      - "sh"
      - "-c"
      - |
        echo "Waiting for spire-server to be healthy..."
        until /usr/local/bin/spire-server healthcheck -socketPath /run/spire/sockets/registration.sock; do sleep 2; done
        echo "Running registration loop..."
        until sh /etc/spire/registration/register.sh; do
          echo "Registration failed (likely waiting for agent), retrying in 5s..."
          sleep 5
        done
        echo "Registration completed successfully"

volumes:
  spire_data: {}
  spire_sockets: {}
  spire_tokens: {}
```

Each goSignals container mounts the agent socket:

```yaml
  goSignals1:
    # ... existing config ...
    volumes:
      - /run/spire/sockets:/run/spire/sockets  # add this
    environment:
      - SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/sockets/agent.sock  # add this
      - SPIFFE_TRUST_DOMAIN=cluster.i2gosignals.internal              # add this
```

### Operational Notes

- **Registry Choice**: `ghcr.io/spiffe/spire-server` images are not publicly accessible. Use the `dhi.io` registry (e.g., `dhi.io/spire-server:1.14.4-dev`) which includes necessary shell environments for registration scripts.
- **Automated Workload Registration**: A dedicated `spire-registration` service handles the idempotent registration of all service entries using a robust `register.sh` script.
    - **Robust Agent Identification**: The script uses `spire-server agent list -output json` to precisely extract the latest active agent's SPIFFE ID as the `parentID`. This handles scenarios where stale agent entries might persist in the server database after a partial reset. It includes a robust wait loop to ensure the agent has joined before attempting registration.
    - **Aggressive Cleanup**: Before registering, the script deletes ALL existing workload entries to ensure a completely clean state and avoid stale parent ID mismatches.
    - **Redundant Selectors**: Workloads are registered with multiple selectors (labels AND container names, including `/` prefix variants) to ensure a match regardless of how the SPIRE agent's docker attestor perceives the container.
    - **Comprehensive Coverage**: Entries are automatically created for all nodes, including `gosignals`, `gossfserver`, `mongodb`, `prometheus`, `grafana`, `keycloak`, `postgres`, and `scim`.
- **Robust Helper Bootstrapping**: Init-containers or setup scripts (like `mongo-init`) should use robust wait loops for both the SPIRE agent socket and the SVID fetching. For example, `mongo-init` loops `api fetch x509` until the registration entry is available and the SVID is issued, ensuring that downstream services like MongoDB only start once their identities are ready.
- **Node Attestation**: The `join_token` node attestor plugin is used for automated bootstrapping in the development environment. A dedicated `spire-token-gen` service generates a join token once the server is healthy and saves it to a shared volume, which the `spire-agent` reads during startup using the `-joinTokenFile` flag.
    - **Persistence**: The `spire-agent` must use a persistent volume for its `data_dir` (e.g., `/var/lib/spire/agent`) and be configured with `KeyManager "disk"`. For the agent, the plugin requires the `directory` parameter (e.g., `directory = "/var/lib/spire/agent"`), whereas the server uses `keys_path`. This ensures that after a container restart, the agent retains its SVID and private keys on disk, avoiding the need for a new join token (which are one-time use).
    - **Robust Token Generation**: The `spire-token-gen` service should use `-output json` and verify that a token was actually generated (by checking for the `"value"` key in the JSON output) before writing to the shared `agent.token` file. This prevents the agent from attempting attestation with an empty or malformed token if the server is not yet ready.
    - Omit the `-spiffeID` flag when generating tokens to allow SPIRE to assign a default ID in its reserved `/spire/agent/` namespace; manual assignment of IDs in the `/spire/` namespace via the API is restricted and may result in "path is in the reserved namespace" errors.
    - The `docker` plugin is used only for **workload attestation** (identifying containers), not for node attestation, as it is not a built-in node attestor in version 1.14.4.
- **Healthchecks**: Both `spire-server` and `spire-agent` are configured with healthchecks using their respective CLI commands. Dependent services (like `spire-registration` and `mongo-init`) use `service_healthy` conditions to ensure they only attempt communication when the SPIRE infrastructure is fully operational.
- **Binary Sharing**: Avoid mounting volumes directly over `/usr/local/bin` in provider containers as it can cause `runc` ELOOP (too many levels of symbolic links) errors if the path is a symlink in the base image. Instead, mount the shared volume to a dedicated path (e.g., `/opt/spire/shared_bin`) and copy the binary there. Use `cmp -s source destination || cp source destination` in the agent's entrypoint to avoid "same file" errors during container restarts while ensuring the shared binary is always up to date with the image.
- **Binary Locations**: In `dhi.io` images, SPIRE binaries are located in `/usr/local/bin/`.
- **Command-line Flags**: Use `-socketPath` for CLI commands instead of the deprecated `-registrationUDSPath`.
- **Config Paths**: Ensure the server uses the `-config` flag explicitly to avoid falling back to image-specific default paths (like `/conf/server/server.conf`).
- For **Kubernetes production**, use the `k8s_sat` (service account token) attestor — no changes to Go code required.
- SPIRE bundles have a `refresh_hint` (typically 5 minutes) that controls how often federated trust bundles are re-fetched.
- The bootstrap bundle exchange is the only manual step; all subsequent rotation is automated.

---

## Area 4: MongoDB mTLS via SPIFFE X.509

### Current State

MongoDB connections use password authentication (`MONGO_INITDB_ROOT_USERNAME/PASSWORD`) via the connection URI. No TLS is configured in the docker-compose files. The Go driver connects via `internal/providers/dbProviders/mongo_provider/provider.go` `connect()`.

### Proposed Change

When SPIFFE is available, obtain the local X.509-SVID from the workload API and use it as the MongoDB client certificate. MongoDB must be configured to accept mTLS with the SPIRE CA as the trusted CA.

#### MongoDB Server Configuration

```yaml
# mongod.conf addition
net:
  tls:
    mode: requireTLS
    CAFile: /etc/spire/ca-bundle.pem          # SPIRE trust bundle (rotated externally)
    PEMKeyFile: /etc/mongo/mongo-svid.pem     # MongoDB's own SVID (fetched by SPIRE agent helper)
    allowConnectionsWithoutCertificates: false
```

Alternatively, use the `spire-helper` sidecar tool to write the SVID and trust bundle to files that MongoDB reads, with automatic rotation via a `renewSignal`.

#### Go Driver Change

In `mongo_provider/provider.go`, `connect()` currently does:

```go
opts := options.Client().ApplyURI(p.DbUrl)
```

Proposed addition (when `SPIFFE_ENDPOINT_SOCKET` is set):

```go
if socket := os.Getenv("SPIFFE_ENDPOINT_SOCKET"); socket != "" {
    x509Source, err := workloadapi.NewX509Source(ctx,
        workloadapi.WithClientOptions(workloadapi.WithAddr(socket)))
    if err == nil {
        tlsConfig := tlsconfig.MTLSClientConfig(x509Source, x509Source,
            tlsconfig.AuthorizeMemberOf(mongoTrustDomain))
        opts.SetTLSConfig(tlsConfig)
    }
}
```

`mongoTrustDomain` is `spiffeid.RequireTrustDomainFromString(os.Getenv("SPIFFE_TRUST_DOMAIN"))`.

The MongoDB connection URI would change from `mongodb://user:pass@mongo1:30001/` to `mongodb://mongo1:30001/?tls=true` (credentials removed; identity comes from the client cert).

#### Replica Set Considerations

- All three replica set members (mongo1, mongo2, mongo3) need SVIDs, either via `spire-helper` sidecars or a shared secrets mechanism.
- The SPIRE trust bundle must be distributed to MongoDB as a CA file, refreshed as bundles rotate.
- Internal replica set member authentication (currently via `keyFile`) can continue unchanged, or be replaced with X.509 member authentication (MongoDB supports both modes).

#### Fallback

If `SPIFFE_ENDPOINT_SOCKET` is not set, the connection reverts to username/password from the URI — no operational change for existing deployments.

---

## New Environment Variables

| Variable | Description | Default |
|---|---|---|
| `SPIFFE_ENDPOINT_SOCKET` | Path to SPIRE agent Unix socket | (unset — disables SPIFFE) |
| `SPIFFE_TRUST_DOMAIN` | Trust domain for this cluster | `cluster.i2gosignals.internal` |
| `SPIFFE_CLUSTER_SPIFFE_ID` | Full SPIFFE ID for this node (for validation by peers) | Auto-derived |
| `SPIFFE_MONGO_ENABLED` | Enable SPIFFE mTLS for MongoDB connections | `false` |

All SPIFFE features are opt-in: existing deployments without `SPIFFE_ENDPOINT_SOCKET` continue to operate identically to today.

---

## go-spiffe Dependency

Add to `go.mod`:

```
github.com/spiffe/go-spiffe/v2 v2.x.y
```

Key packages used:

| Package | Use |
|---|---|
| `workloadapi` | Fetch SVIDs and trust bundles from SPIRE agent |
| `spiffeid` | Parse and validate SPIFFE IDs and trust domains |
| `spiffetls` | High-level mTLS dial/listen |
| `spiffetls/tlsconfig` | Build `*tls.Config` for custom HTTP transports |

The library automatically handles SVID rotation — the `X509Source` returned by `workloadapi.NewX509Source()` watches the workload API and updates certificates in place, so long-running HTTP transports pick up new SVIDs without restart.

---

## Phased Rollout Plan

### Phase 1: Infrastructure (no Go code changes)

1. Add SPIRE server and agent services to `docker-compose-dev.yml`.
2. Write SPIRE server and agent configuration files in `config/spire/`.
3. Create workload registration entries for each service.
4. Validate that SVIDs are issued and auto-rotated.

### Phase 2: Inter-cluster mTLS (Area 1)

1. Add `go-spiffe` to `go.mod`.
2. Add `NewSpiffeX509Source()` helper to `pkg/tlsSupport/`.
3. Modify `NewRouter()` in `event_router.go` to use SPIFFE transport when `SPIFFE_ENDPOINT_SOCKET` is set.
4. Update `WakeTransmitter` in `api_cluster.go` to accept SPIFFE-authenticated requests.
5. Test: cluster wake-up calls succeed with mTLS; HMAC fallback still works without SPIFFE.

### Phase 3: Stream Management (Area 2)

1. Add `SpiffeConfig` struct to `pkg/ssfModels/model_server.go`.
2. Add `pkg/oauthClient/spiffe_client.go` with `GetSpiffeClient()`.
3. Update `GetClientForServer()` in `pkg/oauthClient/client.go` to check `SpiffeConfig` first.
4. Test: stream create/update/delete to a SPIFFE-aware server uses mTLS; OAuth fallback still works.

### Phase 4: MongoDB mTLS (Area 4)

1. Configure MongoDB with TLS and SVID-based client certificates.
2. Modify `mongo_provider/provider.go` `connect()` to use SPIFFE TLS config.
3. Test: MongoDB connection succeeds with mTLS; password-URI fallback works without SPIFFE.

### Phase 5: Federation (Area 3)

1. Deploy a second SPIRE server for a partner test domain.
2. Exchange bootstrap bundles.
3. Register a federated workload entry.
4. Test: `GetSpiffeClient()` using a `SpiffeConfig` with the partner trust domain establishes mTLS successfully.

---

## Files to Modify

| File | Change |
|---|---|
| `go.mod` | Add `github.com/spiffe/go-spiffe/v2` |
| `pkg/ssfModels/model_server.go` | Add `SpiffeConfig` struct and field to `Server` |
| `pkg/oauthClient/client.go` | Add SPIFFE as first auth mode in `GetClientForServer()` |
| `pkg/oauthClient/spiffe_client.go` | **New file**: `GetSpiffeClient()` implementation |
| `pkg/tlsSupport/key.go` | Add `NewSpiffeX509Source()` helper |
| `internal/eventRouter/event_router.go` | `NewRouter()`: optional SPIFFE transport for cluster HTTP client |
| `pkg/goSignals/server/api_cluster.go` | `WakeTransmitter()`: accept SPIFFE-authenticated requests |
| `internal/providers/dbProviders/mongo_provider/provider.go` | `connect()`: optional SPIFFE TLS config for MongoDB |
| `docker-compose-dev.yml` | Add `spire-server`, `spire-agent` services; mount socket on node containers |
| `config/spire/` | **New directory**: SPIRE server and agent configuration files |

---

## Security Considerations

- **Short-lived SVIDs** (default 1 hour) limit the blast radius of a compromised credential.
- **No secret distribution** required for cluster nodes — attestation handles identity bootstrapping.
- **Automatic rotation** means no manual certificate renewal procedures.
- **Audit logs** from SPIRE server record all SVID issuances.
- **Existing mechanisms preserved** — operators can run without SPIFFE in dev/test environments.
- **MongoDB mTLS** eliminates database credentials from environment variables/config files.

---

## References

- [SPIFFE Specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE.md)
- [SPIRE Documentation](https://spiffe.io/docs/latest/spire-about/)
- [go-spiffe Library](https://github.com/spiffe/go-spiffe)
- [SPIFFE Federation Architecture](https://spiffe.io/docs/latest/architecture/federation/readme/)
- [spire-helper](https://github.com/spiffe/spire-helper) — sidecar for file-based SVID rotation
- [MongoDB TLS with go-mongodb-driver](https://www.mongodb.com/docs/drivers/go/current/fundamentals/connection/tls/)
- [OpenID Shared Signals Framework](https://openid.net/specs/openid-sharedsignals-framework-1_0.html)
- [RFC 8417 — Security Event Token (SET)](https://www.rfc-editor.org/rfc/rfc8417)
