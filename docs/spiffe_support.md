# SPIFFE/SPIRE Support in i2goSignals

## Overview

i2goSignals uses [SPIFFE](https://spiffe.io/) (Secure Production Identity Framework for Everyone) and [SPIRE](https://spiffe.io/docs/latest/spire-about/) to provide cryptographically-verifiable workload identities. When SPIFFE is enabled:

- Inter-cluster wake-up calls use mTLS instead of a static HMAC shared secret.
- MongoDB connections use X.509 client certificates instead of embedded passwords.
- SSF stream management to SPIFFE-aware remote servers uses mTLS.
- Certificate rotation is fully automatic — no manual cert management.

All SPIFFE features are **opt-in**. Deployments without `SPIFFE_ENDPOINT_SOCKET` operate identically to non-SPIFFE deployments. Existing OAuth2, HMAC, and password-based mechanisms continue to work as fallbacks.

---

## Architecture

### Trust Domains

| Trust Domain | Scope |
|---|---|
| `cluster.i2gosignals.internal` | All nodes in one goSignals cluster |
| `<partner-domain>` | Federated external SSF server (cross-domain stream management) |

### SPIFFE IDs

| Workload | SPIFFE ID |
|---|---|
| goSignalsServer node | `spiffe://cluster.i2gosignals.internal/workload/gosignals-node` |
| goSsfServer | `spiffe://cluster.i2gosignals.internal/workload/gossf-node` |
| MongoDB replica | `spiffe://cluster.i2gosignals.internal/workload/mongodb` |
| SCIM service | `spiffe://cluster.i2gosignals.internal/workload/scim` |

### Components

| Component | Role |
|---|---|
| SPIRE Server | Issues SVIDs; one per cluster trust domain |
| SPIRE Agent | Proxies workload API; runs as sidecar/DaemonSet alongside workloads |
| `uniqueid` CredentialComposer | SPIRE server plugin that adds a deterministic `x500UniqueIdentifier` to every SVID Subject (required for MongoDB X.509 auth) |

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| `SPIFFE_ENDPOINT_SOCKET` | Path to SPIRE agent Unix socket | (unset — disables SPIFFE) |
| `SPIFFE_TRUST_DOMAIN` | Trust domain for this cluster | `cluster.i2gosignals.internal` |
| `SPIFFE_MONGO_ENABLED` | Enable SPIFFE mTLS for MongoDB connections | `false` |

---

## Docker Compose (Development)

The reference implementation is `docker-compose-spiffe-dev.yml`.

### Quick Start

```bash
docker compose -f docker-compose-spiffe-dev.yml up
```

No manual workload registration is needed — the `spire-registration` service runs `config/spire/registration/register.sh` automatically on startup.

**On first run or after `docker compose down -v`**, Docker creates fresh volumes. On subsequent `docker compose up` (without `-v`), existing volumes are reused and the SPIRE agent reconnects using its persisted key material.

### Service Startup Order

```
spire-setup → spire-server → spire-token-gen → spire-agent → spire-registration
                                                              ↓
                                                         mongo-init (writes certs + replica.key,
                                                                     initialises replica set,
                                                                     creates $external users)
                                                              ↓
                                                    gosignals1 / gosignals2 / gossfserver
```

MongoDB nodes (`mongo1`, `mongo2`, `mongo3`) start in parallel with the SPIRE stack and wait for `/certs/mongo.pem` and `/data/config/replica.key` to appear on the shared `mongo_certs` and `mongo_config` volumes before launching `mongod`.

### Key Volumes

| Volume | Purpose |
|---|---|
| `spire_sockets` | SPIRE agent Unix socket shared with all workload containers |
| `spire_bin` | SPIRE agent binary shared with `mongo-init` |
| `mongo_certs` | Shared SPIFFE certs for MongoDB nodes and `mongo-init` |
| `mongo_config` | Shared `replica.key` for MongoDB keyFile cluster auth |

### Node Attestation

Development uses the `join_token` attestor. `spire-token-gen` generates one token, writes it to the `spire_tokens` volume, and `spire-agent` reads it with `-joinTokenFile`. Join tokens are single-use; the agent persists its SVID to `spire_agent_data` so container restarts do not require a new token.

### SPIRE Image Registry

The public `ghcr.io/spiffe/spire-*` images do not include a shell, which is required by the registration scripts and is not publicly available. Use the `dhi.io` registry images (`dhi.io/spire-server:1.14.4-dev`, `dhi.io/spire-agent:1.14.4-dev`) which include `sh`.

---

## MongoDB SPIFFE mTLS

### How It Works

When `SPIFFE_MONGO_ENABLED=true` and `SPIFFE_ENDPOINT_SOCKET` is set:

1. The Go driver (`internal/providers/dbProviders/mongo_provider/provider.go`) obtains the workload X.509-SVID from the SPIRE agent.
2. The SVID is presented as the MongoDB TLS client certificate.
3. MongoDB validates the client cert against the SPIRE CA bundle and looks up the Subject DN in the `$external` database.
4. The connection URI uses `authMechanism=MONGODB-X509&authSource=$external` with no embedded credentials.

Connection string format (in `env_file`, dollar signs must be doubled):

```
MONGO_URL=mongodb://mongo1:30001,mongo2:30002,mongo3:30003/?tls=true&replicaSet=dbrs&authMechanism=MONGODB-X509&authSource=$$external
```

If SPIFFE is unavailable at startup, the driver falls back to any username/password in the URI.

### The `uniqueid` Plugin Requirement

Standard SPIFFE SVIDs have an **empty Subject** — identity is carried in the URI SAN (`spiffe://...`). MongoDB X.509 auth uses the Subject DN exclusively; an empty Subject always produces `AuthenticationFailed`.

The `uniqueid` CredentialComposer plugin (enabled in `config/spire/server/server.conf`) adds OID `2.5.4.45` (`x500UniqueIdentifier`) to every workload SVID's Subject:

```
SHA256(spiffe_id_uri)[0:16]  →  32-character hex string
```

This value is **deterministic** (same SPIFFE ID always produces the same hash) and **stable** across certificate rotations, which is essential for pre-creating `$external` users.

Example — `spiffe://cluster.i2gosignals.internal/workload/gosignals-node` produces Subject:

```
x500UniqueIdentifier=9f361d2aea911b52e50be001f4c6a91e,O=SPIRE,C=US
```

After enabling `uniqueid`, restart the SPIRE server. Existing SVIDs rotate automatically within their TTL (default 1 hour) or immediately if the `spire_data` volume is removed.

### `$external` User Creation (`mongo_spiffe_init.sh`)

`config/mongo/mongo_spiffe_init.sh` runs in the `mongo-init` container. It:

1. Waits for the SPIRE agent binary and socket.
2. Creates `replica.key` for MongoDB keyFile cluster authentication.
3. Fetches the `workload/mongodb` SVID from SPIRE.
4. Extracts the Subject DN and verifies that the computed SHA256 hash is present — confirming `uniqueid` is active and the hash algorithm is correct. Exits with a diagnostic if not.
5. Detects the RFC2253 OID format (`2.5.4.45=` vs `x500UniqueIdentifier=`) at runtime to handle OpenSSL version differences.
6. Computes Subject DNs for the three workload users (`gosignals-node`, `gossf-node`, `scim`).
7. Waits for `mongo1` to be ready, initialises the replica set, waits for a primary.
8. Creates or updates the three `$external` users.
9. Writes `/certs/.init_complete` as a sentinel file.

The `mongo-init` healthcheck checks for `/certs/.init_complete`. All goSignals services use `condition: service_healthy` against `mongo-init` so they never attempt X.509 auth before the users exist.

> **Note:** The `workload/mongodb` SVID Subject is intentionally **not** created as a `$external` user — see the cluster authentication section below.

### MongoDB Cluster Authentication and the `clusterAuthX509` Problem

All SPIRE SVIDs share `O=SPIRE,C=US` in their Subject. By default, MongoDB derives its cluster-member identification criteria from the replica node's own TLS certificate attributes. Because the MongoDB nodes are also SPIRE workloads with `O=SPIRE,C=US`, MongoDB treats **every** SPIFFE certificate as a potential cluster member and blocks `$external` user creation with:

```
MongoServerError: Cannot create an x.509 user with a subjectname that would be recognized as an internal cluster member
```

**The fix** is `config/mongo/mongod.conf`, mounted read-only into each replica node at `/etc/mongo/mongod.conf`:

```yaml
security:
  keyFile: "/data/config/replica.key"
  clusterAuthMode: sendKeyFile

net:
  tls:
    clusterAuthX509:
      attributes: "x500UniqueIdentifier=6ff4e8d38b5f843e7b91b001b8820e7f"
```

**How it works:**

- `clusterAuthX509.attributes` overrides the cluster-member cert criteria to the specific `x500UniqueIdentifier` value of the `workload/mongodb` SVID. This value is `SHA256("spiffe://cluster.i2gosignals.internal/workload/mongodb")[0:32]`.
- MongoDB validates that its own TLS certificate contains these attributes — the MongoDB nodes use the `workload/mongodb` SVID, which does → server starts cleanly.
- Workload certs (`gosignals-node`, `gossf-node`, `scim`) carry different `x500UniqueIdentifier` hashes → NOT recognised as cluster members → `$external` user creation succeeds.
- The mongodb workload's own Subject still cannot be a `$external` user (correctly — it IS the cluster member cert), so it is not included in the user creation list.

**Why `sendKeyFile` and not `keyFile`:**
Both `clusterAuthX509.attributes` and `clusterAuthX509.extensionValue` require `clusterAuthMode` to allow X.509. `keyFile` mode does not satisfy this (mongod refuses to start with "clusterAuthMode does not allow X.509"). `sendKeyFile` keeps keyFile as the outgoing credential (replica set initialises without needing `$external` users) while accepting x.509 on incoming connections.

**If the trust domain or workload path changes**, recompute the hash:

```bash
printf '%s' "spiffe://<domain>/workload/mongodb" | \
  openssl dgst -sha256 | awk '{print $NF}' | cut -c1-32
```

Then update `clusterAuthX509.attributes` in `mongod.conf`.

**Config path reference:**

| Config path | Works? | Notes |
|---|---|---|
| `security.clusterAuthX509.extensionValue` | No | "Unrecognized option" — mongod crash |
| `net.tls.clusterAuthX509.extensionValue` | No (for this use case) | Requires `clusterAuthMode: x509` → chicken-and-egg: replica set quorum check fails before `$external` users exist |
| `net.tls.clusterAuthX509.attributes: "O=..."` | No | MongoDB validates that server cert contains the attributes; `O=SPIRE` would allow all SPIFFE certs, a fake value causes "InvalidSSLConfiguration" |
| `net.tls.clusterAuthX509.attributes: "x500UniqueIdentifier=<mongodb-hash>"` | **Yes** | Server cert contains its own hash; workload certs have different hashes |

### Hostname Verification

SPIFFE SVIDs carry identity in the URI SAN, not DNS SANs. `mongod` and `mongosh` are started with `--tlsAllowInvalidHostnames` to bypass hostname verification while still validating the certificate chain against the SPIRE CA.

---

## Kubernetes Deployment

### SPIRE on Kubernetes — Overview

The standard Kubernetes deployment uses:

- **SPIRE Server**: `StatefulSet` with persistent storage for the datastore and keys.
- **SPIRE Agent**: `DaemonSet` so every node runs one agent. Workload containers reach the agent via a `hostPath` volume mounting the agent's Unix socket.
- **Node attestor**: `k8s_sat` (Kubernetes Service Account Token) — the agent proves its identity to the server using a projected service account token bound to a specific audience.
- **Workload attestor**: `k8s` — the agent identifies workloads by matching Kubernetes metadata (namespace, service account, labels, container images).

The [SPIRE Helm chart](https://github.com/spiffe/helm-charts-hardened) is the recommended installation method.

### SPIRE Server Configuration (Kubernetes)

```hcl
server {
  trust_domain = "cluster.i2gosignals.internal"
  bind_address = "0.0.0.0"
  bind_port    = "8081"
  data_dir     = "/run/spire/data"
}

plugins {
  DataStore "sql" {
    plugin_data {
      database_type   = "sqlite3"
      connection_string = "/run/spire/data/datastore.sqlite3"
    }
  }

  NodeAttestor "k8s_psat" {
    plugin_data {
      clusters = {
        "my-cluster" = {
          service_account_allow_list = ["spire:spire-agent"]
        }
      }
    }
  }

  KeyManager "disk" {
    plugin_data { keys_path = "/run/spire/data/keys.json" }
  }

  # Required for MongoDB X.509 auth — adds x500UniqueIdentifier to all SVIDs
  CredentialComposer "uniqueid" {}
}
```

### SPIRE Agent Configuration (Kubernetes)

```hcl
agent {
  data_dir            = "/run/spire/agent-data"
  log_level           = "INFO"
  server_address      = "spire-server.spire.svc.cluster.local"
  server_port         = "8081"
  socket_path         = "/run/spire/sockets/agent.sock"
  trust_domain        = "cluster.i2gosignals.internal"
}

plugins {
  NodeAttestor "k8s_psat" {
    plugin_data {
      cluster = "my-cluster"
    }
  }

  KeyManager "disk" {
    plugin_data { directory = "/run/spire/agent-data" }
  }

  WorkloadAttestor "k8s" {
    plugin_data {
      skip_kubelet_verification = true
    }
  }
}
```

### Workload Registration (Kubernetes)

Register each workload with the SPIRE server, selecting it by namespace and service account:

```bash
# goSignals nodes
spire-server entry create \
  -spiffeID spiffe://cluster.i2gosignals.internal/workload/gosignals-node \
  -parentID spiffe://cluster.i2gosignals.internal/spire/agent/k8s_psat/my-cluster/<node-uid> \
  -selector k8s:ns:i2gosignals \
  -selector k8s:sa:gosignals

# goSsfServer
spire-server entry create \
  -spiffeID spiffe://cluster.i2gosignals.internal/workload/gossf-node \
  -parentID spiffe://cluster.i2gosignals.internal/spire/agent/k8s_psat/my-cluster/<node-uid> \
  -selector k8s:ns:i2gosignals \
  -selector k8s:sa:gossf

# MongoDB
spire-server entry create \
  -spiffeID spiffe://cluster.i2gosignals.internal/workload/mongodb \
  -parentID spiffe://cluster.i2gosignals.internal/spire/agent/k8s_psat/my-cluster/<node-uid> \
  -selector k8s:ns:i2gosignals \
  -selector k8s:sa:mongodb
```

Use `-spiffeID` to match exactly the SPIFFE IDs above — the `x500UniqueIdentifier` hashes in `mongod.conf` are derived from these IDs.

### SPIRE Agent Socket in Pod Specs

```yaml
# DaemonSet agent volume
volumes:
  - name: spire-agent-socket
    hostPath:
      path: /run/spire/sockets
      type: DirectoryOrCreate

# Workload container volume mount
volumeMounts:
  - name: spire-agent-socket
    mountPath: /run/spire/sockets
    readOnly: true

# Workload container environment
env:
  - name: SPIFFE_ENDPOINT_SOCKET
    value: "unix:///run/spire/sockets/agent.sock"
  - name: SPIFFE_TRUST_DOMAIN
    value: "cluster.i2gosignals.internal"
  - name: SPIFFE_MONGO_ENABLED
    value: "true"
```

### MongoDB on Kubernetes

For a self-managed MongoDB replica set on Kubernetes (e.g., via the [MongoDB Community Operator](https://github.com/mongodb/mongodb-kubernetes-operator)), the same `mongod.conf` approach applies. Mount `config/mongo/mongod.conf` as a `ConfigMap` into each MongoDB pod.

The `mongo-init` logic can be run as a Kubernetes `Job` or init container. The `mongo_certs` shared volume becomes a Kubernetes `emptyDir` or `PersistentVolumeClaim` shared between the init job and the MongoDB pods. The SPIRE agent socket is mounted from the `hostPath` as above.

For **MongoDB Atlas** (managed), SPIFFE-based X.509 client auth is available via Atlas's X.509 authentication feature. Supply the SVID as the client certificate in the connection string; no `$external` user management is needed (Atlas handles it). The `clusterAuthX509` issue does not apply to Atlas.

---

## AWS EKS

### Node Attestation Options

**Option A — `k8s_psat` (recommended):** Use the standard Kubernetes projected service account token attestor. Works identically to the generic Kubernetes setup above. No AWS-specific configuration needed.

**Option B — `aws_iid` (EC2 Instance Identity Document):** The SPIRE agent proves its node identity using the AWS EC2 Instance Identity Document. Useful when you want node identity tied to specific IAM roles or instance profiles rather than just Kubernetes service accounts.

```hcl
# spire-server.conf
NodeAttestor "aws_iid" {
  plugin_data {
    access_key_id     = ""  # Use instance profile — no static keys
    secret_access_key = ""
  }
}

# spire-agent.conf
NodeAttestor "aws_iid" {
  plugin_data {}
}
```

### EKS-Specific Notes

- **IRSA (IAM Roles for Service Accounts):** SPIFFE and IRSA are complementary. Use IRSA for AWS API access (S3, Secrets Manager, etc.) and SPIFFE for service-to-service mTLS within the cluster.
- **EKS Pod Identity:** EKS Pod Identity (newer than IRSA) also complements SPIFFE. Use EKS Pod Identity for AWS SDK calls; SPIFFE for inter-workload authentication.
- **EKS Fargate:** The SPIRE agent `DaemonSet` cannot run on Fargate nodes. Use the [SPIFFE CSI Driver](https://github.com/spiffe/spiffe-csi) instead, which delivers SVIDs via a CSI volume without requiring a per-node agent daemon.
- **ALB/NLB:** If workloads are behind an Application Load Balancer, SPIFFE mTLS applies only to pod-to-pod traffic inside the cluster. TLS termination at the ALB uses a separate certificate (ACM).
- **Secrets Manager:** The MongoDB `replica.key` can be stored in AWS Secrets Manager and injected via the [AWS Secrets and Configuration Provider (ASCP)](https://docs.aws.amazon.com/secretsmanager/latest/userguide/integrating_csi_driver.html) rather than generated by `mongo-init`.

### Recommended SPIRE Helm Values for EKS

```yaml
spire-server:
  nodeAttestor:
    k8sPsat:
      enabled: true
  credentialComposers:
    uniqueid:
      enabled: true  # Required for MongoDB X.509 auth

spire-agent:
  nodeAttestor:
    k8sPsat:
      enabled: true
```

---

## GCP GKE

### Node Attestation Options

**Option A — `k8s_psat` (recommended):** Same as generic Kubernetes. Simplest option for GKE.

**Option B — `gcp_iit` (GCP Instance Identity Token):** The SPIRE agent uses the GCE metadata server instance identity token to prove node identity. Ties node attestation to GCP project/zone/instance metadata.

```hcl
# spire-server.conf
NodeAttestor "gcp_iit" {
  plugin_data {
    projectid_allow_list = ["my-gcp-project"]
  }
}

# spire-agent.conf
NodeAttestor "gcp_iit" {
  plugin_data {}
}
```

### GKE-Specific Notes

- **GCP Workload Identity:** Workload Identity binds Kubernetes service accounts to GCP service accounts for Google API calls. Use Workload Identity for GCP API access and SPIFFE for inter-workload mTLS — they coexist on the same pod without conflict.
- **GKE Autopilot:** SPIRE agent DaemonSets are not permitted on Autopilot clusters. Use the [SPIFFE CSI Driver](https://github.com/spiffe/spiffe-csi) to deliver SVIDs via a CSI volume, or use a managed SPIFFE solution such as [Certificate Authority Service](https://cloud.google.com/certificate-authority-service) with SPIFFE integration.
- **Cloud SQL:** If using Cloud SQL (managed Postgres/MySQL) instead of self-managed MongoDB, SPIFFE mTLS does not apply to Cloud SQL connections directly. Use Cloud SQL's built-in IAM database authentication or mTLS with client certificates managed separately.
- **Secret Manager:** Store the MongoDB `replica.key` in GCP Secret Manager and inject it using the [Secret Manager CSI Driver](https://github.com/GoogleCloudPlatform/secrets-store-csi-driver-provider-gcp).
- **Binary Authorization:** GKE Binary Authorization can enforce that only attested container images run. Pair with SPIRE's container image selector for defence-in-depth: a workload must pass both Binary Authorization (image identity) and SPIRE attestation (runtime identity) to be granted an SVID.

---

## Azure AKS

### Node Attestation Options

**Option A — `k8s_psat` (recommended):** Same as generic Kubernetes. Simplest option for AKS.

**Option B — `azure_msi` (Azure Managed Service Identity):** The SPIRE agent uses the Azure Instance Metadata Service to prove node identity via MSI. Useful when node identity must be tied to specific Azure resource groups or subscriptions.

```hcl
# spire-server.conf
NodeAttestor "azure_msi" {
  plugin_data {
    tenants = {
      "<tenant-id>" = {
        resource_id = "https://management.azure.com/"
      }
    }
  }
}

# spire-agent.conf
NodeAttestor "azure_msi" {
  plugin_data {
    resource_id = "https://management.azure.com/"
  }
}
```

### AKS-Specific Notes

- **Azure Workload Identity:** Replaces the older pod-managed identity (aad-pod-identity) for Azure SDK calls. Use Azure Workload Identity for Azure API access (Key Vault, Storage, etc.) and SPIFFE for inter-workload mTLS — both use projected service account tokens and coexist on the same pod.
- **AKS Virtual Nodes (ACI):** Virtual nodes run as Azure Container Instances. The SPIRE agent DaemonSet cannot run on ACI nodes. Use the SPIFFE CSI Driver for workloads on virtual nodes.
- **Azure Key Vault:** Store the MongoDB `replica.key` in Azure Key Vault and inject it via the [Azure Key Vault Provider for Secrets Store CSI Driver](https://github.com/Azure/secrets-store-csi-driver-provider-azure).
- **Azure Container Registry (ACR):** When pulling SPIRE images from ACR, attach the ACR to the AKS cluster or configure image pull secrets. The `dhi.io` SPIRE images used in the development docker-compose setup may need to be mirrored to ACR for production use.
- **Azure Application Gateway Ingress:** As with ALB/NLB, SPIFFE mTLS applies to pod-to-pod traffic. TLS at the ingress controller uses certificates from Azure-managed sources (Key Vault, App Service Certificates).

---

## SPIRE Federation (Cross-Domain SSF)

Federation enables two independent i2goSignals deployments (different organizations, different trust domains) to establish mTLS for SSF stream management without pre-shared credentials.

### Setup

On each SPIRE server, enable the federation bundle endpoint in `server.conf`:

```hcl
server {
  federation {
    bundle_endpoint {
      address = "0.0.0.0"
      port    = 8443
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

Bootstrap bundle exchange (one-time, out-of-band):

```bash
# Export our bundle and send to partner
spire-server bundle show -format spiffe > our-bundle.json

# Import partner's bundle
spire-server bundle set -format spiffe -id spiffe://partner.example.com < partner-bundle.json
```

After bootstrap, SPIRE refreshes bundles automatically. Workloads registered with `-federatesWith spiffe://partner.example.com` receive the partner trust bundle and can establish mTLS with partner workloads.

---

## Security Considerations

- **Short-lived SVIDs** (default 1 hour TTL) limit the blast radius of a compromised credential.
- **No secret distribution** — attestation handles identity bootstrapping. Cluster nodes never share a long-lived secret for mTLS.
- **Automatic rotation** — `go-spiffe`'s `X509Source` watches the workload API and updates certificates in-process. No restart required on rotation.
- **MongoDB credentials eliminated** — with `SPIFFE_MONGO_ENABLED=true` the MONGO_URL contains no username or password. Credential rotation is not required.
- **Audit trail** — the SPIRE server logs all SVID issuances, providing a workload-level access log.
- **Defence in depth** — SPIFFE augments, not replaces, existing auth mechanisms (HMAC, OAuth2, static tokens). Deployments can run without SPIFFE.

### Important Operational Notes

- **`uniqueid` plugin is mandatory for MongoDB.** Without it, all SVID Subjects are empty and MongoDB authentication always fails. After enabling the plugin, the SPIRE server must be restarted.
- **The `mongo-init` sentinel file** (`/certs/.init_complete`) must be used for the `mongo-init` healthcheck — not cert file existence. Checking only for cert existence causes a race where goSignals containers start before `$external` users are created.
- **`mongod.conf` must be consistent across all replica members.** The `clusterAuthX509.attributes` value must be the same on all three replica nodes.
- **The `x500UniqueIdentifier` hash in `mongod.conf` is derived from the SPIFFE ID.** If the trust domain or workload path changes, recompute it and update `mongod.conf`.
- **`--tlsAllowInvalidHostnames` is required** for both `mongod` and `mongosh` because SPIFFE SVIDs use URI SANs, not DNS SANs.
- **`authSource=$$external`** in docker-compose env files — the dollar sign must be doubled to prevent docker-compose from interpreting `$external` as an undefined variable.
- **Stale certs on restart** — `mongo_spiffe_init.sh` deletes old `.pem` and `.key` files at startup. This ensures `mongod` waits for fresh SVIDs rather than starting with expired certs from a previous run.

---

## Troubleshooting

### `AuthenticationFailed` on MongoDB connection

1. Verify `CredentialComposer "uniqueid" {}` is in `config/spire/server/server.conf` and the SPIRE server has been restarted since it was added.
2. Check `mongo-init` logs for `Actual SVID Subject (RFC2253)` — the Subject must be non-empty and contain `x500UniqueIdentifier=`.
3. Verify the `$external` user exists: `mongosh ... --eval "db.getSiblingDB('\$external').getUsers()"`.
4. Confirm the connection URI contains `authMechanism=MONGODB-X509&authSource=$$external`.

### `Cannot create an x.509 user with a subjectname that would be recognized as an internal cluster member`

The `clusterAuthX509.attributes` in `mongod.conf` is either missing, using the wrong value, or `clusterAuthMode` does not allow X.509. Verify:
- `security.clusterAuthMode` is `sendKeyFile` (not `keyFile`).
- `net.tls.clusterAuthX509.attributes` is set to `x500UniqueIdentifier=<mongodb-hash>`.
- The hash matches `SHA256("spiffe://<trust-domain>/workload/mongodb")[0:32]` exactly.
- `mongod.conf` is mounted at `/etc/mongo/mongod.conf` and `--config /etc/mongo/mongod.conf` is passed to `mongod`.

### `Error during global initialization: InvalidSSLConfiguration`

The `clusterAuthX509.attributes` value is not present in the server's own TLS certificate. The attributes value must be an attribute that IS in the MongoDB workload SVID's Subject. A synthetic value like `O=MongoDB_Cluster_Internal` does not work. Use `x500UniqueIdentifier=<mongodb-hash>` as described above.

### `rpc error: code = PermissionDenied desc = no identity issued`

The SPIRE workload entry for this container has not been registered yet, or the agent has not received it. The `mongo_spiffe_init.sh` script retries every 5 seconds and proceeds once the SVID is issued. If it never resolves, check `spire-registration` logs and verify the workload selector matches.

### `replSetInitiate quorum check failed`

Occurs when `clusterAuthMode: x509` (not `sendKeyFile`) is used. With pure x.509 cluster auth, the quorum check connects to replica members before `$external` users exist. Use `sendKeyFile` so the quorum check uses the keyFile credential.

### SPIRE agent fails to start after container restart

The agent's persistent volume (`spire_agent_data`) may be missing or corrupted. The `KeyManager "disk"` plugin requires `directory = "/var/lib/spire/agent"` (not `keys_path`, which is the server plugin parameter). Check agent configuration.

---

---

## MongoDB Certificate Rotation

### Background: the Static-Load Problem

SPIRE is designed around short-lived, automatically-rotated SVIDs. Go workloads use `go-spiffe`'s `X509Source`, which watches the Workload API and swaps certificates in-process without any restart. Naively, MongoDB appears to share this limitation:

- `mongod` reads its TLS certificate and CA bundle at startup and holds them in memory.
- Updating cert files on disk has no effect on a running `mongod`.

This creates two failure modes:

| Event | Effect |
|---|---|
| MongoDB's own SVID expires | `mongod` presents an expired server certificate; new TLS handshakes fail |
| SPIRE CA rotates and old CA is pruned from the trust bundle | Go workload SVIDs signed by the new CA are not trusted by MongoDB's in-memory CA bundle — client auth fails |

### Solution: `db.adminCommand({rotateCertificates: 1})`

MongoDB provides the [`rotateCertificates`](https://www.mongodb.com/docs/manual/reference/command/rotateCertificates/) admin command (Community, Enterprise, and Atlas) which re-reads **all three TLS file paths** from disk **without restarting `mongod`**:

- `net.tls.certificateKeyFile` (server cert + key)
- `net.tls.CAFile` **(CA bundle — including the SPIRE trust bundle)**
- `net.tls.CRLFile` (CRL, on Linux/Windows)

Key behaviours:
- Existing connections keep the old cert/CA bundle until they close naturally — no connection disruption.
- All new connections immediately use the reloaded material.
- A failed rotation (expired cert, file missing) leaves the current TLS configuration intact; `mongod` does not crash.
- Requires the `rotateCertificates` privilege action (part of the built-in `hostManager` role; the `root` user has it).
- The new cert must have the **same filename and path** as the old one — already satisfied by the fixed paths `/certs/mongo.pem` and `/certs/ca.pem`.

### Implementation

**`config/mongo/mongo_spiffe_init.sh`** — the renewal loop saves the previous cert/CA before overwriting, then uses them to connect for the `rotateCertificates` call:

```bash
# Save current cert/CA before overwriting
cp /certs/mongo.pem /certs/mongo.pem.prev
cp /certs/ca.pem    /certs/ca.pem.prev

# Write new cert/CA from SPIRE
cp /certs/svid.0.pem /certs/mongo.pem && cat /certs/svid.0.key >> /certs/mongo.pem
cp /certs/bundle.0.pem /certs/ca.pem

# Connect using PREVIOUS cert; call rotateCertificates on each node
CONN_CERT=/certs/mongo.pem.prev; [ -f "$CONN_CERT" ] || CONN_CERT=/certs/mongo.pem
CONN_CA=/certs/ca.pem.prev;     [ -f "$CONN_CA"   ] || CONN_CA=/certs/ca.pem

for HOST in mongo1 mongo2 mongo3; do
    IDX=${HOST##mongo}; PORT=$((30000 + IDX))
    mongosh --host "$HOST" --port "$PORT" \
        --username root --password dockTest --authenticationDatabase admin \
        --tls --tlsAllowInvalidHostnames \
        --tlsCAFile "$CONN_CA" --tlsCertificateKeyFile "$CONN_CERT" \
        --quiet \
        --eval "db.adminCommand({rotateCertificates: 1, message: 'SPIRE SVID renewal'})"
done
```

**Why the previous cert is used for the connection:**

- `mongod` enforces mutual TLS when `--tlsCAFile` is configured — clients must present a valid certificate even for password-based authentication.
- After a SPIRE CA rotation, the new SVID (just written to `/certs/mongo.pem`) is signed by the new CA. `mongod`'s in-memory CA bundle still only knows the old CA, so it would reject the new client cert.
- Connecting with the _previous_ cert (signed by the old CA, still trusted by `mongod`) allows the `rotateCertificates` call to succeed. `mongod` then atomically reloads both the new server cert and the new CA bundle from disk.
- On the first renewal cycle no `.prev` files exist yet; the script falls back to the new cert, which is safe because the CA has not rotated at that point (it only rotates every 24h by default).

**Rotation timeline with 1h SVID TTL (default):**

| Time | Event |
|---|---|
| T+0 | SPIRE issues SVID (valid 1h) |
| T+30m | SPIRE prepares rotation: new CA added to trust bundle, new SVID issued (signed by new CA), old CA kept in bundle during transition |
| T+30–35m | Renewal loop (5-min interval) detects new SVID; writes `/certs/mongo.pem` and `/certs/ca.pem` (bundle contains both old + new CA); calls `rotateCertificates` on each node |
| T+35m | All new `mongod` connections use new cert + CA bundle; old connections drain naturally |
| T+1h | Old SVID expires; new one has been active for ~25 minutes |

MongoDB SVIDs use the same 1h server default as all other workloads. No per-entry TTL override or extended `ca_ttl` is needed.

**`docker-compose-spiffe-dev.yml`** — MongoDB container startup loop validates cert expiry before starting `mongod`:

```bash
until [ -f /certs/mongo.pem ] && [ -f /data/config/replica.key ] \
      && openssl x509 -in /certs/mongo.pem -noout -checkend 60 2>/dev/null; do
    echo 'Waiting for valid certs and key...'
    sleep 5
done
```

`openssl -checkend 60` exits non-zero if the cert is already expired or expires within 60 seconds. This prevents the infinite restart loop that occurs when a mongo container restarts and finds a stale cert on the shared `mongo_certs` volume.

### Alternatives Considered and Rejected

**`spiffe-helper` + container restart:** The [`spiffe-helper`](https://github.com/spiffe/spiffe-helper) sidecar detects SVID rotations and executes a configurable command. For MongoDB it would need to restart the container, requiring careful orchestration to preserve replica-set quorum and avoid connection disruption on both sides simultaneously. `rotateCertificates` is simpler and avoids all restarts.

**Envoy/NGINX TLS sidecar:** A proxy handles TLS termination with SPIFFE SVIDs via the Workload API (automatic rotation); MongoDB listens on localhost without TLS. This is the canonical service-mesh pattern but adds significant infrastructure overhead. `rotateCertificates` achieves the same outcome within the existing setup.

**Long-lived certs:** Setting `ca_ttl` and per-entry SVID TTL to 1 year avoids restarts but degrades the security posture: a compromised MongoDB SVID or CA key has a 1-year blast radius. `rotateCertificates` maintains the 1h TTL and eliminates this tradeoff entirely.

### Operational Notes

- **After `docker compose down -v`:** All volumes are recreated; SPIRE issues a fresh CA and fresh SVIDs. No manual action needed.
- **After `docker compose down` (without `-v`):** Existing volumes reused. MongoDB containers check cert validity via `openssl -checkend` before starting, so they wait for the renewal loop to provide a fresh cert if the previous one has expired.
- **`rotateCertificates` is idempotent:** Calling it when the cert has not changed is harmless — `mongod` re-reads the same files and logs the rotation.
- **Production:** The same `rotateCertificates` approach applies on Kubernetes. Run a sidecar that calls `rotateCertificates` via `mongosh` after writing updated cert files, triggered by a file-watch or timer.

## References

- [SPIFFE Specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE.md)
- [SPIRE Documentation](https://spiffe.io/docs/latest/spire-about/)
- [SPIRE Helm Charts (Hardened)](https://github.com/spiffe/helm-charts-hardened)
- [go-spiffe Library](https://github.com/spiffe/go-spiffe)
- [SPIFFE CSI Driver](https://github.com/spiffe/spiffe-csi) — for Fargate, Autopilot, ACI
- [spire-helper](https://github.com/spiffe/spire-helper) — sidecar for file-based SVID rotation
- [MongoDB X.509 Authentication](https://www.mongodb.com/docs/manual/tutorial/configure-x509-client-authentication/)
- [MongoDB `clusterAuthX509` Configuration](https://www.mongodb.com/docs/manual/reference/configuration-options/#mongodb-setting-net.tls.clusterAuthX509.attributes)
- [MongoDB `rotateCertificates` Command](https://www.mongodb.com/docs/manual/reference/command/rotateCertificates/)
- [MongoDB Community Kubernetes Operator](https://github.com/mongodb/mongodb-kubernetes-operator)
- [SPIFFE Federation Architecture](https://spiffe.io/docs/latest/architecture/federation/readme/)
- [OpenID Shared Signals Framework](https://openid.net/specs/openid-sharedsignals-framework-1_0.html)
