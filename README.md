<picture><source media="(prefers-color-scheme: dark)" srcset="brand/logo/gosignals-hero-primary.svg"><img src="brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# goSignals

_A Security Event Router that bridges Push and Poll SET delivery across federation boundaries, with durable storage, replay, and fan-out._

## Background: what are security signals?

Identity and access decisions used to be one-shot events hidden in access logs. A user authenticated, received a token or a session cookie, and the relying party trusted that token until it expired — often 
hours or days later. That model breaks down the moment something changes mid-session: a device is reported stolen, an account is suspended, a privilege is revoked, a risk signal fires, 
or a user is offboarded by HR. 

**Security signals processing** is the practice of communicating security related changes and events — continuously, asynchronously, and across organizational and product boundaries — so every system holding a session or a credential can react in near real time. This is done using
a specialized form of Json Web Tokens called Security Event Tokens, a cryptographically signed message.

The canonical examples:

- An identity provider detects a compromised account and wants to inform every downstream SaaS application to terminate that user's sessions *now*, not at the next token refresh.
- An MDM platform marks a device as out of compliance and informs every application running on that device to revoke access.
- A SCIM-based provisioning system inactivates a user and informs every connected resource server to expire any cached state.
- A fraud engine raises a user's risk score and informs the IdP to step up authentication on the next sensitive action.

Doing this well at scale takes more than goodwill between IdPs and SaaS applications. It takes a stack of agreements about format, transport, semantics, and operations — and the operational infrastructure to make those agreements run in production.

## What does it take to build a Security Signals Processing infrastructure?

The IETF and the OpenID Foundation have been assembling consensus around the stack. Five questions, five answers — and a gap that goSignals is built to fill.

**1. How do we describe a security event in a way every recipient can verify?**
[RFC 8417](https://www.rfc-editor.org/rfc/rfc8417) defines the **Security Event Token (SET)**: a JWT-based data structure that conveys a statement of fact, from an issuer, about a security subject — that something happened to or about that subject. A SET is not a command. It is a signed claim that an event occurred, which the receiver is free to act on, or not, according to its own policy. Every other spec in this stack rides on top of SETs.

**2. How do SETs get from a transmitter to a receiver?**
[RFC 8935](https://www.rfc-editor.org/rfc/rfc8935) defines **push-based delivery** over HTTP, in which the transmitter POSTs each SET to a receiver endpoint. [RFC 8936](https://www.rfc-editor.org/rfc/rfc8936) defines **poll-based delivery**, in which the receiver fetches batches of pending SETs from the transmitter. Push fits receivers that can host endpoints; poll fits receivers behind a firewall or in environments where outbound is the only reliable direction.

**3. How do transmitters and receivers find each other, agree on what they share, and manage the relationship over time?**
The OpenID Foundation's [Shared Signals Framework (SSF)](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html) defines that layer — configuration discovery, stream lifecycle management, subject identifiers, and verification flows. SSF turns a bespoke integration into a managed stream.

**4. What events specifically should we be sending?**
Three event vocabularies, all carried as SETs over SSF streams:

- [OpenID CAEP](https://openid.net/specs/openid-caep-1_0-final.html) — **Continuous Access Evaluation Profile**: session revoked, credential change, device compliance change, assurance level change. The vocabulary for keeping active sessions honest.
- [OpenID RISC](https://openid.net/specs/openid-risc-1_0-final.html) — **Risk Incident Sharing and Coordination**: account credential changes, account disabled, identifier changes. The vocabulary for telling peers about account-level changes that affect risk.
- [RFC 9967](https://www.rfc-editor.org/rfc/rfc9967) — **SCIM Profile for Security Event Tokens**: provisioning-lifecycle events that let SCIM service providers and receivers exchange asynchronous change notifications. The vocabulary for identity-data synchronization.

**5. How does any of this survive an outage, a backlog, a misbehaving peer, or a federation boundary between trust zones?**
The specs define the wire and the words — not durable storage, replay, fan-out, ingress validation, egress re-signing, or the operational controls a production deployment needs. That gap is filled by a **Security Event Router** — the gap **goSignals** is built to fill.

## The standards landscape

_A quick reference for the specifications i2goSignals implements and interoperates with — several of which were authored or co-authored by contributors to this project._

| Specification | Defines | Status |
|---|---|---|
| [OpenID SSF 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html) | Stream management, configuration discovery, subject identifiers, and wire framing for shared security event delivery | OpenID Final Spec (Sept 2025) |
| [OpenID CAEP 1.0](https://openid.net/specs/openid-caep-1_0-final.html) | Continuous Access Evaluation event types (session revocation, credential change, device compliance, assurance level) | OpenID Final Spec (Sept 2025) |
| [OpenID RISC 1.0](https://openid.net/specs/openid-risc-1_0-final.html) | Risk Incident Sharing and Coordination event types (account credential change, account disabled, identifier change) | OpenID Final Spec (Sept 2025) |
| [RFC 8417](https://www.rfc-editor.org/rfc/rfc8417) | Security Event Token (SET) — JWT-based envelope for all of the above | IETF Proposed Standard (2018) |
| [RFC 8935](https://www.rfc-editor.org/rfc/rfc8935) | Push-based SET delivery over HTTP | IETF Proposed Standard (2020) |
| [RFC 8936](https://www.rfc-editor.org/rfc/rfc8936) | Poll-based SET delivery over HTTP | IETF Proposed Standard (2020) |
| [RFC 9967](https://www.rfc-editor.org/rfc/rfc9967) | SCIM Profile for Security Event Tokens — provisioning-lifecycle event types; updates RFC 7643 and RFC 7644 | IETF Proposed Standard (May 2026) |

## What is goSignals?

**goSignals** is a high-performance security event router and processor designed to facilitate the secure exchange of Security Event Tokens (SETs) between systems. It acts as a bridge, gateway, or store-and-forward server, connecting security event generators (transmitters) to receivers across different domains.

### Main Components
* **[goSignals Tool](docs/gosignals_tool.md)** (`cmd/goSignals`): A powerful command-line utility for configuring and administering goSignals and SSF-compliant servers.
* **goSignals Server** (`cmd/goSignalsServer`): The core service implementing SET delivery protocols and the SSF framework. It uses **MongoDB** for persistent storage of configuration, keys, and event streams.
* **goSet Library** (`pkg/goSet`): A Go package for creating, parsing, and validating SET tokens, with built-in support for SCIM, RISC, and CAEP event types.

## What is the purpose of this project?

**For developers and platform engineers**, this repository is the **community edition** of goSignals — the open source core of the Security Event Router, released under Apache 2.0. The fastest path in is [Getting Started](#getting-started) and the [Demonstration Walk-through](#demonstration-walk-through); [Capabilities](#capabilities) and [Main Components](#main-components) are the quickest scan of what's implemented.

**For organizations evaluating goSignals as a product** — for licensing, embedding, or commercial deployment alongside the I2 administration server or planned hosted service — start with [What is goSignals?](#what-is-gosignals) and read through [Capabilities](#capabilities). For commercial conversations, contact <info@independentid.com>.

## Project Status
The i2goSignals project is currently under active development. This preview code is intended for feedback and community involvement and is **not yet ready for production**. Key features like administration API security and multi-node coordination are being finalized.

## Capabilities
- **Protocol Interoperability**: Acts as a protocol converter, allowing Poll-only receivers to pick up events from Push-only transmitters.
- **Advanced Routing**: Controls how events are validated, filtered, and re-published to one or more outbound streams based on issuer and audience.
- **Stream Management**: Implements full SSF stream lifecycle management, including registration, status updates, and subject management.
- **Fault Tolerance**: Supports stream recovery, automatic re-transmission, and configurable resets to specific dates or Event Identifiers (`JTI`).
- **Security & Identity**:
  - Validates events based on configured signing and encryption requirements.
  - Integrates with **SPIFFE/SPIRE** for workload identity and mutual TLS (mTLS).
  - Supports OAuth2 and HMAC for API and inter-cluster authentication.

## Getting Started

### Prerequisites
* [Go 1.25+](https://go.dev)
* [Docker Desktop](https://www.docker.com/products/docker-desktop) for local testing and development
* [MongoDB](https://www.mongodb.com/) (provided in Docker Compose setups)

### Installation
```bash
git clone https://github.com/i2-open/i2gosignals.git
cd i2gosignals
make build
```

### SPIFFE Registration
When using SPIFFE-enabled setups, register workloads once the services are healthy:
```bash
docker exec spire-server sh /etc/spire/registration/register.sh
```

## Documentation
* [GoSignals Administration Tool](docs/gosignals_tool.md) - CLI usage and commands.
* [Configuration Properties](docs/configuration_properties.md) - Environment variables and settings.
* [Security Model](docs/security_model.md) - Authentication, authorization, and SPIFFE details.
* [Clustering & High Availability](docs/Cluster.md) - Multi-node deployment and lease management.
* [Metrics & Monitoring](docs/Metrics.md) - Prometheus and Grafana integration.
* [Observability & Log Shipping](docs/observability.md) - Structured JSON logging, label schema, and cloud-specific shipper recipes (Loki, CloudWatch, Cloud Logging, Azure Monitor).
* [OIDC Implementation](docs/OIDC_IMPLEMENTATION.md) - Keycloak integration and administrative authentication.
* [Keycloak SSF Transmitter Guide](docs/keycloak-ssf-guide.md) - Hands-on walk-through for running the identitytailor SSF PoC and emitting CAEP/RISC events to a receiver.
* [SPIFFE/SPIRE Support](docs/spiffe_support.md) - SPIFFE integration support.

## Docker Compose Setups

There are several Docker Compose configurations for various use cases and demonstrations.

| File | Purpose | Key Features |
| :--- | :--- | :--- |
| `docker-compose.yml` | **Standard Demo** | Full stack with 2 nodes, MongoDB replica set, Keycloak, and monitoring (Prometheus/Grafana). |
| `docker-compose-dev.yml` | **Development** | Optimized for dev: live code mounting, Delve debugger (ports 2345-2347). |
| `docker-compose-spiffe.yml` | **SPIFFE Demo** | Adds SPIRE for workload identity and mTLS between nodes and MongoDB. |
| `docker-compose-cluster.yml` | **Clustered Demo** | Adds Nginx load balancer and redundant nodes for high-availability testing. |

**Note**: The `-dev` variants use `Dockerfile-dev` and mount the source code for live changes.

### Demonstration Walk-through

The `docker-compose.yml` file provides a sample environment demonstrating Push and Poll scenarios between two i2goSignals servers, along with `i2scim.io` servers for multi-master replication.

1. **Build the project**: `make build`
2. **Configure local DNS**: Add `goSignals1`, `goSignals2`, and `keycloak` to your `/etc/hosts` pointing to `127.0.0.1`. The `keycloak` entry is required so that browser-side SSO redirects (e.g. Grafana logging in via Keycloak) resolve to the local stack.
3. **Trust the dev CA**: The stack serves TLS with a self-signed CA. Import `config/certs/ca-cert.pem` into your browser or OS trust store so that `https://localhost:3000` (Grafana) and `https://keycloak:9080` are accepted without certificate warnings.
   - macOS: `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain config/certs/ca-cert.pem`
   - Linux: copy to `/usr/local/share/ca-certificates/` and run `sudo update-ca-certificates`
   - Firefox keeps its own store — import the CA under Settings → Privacy & Security → Certificates.
4. **Start services**: `docker compose up -d`
5. **Automated Configuration**: The `scimSsfSetup` service automatically configures the streams. To perform manual configuration or explore the tool:
   ```bash
   ./goSignals
   goSignals> add server gs1 http://goSignals1:8888
   ```

### Grafana SSO

Grafana is served at `https://localhost:3000`. The local username/password
login form is disabled — the only way in is **Sign in with GoSignals Realm**,
which authenticates against the `gosignals` Keycloak realm. Demo users map to
Grafana org roles via the `grafana` client roles: `admin` → Admin, `user` →
Viewer; any authenticated realm user with no `grafana` client role falls back
to Viewer.

## Developing and Debugging (GoLand/IntelliJ)

1. **Build dev image**: `make dev-build-image`
2. **Start dev stack**: `make dev-up`
3. **Attach Debugger**:
   - Create a **Go Remote** configuration in GoLand.
   - Set Host to `localhost`, Port to `2345`.
   - Map local root to `/app` in "Paths mapping".
   - Set breakpoints and click Debug.

Use `make dev-logs` to follow logs and `make dev-down` to stop the stack.

---
*Production image builds use `sh ./build.sh` and the standard `docker-compose.yml`.*

---

<!-- gosignals-brand-footer -->
<p align="center"><sub><img src="./brand/logo/gosignals-favicon-simple.svg" width="12" height="12" alt="goSignals"> (C)2026 Independent Identity Inc.</sub></p>
