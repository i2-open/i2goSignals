# i2goSignals

<div style="text-align: right"><img src="media/GoSignals-msgs.png" title="GoSignals-Msgs" width=300  alt="i2GoSignals!"/></div>

**_goSignals_** is a security signals processor that provides the ability to route Security Events between systems.
A Security Event is a token that describes an event that has occurred within the domain of an issuer. A 
[Security Event Token RFC8417](https://www.rfc-editor.org/rfc/rfc8417) is a specialized type of Json Web Token 
traditionally used in [OAuth2](https://www.rfc-editor.org/rfc/rfc6749) based authentication and authorization systems. Typically a series of "SET" tokens
are shared in a series called a stream between a publisher and receiver. The management of these streams is defined by
the OpenID [Shared Signals Events Framework](https://openid.net/specs/openid-sharedsignals-framework-1_0-02.html).  The mechanism for the transfer of Security Event Tokens is defined
by the SET Event transfer protocols ([RFC8935](https://www.rfc-editor.org/rfc/rfc8935) and [RFC8936](https://www.rfc-editor.org/rfc/rfc8936)). 

The **_goSignals_** server works as a gateway router or store and forward server connecting one or more security 
event generators to one or more receivers across domains using streams. An **_goSignals_** server is able to receive, 
validate, route, and forward Security Event Tokens (SETs) in streams to registered receivers.

The i2goSignals server has the following capabilities:
* Implementation of both SET PUSH (RFC8935) and SET POLL (RFC8936) Protocols
* Organizes SETS into streams between publishers (event generators) and receivers (as defined in RFC8935/8936). 
* Support for multiple inbound and outbound streams and routing between them
* Acts as a protocol converter such as enabling Receivers that support Poll transfer only (e.g. from behind a firewall) to pick up events from SET Push-only transmitters.
* Support for fault-tolerant stream recovery including automatic re-transmission and stream resets as well as configurable stream resets to a specified date or event identifier (`JTI`).
* Supports routing which controls how events are forwarded, and/or re-published to one or more outbound streams
* Validates events based on configured stream signing and encryption requirements.

The i2goSignals project is currently under development and is published for feedback and community involvement at this time.  This 
preview code is not yet ready for production. Key features such as administration API security, multi-node co-ordination and TLS are still in progress.

There are 3 main components to this project
* goSet - utility functions to create SET tokens (which are a profile of JWT tokens) and a set of convenience methods to add, validate, and parse events. Includes support for SCIM Events.
* cmd/goSignalsServer - provides a services framework to implement push and pull delivery services. This framework depends on MongoDB to store configuration and key data. SSEF also uses Kafka to pick up and store event streams per registered stream.
* cmd/goSignalsTool - A command line tool which can be used to configure and administrator an goSignals server.

## Getting Started

Clone or download the codebase from GitHub to your local machine and install the following prerequisites.

* [Go 1.21.5](https://go.dev) - Note: in GoLand make sure to select the correct version of go `Preferences > Go > GOROOT`.
* [Docker Desktop](https://www.docker.com/products/docker-desktop) for local testing and development

```bash
cd /home/user/workspace/
git clone git@github.com:i2-open/i2gosignals.git
```
To run the demonstration configuration, see Demonstration Set Up below.


Building a local docker image (starting from the main project directory):
```bash
go install ./...
docker build . --tag i2gosignals
```
> [!NOTE] 
> The 0.7.0 release image is also available at ghcr.io/i2-open/i2gosignals:0.7.0

This project uses MongoDB for event, key, and stream storage, management, and recovery. By default, unit testing is done with the MongoDb server defined in [docker-compose.yml](docker-compose.yml).

The use of Mongo can be changed out to other database systems. However at this time, it would depend on contributors to implement or sponsor such support.

Run the i2goSignals server and Mongo database using docker-compose

## Documentation
* [goSignals administration tool](docs/gosignals_tool.md)
* [Supported environment properties](docs/configuration_properties.md)


## Demonstration Set Up
in the file [docker-compose.yml](docker-compose.yml) is a sample set up that demonstrates both Push and Pull stream scenarios between 2 separate i2goSignals
servers. Additionally, 2 i2scim.io servers are used to demonstrate multi-master replication using SCIM defined provisioning events.

To configure the demonstration do the following:
1. Build the goSignals project (see above)
2. In /ect/hosts or your localdns configuration, define goSignals1 and goSignals2 to point to the corresponding goSignals server in docker (e.g. 127.0.0.1).
3. Start all servocers in `docker-compose.yml`
4. Start the `goSignals` tool and perform the following configuration
```bash
To be completed.
```

## Developing and debugging inside Docker (GoLand/JetBrains)

Use the dev stack to run `goSignalsServer` under the Delve debugger in Docker so you can attach from GoLand or IntelliJ with the Go plugin.

Prerequisites:
- Docker Desktop running
- GoLand or IntelliJ IDEA Ultimate with Go plugin

Start the dev stack with the debug-enabled service:

```bash
# Build the dev image (installs Delve)
make dev-build-image

# Start Mongo, Prometheus, Grafana, and goSignals1 under Delve
make dev-up

# Follow logs if desired
make dev-logs
```

Notes:
- The dev image is defined in `Dockerfile-dev` and started by `docker-compose-dev.yml`.
- The project source is volume-mounted into the container at `/app`. Delve recompiles the server inside the container, so first start may take a little longer while modules download.
- Ports exposed:
  - 8888: application API/UI
  - 2345: Delve debug port

Attach the debugger from JetBrains (GoLand/IntelliJ):
1. Run > Edit Configurations… > add “Go Remote”.
2. Set Host to `localhost` and Port to `2345`.
3. Open “Paths mapping” and add a mapping from your local project root to `/app` (container path).
4. Click Debug to attach. Set breakpoints in server code under `cmd/goSignalsServer` or packages it uses.

Iterating:
```bash
# Rebuild the dev image (if Dockerfile-dev changed) and restart just goSignals1
make dev-rebuild

# Stop the dev stack
make dev-down
```

Production image builds are unchanged; continue to use `./build.sh` to create the normal release image `i2gosignals:<tag>` and `docker-compose.yml` for the full demo stack.