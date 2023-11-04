# i2goSignals

<div style="text-align: right"><img src="media/GoSignals-msgs.png" title="GoSignals-Msgs" width=300 /></div>

**i2goSignals** is an open source GoLang project that enables the deployment of message routers designed to receive and route
Security Event Tokens to assigned receivers.  Security Event Tokens (RFC8417) are a version of Json Web Tokens often used
for authentication and authorization systems. However instead of conveying authorizations SET tokens are signals that 
convey security signals information between a publisher and a receiver. 

i2goSignals is under development to be an implementation of the the OpenID [Shared Signals Events Framework](https://openid.net/wg/sse/)
or SSF. To transfer SET Event Tokens between parties, the HTTP SET PUSH (RFC8935) and SET POLL (RFC8936) are used. In
order to ensure secure transfer, messages are organized into "streams" where by each individual SET is acknowledged by
receivers in order to guarantee lossless transfer of information.  Standard JOSE signing and encryption is used to validate
and authenticate the receiver of events.

i2goSignals has the following capabilities:
* Implementation of both SET PUSH (RFC8935) and SET POLL (RFC8936) Protocols
* Supports logical relationships between publishers and receivers in the form of "streams" (as defined in RFC8935/8936)
* Support for inbound and outbound streams
* All security events are stored to enable fault-tolerance and stream recovery in support of SET Acknowledged transfer protocols
* Routing allows received events to be forwarded, or re-published to outbound streams
* Each publishing stream defines the issuer and event types to be transmitted

This project is currently under development and is published for feedback and community involvement at this time.  This 
preview code is not yet ready for production. Key features such as administration API security, multi-node co-ordination and TLS are still in progress.

There are 3 main components to this project
* goSet - utility functions to create SET tokens (which are a profile of JWT tokens) and a set of convenience methods to add, validate, and parse events. Includes support for SCIM Events.
* cmd/goSignalsServer - provides a services framework to implement push and pull delivery services. This framework depends on MongoDB to store configuration and key data. SSEF also uses Kafka to pick up and store event streams per registered stream.
* cmd/goSignalsTool - A command line tool which can be used to configure and administrator an goSignals server.

## Getting Started

Clone or download the codebase from GitHub to your local machine and install the following prerequisites.

* [Go 1.19](https://go.dev)
* [Docker Desktop](https://www.docker.com/products/docker-desktop)

```bash
cd /home/user/workspace/
git clone git@github.com:i2-open/i2gosignals.git
```

To use in Golang code, `import github.com/i2-open/i2goSignals`
To deploy the server, build an i2goSignals image with Pack. The newly created image will contain the ssef server.

Building with Docker (in the project root):
```bash
go install ./...
docker build . --tag i2gosignals
```

This project currently uses MongoDB for event, key, and stream management.


Run the ssef server and the database using docker-compose

## Demonstration Set Up
in the file `docker-compose.yml` is a sample set up that demonstrates both Push and Pull stream scenarios between 2 separate i2goSignals
servers. Additionally, 2 i2scim.io servers are used to demonstrate multi-master replication using SCIM defined provisioning events.

To configure the demonstration do the following:
1. Build the goSignals project (see above)
2. In /ect/hosts or your localdns configuration, define goSignals1 and goSignals2 to point to the corresponding goSignals server in docker (e.g. 127.0.0.1).
3. Start all the service in `docker-compose.yml`
4. Start the `goSignals` tool and perform the following configuration
```bash
to be determined
```