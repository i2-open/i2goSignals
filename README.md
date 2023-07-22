# i2goSignals Project

i2goSignals is an open source Golang implementation of Security Event Tokens (RFC8417), SET Push Delivery (RFC8935) and SET 
Poll-based Delivery (RFC8936). The project also supports the OpenID [Shared Signals Events Framework](https://openid.net/wg/sse/).

There are 3 main components to this project
* goSet - utility functions to create SET tokens (which are a profile of JWT tokens) and a set of convenience methods to add, validate, and parse events. Includes support for SCIM Events.
* goSSEF - provides a services framework to implement push and pull delivery services. This framework depends on MongoDB to store configuration and key data. SSEF also uses Kafka to pick up and store event streams per registered stream.
* goSsefMongoKafka - provides an implementation based on Kafka message bus and MongoDB stream configuration management

## Getting Started

Clone or download the codebase from GitHub to your local machine and install the following prerequisites.

* [Go 1.19](https://go.dev)
* [Pack](https://buildpacks.io)
* [Docker Desktop](https://www.docker.com/products/docker-desktop)

```bash
cd /home/user/workspace/
git clone git@github.com:i2-open/i2gosignals.git
```

To use in Golang code, `import github.com/i2-open/i2goSignals`
To deploy the server, build an i2goSignals image with Pack. The newly created image will contain the ssef server.

Building with Heroku
```bash
pack build i2goSignals --builder heroku/buildpacks:20
```

Building with Docker
```bash
docker build . --tag i2gosignals
```

We'll be using postgresql and need to execute the below shell scripts from docker-compose.


Run the ssef server and the database using docker-compose

```bash
docker-compose up
```

Cleaning up. Remove all docker containers and volumes.

```bash
docker rm -f $(docker ps -a -q)
docker volume rm -f $(docker volume ls -q)
docker system prune -a -f
```

## Creating a Security Event

```

  subject := &EventSubject{
    SubIdentifier: SubIdentifier{Sub: "1234"},
  }

  set := CreateSetForStream(subject, testStream)

  payload_claims := map[string]interface{}{
    "aclaim": "avalue",
  }
  set.AddEventPayload("uri:testevent", payload_claims)

}
```


