
This is a proposal to modify Dockerfile builds moving away from chainguard and towards an even smaller distribution.

Instead of starting with FROM cgr.dev/chainguard/bash:latest@sha256:306e8dc981e8be097bbd5d56cd040e16d365f6d06ec602d2153e5021a14f8f6c

This is a generic idea. It will need to be adapted to cover all the execs:
```dockerfile
FROM golang:alpine as builder
WORKDIR /build
COPY . .
RUN go build -o /app .

FROM scratch
COPY --from=builder /app /app
```

This also has to be done in connection with setting up a .dockerignore file.

Note that some issues like the goSignals cli might need more support as they run scripted commands in docker-compose.yml

