
This is a proposal to modify Dockerfile builds moving away from chainguard and towards an even smaller distribution.

Instead of starting with FROM cgr.dev/chainguard/bash:latest@sha256:580c4beaeb19e77fbfbaf0a28752b7d47edb04fb939986b8b8d7c5cc01bc80e5

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

