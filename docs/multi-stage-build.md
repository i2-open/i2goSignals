
This is a proposal to modify Dockerfile builds moving away from chainguard and towards an even smaller distribution.

Instead of starting with FROM cgr.dev/chainguard/bash:latest@sha256:08e5da9421ccb57676c74fc8d228c48600c4b578a4797fd08a4f9b0e92b6ce9a

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

