
This is a proposal to modify Dockerfile builds moving away from chainguard and towards an even smaller distribution.

Instead of starting with FROM cgr.dev/chainguard/bash:latest@sha256:7457faf36c3b250e6644f3202bfba5cc4f6ec12cef3ac09fe63fd4c29babb33f

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

