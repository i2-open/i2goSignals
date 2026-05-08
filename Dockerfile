# syntax=docker/dockerfile:1

# chainguard/bash (minimal distroless image with bash) — required because operators
# run shell scripts inside the container to drive the goSignals CLI. Digest pin keeps
# builds reproducible; bump deliberately when refreshing the base image.
FROM cgr.dev/chainguard/bash:latest@sha256:b434d0c46e9daebb872eb5cd1579cfa4a71a76cfece9b6b8750513c61de39edd

LABEL org.opencontainers.image.authors="phil.hunt@independentid.com"
LABEL org.opencontainers.image.source="https://github.com/i2-open/i2gosignals"

# Set automatically by buildx (amd64, arm64, ...) per --platform target.
# Selects the per-arch binaries staged by build.sh under bin/linux/<arch>/.
# Always invoke this Dockerfile through build.sh — plain `docker build`
# without buildx will leave TARGETARCH unset and the COPY paths won't resolve.
ARG TARGETARCH

ARG USER=1000:1000

WORKDIR /app

# Numeric UID is required so k8s pod securityContext runAsNonRoot can resolve it
# (named users don't work: https://github.com/kubernetes/kubernetes/issues/40958).
USER ${USER}

COPY --chmod=0755 ./bin/linux/${TARGETARCH}/goSignals       ./goSignals
COPY --chmod=0755 ./bin/linux/${TARGETARCH}/goSignalsServer ./goSignalsServer
COPY --chmod=0755 ./bin/linux/${TARGETARCH}/goSsfServer     ./goSsfServer
COPY --chmod=0755 ./bin/linux/${TARGETARCH}/cluster-monitor ./cluster-monitor
COPY --chmod=0755 ./bin/linux/${TARGETARCH}/genTlsKeys      ./genTlsKeys
COPY --chmod=0755 ./bin/linux/${TARGETARCH}/healthcheck     ./healthcheck
COPY --chmod=0766 --chown=${USER} ./cmd/goSignals/resources ./resources

EXPOSE 8888

CMD ["/app/goSignalsServer"]
