# syntax=docker/dockerfile:1

# chainguard/bash (minimal distroless image with bash) — required because operators
# run shell scripts inside the container to drive the goSignals CLI. Digest pin keeps
# builds reproducible; bump deliberately when refreshing the base image.
# Refresh procedure: `crane digest cgr.dev/chainguard/bash:latest`.
FROM cgr.dev/chainguard/bash:latest@sha256:580c4beaeb19e77fbfbaf0a28752b7d47edb04fb939986b8b8d7c5cc01bc80e5

# Build-time metadata, populated by the Makefile from pkg/constants/version.txt,
# `git rev-parse --short HEAD`, and the build host's UTC clock.
ARG VERSION=dev
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.authors="phil.hunt@independentid.com"
LABEL org.opencontainers.image.source="https://github.com/i2-open/i2gosignals"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.revision="${VCS_REF}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"

# Set automatically by buildx (amd64, arm64, ...) per --platform target.
# Selects the per-arch binaries staged by the Makefile under bin/linux/<arch>/.
# Always invoke this Dockerfile through `make build-docker` — plain `docker build`
# without buildx will leave TARGETARCH unset and the COPY paths won't resolve.
ARG TARGETARCH

ARG USER=1000:1000

WORKDIR /app

# /app/resources is where the mongo watchtokens code writes its resume-token file.
# WORKDIR is owned by root, so we create the directory and hand it to the runtime
# user before dropping privileges. tokens.go MkdirAll's nested paths at runtime,
# but the parent must already be writable by the unprivileged process.
RUN mkdir -p /app/resources && chown ${USER} /app/resources && chmod 0770 /app/resources

# Numeric UID is required so k8s pod securityContext runAsNonRoot can resolve it
# (named users don't work: https://github.com/kubernetes/kubernetes/issues/40958).
USER ${USER}

COPY --chmod=0755 ./bin/linux/${TARGETARCH}/goSignals       ./goSignals
COPY --chmod=0755 ./bin/linux/${TARGETARCH}/goSignalsServer ./goSignalsServer
COPY --chmod=0755 ./bin/linux/${TARGETARCH}/goSsfServer     ./goSsfServer
COPY --chmod=0755 ./bin/linux/${TARGETARCH}/cluster-monitor ./cluster-monitor
COPY --chmod=0755 ./bin/linux/${TARGETARCH}/genTlsKeys      ./genTlsKeys
COPY --chmod=0755 ./bin/linux/${TARGETARCH}/healthcheck     ./healthcheck

# The binaries above statically link third-party Go dependencies, so the image
# is a binary redistribution. Ship the project license and the dependency
# attributions to satisfy the Apache 2.0, BSD, MIT, and ISC license terms.
COPY --chmod=0644 ./LICENSE.txt              ./LICENSE.txt
COPY --chmod=0644 ./THIRD-PARTY-NOTICES.txt  ./THIRD-PARTY-NOTICES.txt

EXPOSE 8888

CMD ["/app/goSignalsServer"]
