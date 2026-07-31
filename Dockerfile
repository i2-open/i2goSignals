# syntax=docker/dockerfile:1

# chainguard/bash (minimal distroless image with bash) — required because operators
# run shell scripts inside the container to drive the goSignals CLI. Digest pin keeps
# builds reproducible; bump deliberately when refreshing the base image.
# Refresh procedure: `crane digest cgr.dev/chainguard/bash:latest`.
FROM cgr.dev/chainguard/bash:latest@sha256:580c4beaeb19e77fbfbaf0a28752b7d47edb04fb939986b8b8d7c5cc01bc80e5

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

# The binaries below statically link third-party Go dependencies, so the image
# is a binary redistribution. Ship the project license and the dependency
# attributions to satisfy the Apache 2.0, BSD, MIT, and ISC license terms.
# Copied first: they change only when the dependency set does.
COPY --chmod=0644 ./LICENSE.txt              ./LICENSE.txt
COPY --chmod=0644 ./THIRD-PARTY-NOTICES.txt  ./THIRD-PARTY-NOTICES.txt

# Ordered least- to most-frequently-changed, deliberately. BuildKit's cache is a
# linear chain — invalidating one COPY re-runs every step below it — so the
# binaries that move on almost every commit go last. The order follows each
# binary's in-repo dependency set (`go list -deps ./cmd/<name>/...`):
#
#   healthcheck       imports no in-repo package but its own
#   genTlsKeys        pkg/constants only (so it moves on a version.txt bump)
#   cluster-monitor   envcompat, logger, tlsSupport
#   goSignals         10 in-repo packages
#   goSsfServer       36 in-repo packages
#   goSignalsServer   35, of which 34 are also imported by goSsfServer
#
# Cache keys are content checksums, not mtimes, so re-running cross-compile-linux
# without a source change does not invalidate anything: the Go link is
# reproducible under -trimpath + CGO_ENABLED=0, and a no-op rebuild still gives
# 11 of 11 steps cached.
#
# Know the limit before relying on this ordering: cmd/goSignalsServer is the only
# package exclusive to goSignalsServer. Any edit under internal/ or pkg/ moves
# several binaries at once (a pkg/logger change moves four), and no ordering
# helps there. Measured on a cmd/goSignalsServer-only change: 4 of 11 steps
# cached in the old order, 10 of 11 in this one.
COPY --chmod=0755 ./bin/linux/${TARGETARCH}/healthcheck     ./healthcheck
COPY --chmod=0755 ./bin/linux/${TARGETARCH}/genTlsKeys      ./genTlsKeys
COPY --chmod=0755 ./bin/linux/${TARGETARCH}/cluster-monitor ./cluster-monitor
COPY --chmod=0755 ./bin/linux/${TARGETARCH}/goSignals       ./goSignals
COPY --chmod=0755 ./bin/linux/${TARGETARCH}/goSsfServer     ./goSsfServer
COPY --chmod=0755 ./bin/linux/${TARGETARCH}/goSignalsServer ./goSignalsServer

# Build-time metadata, populated by the Makefile from pkg/constants/version.txt,
# `git rev-parse --short HEAD`, and the build host's UTC clock.
#
# Declared LAST, deliberately — do not move these back above the COPYs. An ARG
# in scope becomes part of the cache key of every step below it (visible in
# `docker history` as `RUN |5 VERSION=... BUILD_DATE=... /bin/sh -c mkdir ...`),
# and BUILD_DATE is a fresh timestamp on every `make` invocation. Declaring them
# next to the FROM invalidated the RUN and all eight COPY layers on every single
# build: 1 of 11 steps cached, versus 11 of 11 in this order. LABEL emits no
# filesystem layer, so there is nothing below these for them to invalidate.
#
# ARG TARGETARCH and ARG USER above are exempt: the COPY paths and the RUN/USER
# steps reference them, so they must stay on top. Neither churns — TARGETARCH is
# fixed per --platform target and USER is a constant.
ARG VERSION=dev
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.authors="phil.hunt@independentid.com"
LABEL org.opencontainers.image.source="https://github.com/i2-open/i2gosignals"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.revision="${VCS_REF}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"

EXPOSE 8888

# Image-level default health probe. Mirrors the per-service healthchecks in the
# compose files so plain `docker run` gets the same signal. /app/healthcheck is
# used instead of curl/wget — the chainguard/bash base ships neither — and is
# exec'd directly, so no shell is involved. TLS is the default listener, hence
# https and -k (the server may present a self-signed or SPIFFE cert). The binary
# takes a single URL and has no scheme fallback, so a TLS-disabled deployment or
# a non-default port must override with `docker run --health-cmd` (or the compose
# `healthcheck` key). retries x interval gives a 5-minute grace window for
# mongo/cluster join.
HEALTHCHECK --interval=10s --timeout=5s --retries=30 \
    CMD ["/app/healthcheck", "-k", "https://localhost:8888/health"]

CMD ["/app/goSignalsServer"]
