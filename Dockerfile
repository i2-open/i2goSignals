# syntax=docker/dockerfile:1

FROM cgr.dev/chainguard/bash:latest

LABEL org.opencontainers.image.authors="phil.hunt@independentid.com"
LABEL org.opencontainers.image.source="https://github.com/i2-open/i2gosignals"

# Create a working directory to store mongo resume tokens

ARG USER=1000:1000

# Set destination for COPY
WORKDIR /app

# Any non-zero number will do, and unfortunately a named user will not, as k8s
# pod securityContext runAsNonRoot can't resolve the user ID:
# https://github.com/kubernetes/kubernetes/issues/40958.

USER ${USER}

ADD --chmod=0755 ./goSignals ./goSignals
ADD --chmod=0755 ./goSignalsServer ./goSignalsServer
ADD --chmod=0766 --chown=${USER} ./cmd/goSignals/resources ./resources

# Optional:
# To bind to a TCP port, runtime parameters must be supplied to the docker command.
# But we can document in the Dockerfile what ports
# the application is going to listen on by default.
# https://docs.docker.com/engine/reference/builder/#expose
EXPOSE 8888

# Run
CMD ["/app/goSignalsServer"]

