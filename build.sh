 #!/usr/bin/env bash
#
# Go Signals docker image builder.
#
# Single buildx invocation produces one manifest list across all requested
# platforms. Push tags both :$tag and :latest at the same digest. Local
# (no-push) builds load a single host-arch image into the docker daemon.
#
# Usage:
#   ./build.sh                    # local single-arch (host) image -> i2gosignals:$tag
#   ./build.sh -t                 # also run go test ./... first
#   ./build.sh -n 1.2.3           # override the tag
#   ./build.sh -p                 # push single host-arch image with :tag and :latest
#   ./build.sh -m -p              # push multi-arch manifest (linux/amd64,linux/arm64)
#   ./build.sh -m -p -a amd64     # push manifest restricted to one arch
#   ./build.sh -c                 # install goSignals CLI from upstream and exit
#
# Image references:
#   local:  i2gosignals:$tag                 (loaded into local docker daemon)
#   push:   independentid/i2gosignals:$tag   (Docker Hub) plus :latest at same digest
#
set -euo pipefail

echo ""
echo "Go Signals builder utility"
echo "(meant for building docker images only — use Make for normal development)"
echo ""

BIN_DIR=bin
PUSH_REPO="independentid/i2gosignals"
LOCAL_IMAGE="i2gosignals"

tag="0.11.0-beta.1"
test="N"
doPush="N"
aIn="amd64,arm64"
multi="N"

optString="amhtdcpn:"
while getopts ${optString} OPTION; do
    case "$OPTION" in
        a)
            aIn=${OPTARG}
            echo "  .. selecting arch: $aIn"
            ;;
        t)
            test="Y"
            ;;
        n)
            tag=${OPTARG}
            echo "  ..using docker version tag: $tag"
            ;;
        p)
            echo "  ..push to Docker Hub requested"
            doPush="Y"
            ;;
        c)
            echo "* Installing goSignals CLI"
            if ! command -v goSignals &> /dev/null; then
                go install github.com/i2-open/i2goSignals/cmd/goSignals@latest
            fi
            goSignals help
            exit
            ;;
        m)
            echo "  ..multi platform build selected"
            multi="Y"
            ;;
        *)
            echo "Usage: ./build.sh [-t] [-m] [-p] [-n <tag>] [-a <arch1,arch2,...>] [-c]"
            echo "  -t           Run go test ./... before building"
            echo "  -m           Multi-arch image (default: amd64,arm64). Requires -p."
            echo "  -p           Push to Docker Hub. Tags both :\$tag and :latest at the same digest."
            echo "  -n <tag>     Tag version (default: $tag)"
            echo "  -a <archs>   Comma-separated arches when -m is set (default: $aIn)"
            echo "  -c           Install goSignals CLI from upstream and exit"
            exit 1
            ;;
    esac
done

echo ""

# --- Validate flag combinations ---
# Multi-arch images are OCI manifest lists. The local docker daemon's image
# store can't load a manifest list, so -m only makes sense with -p.
if [ "$multi" = "Y" ] && [ "$doPush" = "N" ]; then
    echo "ERROR: -m (multi-arch) requires -p (push)."
    echo "       Multi-arch manifests cannot be loaded into the local docker daemon."
    exit 1
fi

# --- Optional test pass ---
if [ "$test" = "Y" ]; then
    echo "* Building and running tests ..."
    go build ./...
    go test ./...
    echo ""
fi

# --- Resolve target architectures ---
if [ "$multi" = "Y" ]; then
    IFS=',' read -ra archs <<< "$aIn"
else
    archs=("$(go env GOARCH)")
fi

# --- Cross-compile Go binaries into bin/linux/<arch>/ ---
mkdir -p "${BIN_DIR}"

echo "* Cross-compiling Go binaries for: ${archs[*]}"
for arch in "${archs[@]}"; do
    outdir="${BIN_DIR}/linux/${arch}"
    mkdir -p "${outdir}"
    echo "  - building ${arch} -> ${outdir}"
    CGO_ENABLED=0 GOOS=linux GOARCH=${arch} go build -o "${outdir}/goSignals"       ./cmd/goSignals/...
    CGO_ENABLED=0 GOOS=linux GOARCH=${arch} go build -o "${outdir}/goSignalsServer" ./cmd/goSignalsServer/...
    CGO_ENABLED=0 GOOS=linux GOARCH=${arch} go build -o "${outdir}/goSsfServer"     ./cmd/goSsfServer/...
    CGO_ENABLED=0 GOOS=linux GOARCH=${arch} go build -o "${outdir}/cluster-monitor" ./cmd/cluster-monitor/...
    CGO_ENABLED=0 GOOS=linux GOARCH=${arch} go build -o "${outdir}/genTlsKeys"      ./cmd/genTlsKeys/...
    CGO_ENABLED=0 GOOS=linux GOARCH=${arch} go build -o "${outdir}/healthcheck"     ./cmd/healthcheck/...
done
echo ""

# --- Compose buildx --platform list (linux/amd64,linux/arm64) ---
platforms=""
for arch in "${archs[@]}"; do
    if [ -z "$platforms" ]; then
        platforms="linux/${arch}"
    else
        platforms="${platforms},linux/${arch}"
    fi
done

# --- Ensure a buildx builder exists that can produce manifest lists ---
# The default buildx builder uses the `docker` driver, which only supports
# a single platform. Multi-arch builds need a `docker-container` builder.
if [ "$multi" = "Y" ]; then
    current_driver=$(docker buildx inspect 2>/dev/null | awk '/^Driver:/ {print $2}')
    if [ "${current_driver:-}" != "docker-container" ]; then
        if ! docker buildx inspect i2sig >/dev/null 2>&1; then
            echo "* Creating docker-container buildx builder 'i2sig' (one-time)"
            docker buildx create --name i2sig --driver docker-container --bootstrap
        fi
        docker buildx use i2sig
    fi
fi

echo "* Building docker image (tag: ${tag}, platforms: ${platforms})"

if [ "$doPush" = "Y" ]; then
    echo "  - pushing tags: ${PUSH_REPO}:${tag}, ${PUSH_REPO}:latest"
    docker buildx build \
        --platform "${platforms}" \
        --provenance=mode=max \
        --sbom=true \
        --tag "${PUSH_REPO}:${tag}" \
        --tag "${PUSH_REPO}:latest" \
        --metadata-file "${BIN_DIR}/build-meta.json" \
        --push \
        .
    echo ""
    echo "  - manifest metadata captured at: ${BIN_DIR}/build-meta.json"
else
    # Local single-arch path. Skip SBOM/provenance (those produce OCI indexes
    # that the local daemon can't --load without containerd image store).
    echo "  - loading into local docker daemon as ${LOCAL_IMAGE}:${tag}"
    docker buildx build \
        --platform "${platforms}" \
        --tag "${LOCAL_IMAGE}:${tag}" \
        --load \
        .
fi

echo ""
echo "  Build complete."
