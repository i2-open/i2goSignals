#!/usr/bin/env bash
#
# Thin shim around the Makefile, preserved for muscle memory and any external
# automation that still invokes build.sh directly. New work should call
# `make build-docker` / `make build-docker-multiarch` directly.
#
# Usage:
#   ./build.sh                    # local single-arch image -> i2gosignals:<version>
#   ./build.sh -t                 # also run go test ./... first
#   ./build.sh -n 1.2.3           # override the version tag (overrides version.txt)
#   ./build.sh -p                 # push single host-arch image with :<tag> and :latest
#   ./build.sh -m -p              # push multi-arch manifest (linux/amd64,linux/arm64)
#   ./build.sh -m -p -a amd64     # push manifest restricted to one arch
#   ./build.sh -c                 # install goSignals CLI from upstream and exit
#
# The canonical version comes from pkg/constants/version.txt (also embedded
# into every Go binary via //go:embed). `-n <tag>` here forwards as
# `VERSION=<tag>` to make, which overrides the file at build time only.
#
set -euo pipefail

echo ""
echo "Go Signals build.sh — shim that delegates to the Makefile."
echo "(prefer 'make build-docker' or 'make build-docker-multiarch' going forward)"
echo ""

tag=""
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
            echo "  -p           Push to the configured registry."
            echo "  -n <tag>     Override version tag (default: pkg/constants/version.txt)"
            echo "  -a <archs>   Comma-separated arches when -m is set (default: $aIn)"
            echo "  -c           Install goSignals CLI from upstream and exit"
            exit 1
            ;;
    esac
done

if [ "$multi" = "Y" ] && [ "$doPush" = "N" ]; then
    echo "ERROR: -m (multi-arch) requires -p (push)."
    echo "       Multi-arch manifests cannot be loaded into the local docker daemon."
    exit 1
fi

if [ "$test" = "Y" ]; then
    echo "* Running go test ./..."
    go build ./...
    go test ./...
    echo ""
fi

# Build the PLATFORMS list (multi-arch) or leave default (single host arch).
make_args=()
if [ -n "$tag" ]; then
    make_args+=("VERSION=$tag")
fi

if [ "$multi" = "Y" ]; then
    platforms=""
    IFS=',' read -ra archs <<< "$aIn"
    for arch in "${archs[@]}"; do
        if [ -z "$platforms" ]; then
            platforms="linux/${arch}"
        else
            platforms="${platforms},linux/${arch}"
        fi
    done
    make_args+=("PLATFORMS=$platforms")
    exec make build-docker-multiarch "${make_args[@]}"
elif [ "$doPush" = "Y" ]; then
    # Single-arch push: build locally first, then docker push both tags.
    make build-docker "${make_args[@]}"
    # Resolve the effective version for the push tags (mirrors Make's logic).
    push_version="${tag:-$(tr -d '[:space:]' < pkg/constants/version.txt)}"
    push_repo="${PUSH_REPO:-independentid/i2gosignals}"
    local_image="${LOCAL_IMAGE:-i2gosignals}"
    docker tag "${local_image}:${push_version}" "${push_repo}:${push_version}"
    docker tag "${local_image}:${push_version}" "${push_repo}:latest"
    docker push "${push_repo}:${push_version}"
    docker push "${push_repo}:latest"
    echo ">> pushed ${push_repo}:${push_version} and :latest"
else
    exec make build-docker "${make_args[@]}"
fi