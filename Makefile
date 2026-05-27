# Root Makefile to build the goSignals Go server, CLI, and container images.

GO ?= go

# Single source of truth for the app version: pkg/constants/version.txt.
# That file is also embedded into the binary via //go:embed (see
# pkg/constants/server.go), so bumping it in one place updates both the
# compiled-in default and every Make-driven build/tag.
VERSION    := $(shell tr -d '[:space:]' < pkg/constants/version.txt)
VCS_REF    := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# Injected into every Go binary. Overrides the embedded default in
# pkg/constants/server.go so CI / release builds can publish a branded tag
# (e.g. "1.2.3-rc1") without committing a one-off version.txt change.
VERSION_PKG := github.com/i2-open/i2goSignals/pkg/constants
LDFLAGS     := -X $(VERSION_PKG).GoSignalsVersion=$(VERSION)
GOFLAGS_BUILD := -trimpath
GO_BUILD := CGO_ENABLED=0 $(GO) build $(GOFLAGS_BUILD) -ldflags "$(LDFLAGS)"

# Docker image settings. Override on the command line to publish elsewhere:
#   make build-docker-multiarch REGISTRY=ghcr.io/i2-open IMAGE=i2gosignals
DOCKER      ?= docker
LOCAL_IMAGE ?= i2gosignals
PUSH_REPO   ?= independentid/i2gosignals
PLATFORMS   ?= linux/amd64,linux/arm64
BUILDX_BUILDER ?= i2sig

CONSOLE_DIR := cmd/goSignals
SERVER_DIR  := cmd/goSignalsServer
CONFIG_DIR  := config
SCIM_CONFIG := $(CONFIG_DIR)/scim
BIN_DIR     := bin
SERVER_BIN  := $(BIN_DIR)/goSignalsServer
DEV_IMAGE   := i2gosignals-dev:latest
DEV_IMAGE_STAMP := .dev-image.stamp

# Binaries staged under bin/linux/<arch>/ and copied by the production Dockerfile.
DOCKER_BINS := goSignals goSignalsServer goSsfServer cluster-monitor genTlsKeys healthcheck

.PHONY: all help build run console-build server-build clean clean-scim dev-clean \
    generate-certs check-certs licenses-check \
    build-docker build-docker-multiarch docker-sbom cross-compile-linux \
    dev-build-image dev-up dev-down dev-logs dev-rebuild ensure-dev-image \
    run-spiffe-demo dev-reset-spiffe dev-rebuild-spiffe-goSignals

all: build

help:
	@echo "Targets:"
	@echo "  build              - check-certs + console-build + server-build (no docker)"
	@echo "  console-build      - build the goSignals CLI"
	@echo "  server-build       - build bin/goSignalsServer"
	@echo "  run                - build + bring up docker-compose.yml demo cluster"
	@echo "  generate-certs     - regenerate self-signed CA + certs under config/certs/"
	@echo "  licenses-check     - verify Go deps use permissive licenses"
	@echo "  build-docker       - build & --load i2gosignals:$(VERSION) (+ :latest)"
	@echo "  build-docker-multiarch - build & push $(PUSH_REPO):$(VERSION) + :latest ($(PLATFORMS))"
	@echo "  docker-sbom        - export the image SBOM to bin/sbom-$(VERSION).json"
	@echo "  cross-compile-linux - cross-compile $(DOCKER_BINS) into bin/linux/<arch>/"
	@echo "  dev-up / dev-down / dev-logs / dev-rebuild - dev compose stack with Delve"
	@echo "  clean              - remove build artifacts"

# Build and install the command line console gosignals.
console-build:
	$(GO) build -ldflags "$(LDFLAGS)" ./$(CONSOLE_DIR)
	$(GO) install -ldflags "$(LDFLAGS)" ./$(CONSOLE_DIR)

# Build the Go server.
server-build:
	@mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(SERVER_BIN) ./$(SERVER_DIR)

# `build` no longer chains docker-build by default — the production image is
# heavyweight and not every caller wants Docker. Run `make build-docker`
# explicitly when you need it.
build: check-certs console-build server-build

# Check if certificates exist.
check-certs:
	@if [ ! -f config/certs/ca-cert.pem ]; then $(MAKE) generate-certs; fi

# Generate TLS certificates.
generate-certs:
	$(GO) run -ldflags "$(LDFLAGS)" ./cmd/genTlsKeys

# Verify every third-party dependency uses a permissive license (no copyleft or
# unlicensed code). Run this after changing go.mod, and update
# THIRD-PARTY-NOTICES.txt to match. Installs google/go-licenses on demand.
licenses-check:
	@command -v go-licenses >/dev/null 2>&1 || { \
		echo ">> installing go-licenses..."; \
		$(GO) install github.com/google/go-licenses@latest; \
	}
	@PATH="$$PATH:$$($(GO) env GOPATH)/bin" go-licenses check ./... \
		--disallowed_types=forbidden,restricted,unknown

# --- Container image targets (formerly in build.sh) -------------------------
#
# The production Dockerfile is a binary-copy distroless image: it expects
# pre-built per-arch binaries under bin/linux/<arch>/. `cross-compile-linux`
# produces them; the buildx targets below then assemble the image.
#
# PLATFORMS controls which architectures are produced. Override on the command
# line, e.g.
#   make build-docker-multiarch PLATFORMS=linux/amd64
#   make build-docker-multiarch PLATFORMS=linux/amd64,linux/arm64,linux/arm/v7

# Extract the architecture list from PLATFORMS (linux/amd64,linux/arm64 -> amd64 arm64).
# `comma` must be defined before use because := expands its RHS immediately.
comma := ,
ARCHS := $(subst linux/,,$(subst $(comma), ,$(PLATFORMS)))

# Cross-compile every binary the production Dockerfile copies, for every arch
# in PLATFORMS. For single-arch local builds this is just the host arch.
cross-compile-linux:
	@for arch in $(ARCHS); do \
		outdir=$(BIN_DIR)/linux/$$arch; \
		mkdir -p $$outdir; \
		echo ">> cross-compiling for linux/$$arch -> $$outdir"; \
		for bin in $(DOCKER_BINS); do \
			CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $(GO) build $(GOFLAGS_BUILD) \
				-ldflags "$(LDFLAGS)" -o $$outdir/$$bin ./cmd/$$bin/... || exit 1; \
		done; \
	done

# Build a local (host-arch) image and load it into the docker daemon as
# i2gosignals:$(VERSION) + :latest. Single-arch only — multi-arch manifest
# lists cannot be --load'd into the daemon's image store.
build-docker: cross-compile-linux
	$(DOCKER) buildx build \
		--platform linux/$$($(GO) env GOARCH) \
		--build-arg VERSION=$(VERSION) \
		--build-arg VCS_REF=$(VCS_REF) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--tag $(LOCAL_IMAGE):$(VERSION) \
		--tag $(LOCAL_IMAGE):latest \
		--load \
		.
	@echo ">> built $(LOCAL_IMAGE):$(VERSION) and $(LOCAL_IMAGE):latest"

# Build a multi-arch image ($(PLATFORMS)) and push it as a single manifest
# list to $(PUSH_REPO). A multi-arch manifest cannot be loaded into the local
# Docker daemon, so this target pushes directly. Needs a buildx builder with
# the docker-container driver — created on demand if missing.
build-docker-multiarch: cross-compile-linux
	@current_driver=$$($(DOCKER) buildx inspect 2>/dev/null | awk '/^Driver:/ {print $$2}'); \
	if [ "$$current_driver" != "docker-container" ]; then \
		if ! $(DOCKER) buildx inspect $(BUILDX_BUILDER) >/dev/null 2>&1; then \
			echo ">> creating docker-container buildx builder '$(BUILDX_BUILDER)' (one-time)"; \
			$(DOCKER) buildx create --name $(BUILDX_BUILDER) --driver docker-container --bootstrap; \
		fi; \
		$(DOCKER) buildx use $(BUILDX_BUILDER); \
	fi
	$(DOCKER) buildx build \
		--platform $(PLATFORMS) \
		--build-arg VERSION=$(VERSION) \
		--build-arg VCS_REF=$(VCS_REF) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--tag $(PUSH_REPO):$(VERSION) \
		--tag $(PUSH_REPO):latest \
		--provenance=mode=max \
		--sbom=true \
		--metadata-file $(BIN_DIR)/build-meta.json \
		--push \
		.
	@echo ">> pushed $(PUSH_REPO):$(VERSION) and :latest for $(PLATFORMS)"
	@echo ">> manifest metadata at $(BIN_DIR)/build-meta.json"

# Export the image SBOM to a local file. BuildKit's tar exporter writes the
# SBOM as sbom.spdx.json at the archive root; stream the archive and extract
# just that file (no registry push or socket mount required). The result is
# an in-toto attestation envelope wrapping an SPDX 2.3 document.
docker-sbom: cross-compile-linux
	@mkdir -p $(BIN_DIR)
	@set -o pipefail; $(DOCKER) buildx build \
		--platform linux/$$($(GO) env GOARCH) \
		--build-arg VERSION=$(VERSION) \
		--build-arg VCS_REF=$(VCS_REF) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--sbom=true --provenance=false \
		--output type=tar,dest=- . \
		| tar -xO sbom.spdx.json > $(BIN_DIR)/sbom-$(VERSION).json
	@echo ">> wrote $(BIN_DIR)/sbom-$(VERSION).json (in-toto SBOM attestation, SPDX 2.3)"

# Remove build artifacts.
clean: dev-clean
	rm -rf $(BIN_DIR) goSignals goSignalsServer goSsfServer cluster-monitor genTlsKeys healthcheck
	rm -f $(DEV_IMAGE_STAMP)

# --- Dev/debug in Docker with Delve -----------------------------------------
# `dev-build-image` builds the production image as a side-effect of priming
# the buildx cache; the actual dev image (i2gosignals-dev:latest, built from
# Dockerfile-dev) is produced lazily by docker compose on `up`.
dev-build-image: build-docker
	@touch $(DEV_IMAGE_STAMP)

# Stamp tracks the last successful dev image build against its source files.
# If Dockerfile-dev / go.mod / go.sum change, the stamp is older and triggers a rebuild.
$(DEV_IMAGE_STAMP): Dockerfile-dev go.mod go.sum
	$(MAKE) dev-build-image

# Ensure the dev image is present locally and up to date with its sources.
ensure-dev-image: $(DEV_IMAGE_STAMP)
	@if ! $(DOCKER) image inspect $(DEV_IMAGE) >/dev/null 2>&1; then \
		echo ">> $(DEV_IMAGE) is missing; rebuilding..."; \
		$(MAKE) dev-build-image; \
	fi

# Bring up the minimal dev stack with the debug-enabled goSignals1.
dev-up: check-certs ensure-dev-image
	$(DOCKER) compose -f docker-compose-dev.yml up -d

# Rebuild the dev image and restart goSignals1.
dev-rebuild: dev-build-image
	$(DOCKER) compose -f docker-compose-dev.yml up -d --no-deps --build goSignals1 goSignals2 goSsfServer

clean-scim:
	rm -f -v $(SCIM_CONFIG)/*.pem $(SCIM_CONFIG)/*.jwt $(SCIM_CONFIG)/*.env $(SCIM_CONFIG)/config.json $(SCIM_CONFIG)/data1/*.pem $(SCIM_CONFIG)/data2/*.pem $(SCIM_CONFIG)/data1/*.j* $(SCIM_CONFIG)/data2/*.j*

run-spiffe-demo:
	$(MAKE) dev-build-image
	$(DOCKER) compose -f docker-compose-spiffe.yml up -d

dev-reset-spiffe:
	$(DOCKER) compose -f docker-compose-spiffe-dev.yml down -v
	$(MAKE) clean-scim
	$(MAKE) check-certs
	$(DOCKER) compose -f docker-compose-spiffe-dev.yml up -d

# Rebuild the dev image and restart for spiffe.
dev-rebuild-spiffe-goSignals: dev-build-image
	$(DOCKER) compose -f docker-compose-spiffe-dev.yml up -d --no-deps --build goSignals1 goSignals2 goSsfServer

# Stop and remove the dev stack containers.
dev-down:
	$(DOCKER) compose -f docker-compose-dev.yml down

# Tail logs from goSignals1.
dev-logs:
	$(DOCKER) compose -f docker-compose-dev.yml logs -f goSignals1

# Remove dev containers and caches (module/build caches).
dev-clean:
	$(DOCKER) compose -f docker-compose-dev.yml down -v
	$(MAKE) clean-scim

# Start the docker-compose.yml demo cluster.
run: build build-docker
	$(DOCKER) compose -f docker-compose.yml up -d