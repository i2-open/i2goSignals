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

# --- Quality gate knobs -----------------------------------------------------
GOFMT ?= gofmt

# The benchmark set that forms the project's performance floor. These four
# packages carry the hot paths a toolchain or dependency change is most likely
# to move: SET marshal/parse/sign, event-payload validation, RFC8936 poll
# request/response encoding, and the long-poll buffer's wait/wake cycle.
# docs/perf/go127-baseline.md records their numbers and every subsequent
# change appends a delta row against them. Keep this list and
# docs/perf/go127-baseline.md in step.
BENCH_PKGS ?= ./pkg/goSet ./pkg/goSetValidate ./pkg/goSetPoll ./internal/eventRouter/buffer

# `make qa` only needs to prove the benchmarks still compile and run, so one
# iteration each is enough and keeps the gate fast. Real measurements use a
# statistically meaningful benchtime -- see docs/perf/go127-baseline.md for
# the command that produced the recorded numbers.
BENCHTIME ?= 1x

# Packages run under Go 1.27's goroutine-leak profile by `make leak-check`.
# These are the ones that own a timer path -- lease heartbeats and push
# recovery (internal/eventRouter), the long-poll wait (its buffer package),
# the SSTP dialer's heartbeat and resume timers (internal/server), and the
# poll/push protocol packages that sit on top of them. A regression that
# abandons a goroutine on a timer channel nobody will ever send to shows up
# here and nowhere else in the gate.
LEAK_PKGS ?= ./pkg/goSetPoll/... ./pkg/goSetPush/... ./internal/eventRouter/... ./internal/server

.PHONY: all help build run console-build server-build clean clean-scim dev-clean \
    generate-certs check-certs licenses-check \
    build-docker build-docker-multiarch docker-sbom cross-compile-linux \
    dev-build-image dev-up dev-down dev-logs dev-rebuild ensure-dev-image \
    run-spiffe-demo dev-reset-spiffe dev-rebuild-spiffe-goSignals \
    seams qa fmt-check vet test tidy-check bench leak-check

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
	@echo "  build-docker-multiarch - multi-arch ($(PLATFORMS)) validate-only build; add PUSH=1 to publish $(PUSH_REPO):$(VERSION) + :latest"
	@echo "  docker-sbom        - export the image SBOM to bin/sbom-$(VERSION).json"
	@echo "  cross-compile-linux - cross-compile $(DOCKER_BINS) into bin/linux/<arch>/"
	@echo "  dev-up / dev-down / dev-logs / dev-rebuild - dev compose stack with Delve"
	@echo "  clean              - remove build artifacts"
	@echo "  qa                 - full quality gate: fmt-check vet tidy-check test leak-check bench"
	@echo "  fmt-check          - fail if any Go file is not gofmt-clean"
	@echo "  vet                - go vet ./..."
	@echo "  test               - go test -race ./..."
	@echo "  tidy-check         - fail if go mod tidy would change go.mod/go.sum"
	@echo "  bench              - run the benchmark set (BENCHTIME=$(BENCHTIME))"

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
#
# NOT ENABLED — image-payload stripping, recorded here for a later release.
# Debug information is deliberately retained for the current release.
#
# Appending the linker flags `-s` (disable symbol table) and `-w` (disable DWARF
# generation) to the link step below strips debug metadata from the six staged
# binaries. Measured on linux/arm64 at v0.12.0-alpha.16:
#
#     goSignalsServer   37.5MB -> 29.3MB  (-22%)
#     goSsfServer       37.5MB -> 29.3MB  (-22%)
#     goSignals         22.4MB -> 15.7MB  (-30%)
#     cluster-monitor   20.6MB -> 14.3MB  (-31%)
#     healthcheck        7.6MB ->  5.3MB  (-31%)
#     genTlsKeys         6.0MB ->  4.1MB  (-32%)
#     ------------------------------------------
#     image payload      131MiB ->  98MiB (-25%)
#
# Verified to have no effect on: panic tracebacks (Go resolves those from the
# pclntab, not DWARF, so function/file/line survive stripping), embedded build
# info (`go version -m` still reports all 29 deps, so buildx `--sbom=true` and
# the provenance attestation are unaffected), and the -X version injection in
# LDFLAGS. The one real loss is source-level debugging (Delve/gdb) against a
# binary pulled out of the image — which is why this stays off for now.
#
# Scoped to this target only. console-build / server-build keep full debug info
# regardless, and Dockerfile-dev is unaffected either way: it builds from source
# under `dlv debug` and never reads LDFLAGS.
#
# To enable, uncomment and append $(STRIP_LDFLAGS) to -ldflags in the recipe:
# STRIP_LDFLAGS := -s -w
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

# Build a multi-arch image ($(PLATFORMS)) as a single manifest list. A multi-arch
# manifest cannot be loaded into the local Docker daemon, so by default this
# target just validates the build (layers stay in the buildx cache). Set PUSH=1
# to publish to $(PUSH_REPO) with both :$(VERSION) and :latest tags. Needs a
# buildx builder with the docker-container driver — created on demand if missing.
#
#   make build-docker-multiarch                # build only, no push
#   make build-docker-multiarch PUSH=1         # build + push to $(PUSH_REPO)
#   make build-docker-multiarch PUSH=1 PUSH_REPO=ghcr.io/i2-open/i2gosignals
ifdef PUSH
DOCKER_MULTIARCH_OUTPUT := --push --tag $(PUSH_REPO):$(VERSION) --tag $(PUSH_REPO):latest --metadata-file $(BIN_DIR)/build-meta.json
DOCKER_MULTIARCH_BANNER := pushed $(PUSH_REPO):$(VERSION) and :latest for $(PLATFORMS) (metadata at $(BIN_DIR)/build-meta.json)
else
DOCKER_MULTIARCH_OUTPUT :=
DOCKER_MULTIARCH_BANNER := built $(PLATFORMS) into the buildx cache (no push; set PUSH=1 to publish to $(PUSH_REPO))
endif

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
		--provenance=mode=max \
		--sbom=true \
		$(DOCKER_MULTIARCH_OUTPUT) \
		.
	@echo ">> $(DOCKER_MULTIARCH_BANNER)"

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

# Cross-repo seam self-check (family "make seams" contract).
# community is a dependency ROOT (no Go sibling modules depend UP into it), so
# the wide workspace degenerates to `use .`: we spin up an EPHEMERAL go.work,
# compile + vet the whole module through it, then delete it. go.work is never
# committed — the git-tag pin stays the single source of truth (ADR 0048).
# `go build ./...` and `go vet ./...` are both hard gates: a broken seam fails
# the compile, and vet must be clean. (The formerly-documented generated-code
# diagnostics — duplicate JSON tags in pkg/ssfModels / pkg/goScim, unkeyed bson.E
# in cmd/cluster-monitor — have been fixed on the release branch.)
seams:
	@echo ">> make seams: ephemeral wide go.work self-check (community = dependency root)"
	@rm -f go.work go.work.sum
	@trap 'rm -f go.work go.work.sum' EXIT INT TERM; \
	  $(GO) work init && \
	  $(GO) work use . && \
	  echo ">> go build ./..." && $(GO) build ./... && \
	  echo ">> go vet ./..." && $(GO) vet ./... && \
	  echo ">> make seams: OK (wide-workspace build + vet green)"

# --- Quality gate -----------------------------------------------------------
# `make qa` is THE gate: one command that has to be green before a branch is
# proposed for merge. It exists so there is a single place to hang a check --
# CI, a pre-merge review, and an agent finishing a slice all run the same thing
# rather than each remembering its own list of commands.
#
# Ordering is cheapest-first so an obvious failure reports in seconds rather
# than after the race-detector suite: formatting, then vet, then the go.mod
# tidiness diff, then tests, then the goroutine-leak profile, then the
# benchmark set.
qa: fmt-check vet tidy-check test leak-check bench
	@echo ">> make qa: OK"

# Go sources here are gofmt-canonical tabs. Any output from `gofmt -l` is a
# failure -- gofmt -l reports the files it WOULD change and exits 0 either way,
# so the target has to inspect the output rather than the exit status.
fmt-check:
	@echo ">> gofmt -l ."
	@unformatted="$$($(GOFMT) -l .)"; \
	  if [ -n "$$unformatted" ]; then \
	    echo "ERROR: these files are not gofmt-clean; run 'gofmt -w' on them:"; \
	    echo "$$unformatted"; \
	    exit 1; \
	  fi

vet:
	@echo ">> go vet ./..."
	@$(GO) vet ./...

test:
	@echo ">> go test -race ./..."
	@$(GO) test -race ./...

# Fail if `go mod tidy` would change anything. Tidiness is checked rather than
# applied: the gate must not silently rewrite dependency state underneath the
# caller. go.mod/go.sum are backed up, tidy runs, the result is diffed, and the
# trap restores the originals on every exit path including a failed diff.
tidy-check:
	@echo ">> go mod tidy (diff check)"
	@cp go.mod go.mod.qa-backup && cp go.sum go.sum.qa-backup
	@trap 'mv -f go.mod.qa-backup go.mod; mv -f go.sum.qa-backup go.sum' EXIT INT TERM; \
	  $(GO) mod tidy && \
	  if ! diff -u go.mod.qa-backup go.mod || ! diff -u go.sum.qa-backup go.sum; then \
	    echo "ERROR: go.mod/go.sum are not tidy; run 'go mod tidy' and commit the result."; \
	    exit 1; \
	  fi

# Go 1.27 GA'd goroutine leak detection as a runtime/pprof profile named
# "goroutineleak": writing it runs a GC cycle with leak detection on and reports
# the goroutines the runtime has PROVED can never become runnable again. It is
# not the old count-before-and-after heuristic, so there is no tolerance to tune
# and a slow-but-finishing goroutine is never reported.
#
# pkg/goroutineleak turns that profile into a TestMain hook. The hook is inert
# unless I2SIG_GOROUTINE_LEAK_CHECK is set, which is what keeps `go test ./...`
# unchanged in the edit/test loop and makes this target the thing that enforces
# it. -count=1 is required: a cached PASS would skip the profile entirely.
#
# A failure prints each leaked goroutine's stack, which names the code that
# started it -- not the test that stranded it. See docs/perf/go127-baseline.md
# for how to narrow that down.
leak-check:
	@echo ">> goroutine leak profile: $(LEAK_PKGS)"
	@I2SIG_GOROUTINE_LEAK_CHECK=1 $(GO) test -count=1 $(LEAK_PKGS)

# Run the benchmark set. -run='^$$' selects no ordinary tests, so this measures
# only the benchmarks. Override BENCHTIME for a real measurement run.
bench:
	@echo ">> benchmark set ($(BENCHTIME)): $(BENCH_PKGS)"
	@$(GO) test -run='^$$' -bench=. -benchmem -benchtime=$(BENCHTIME) $(BENCH_PKGS)
