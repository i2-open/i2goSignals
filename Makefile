# Root Makefile to build admin UI and Go server

# Variables
NPM?=npm
GO?=go
ADMIN_DIR=adminUI
ADMIN_BUILD_DIR=$(ADMIN_DIR)/build
SERVER_DIR=cmd/goSignalsServer
BIN_DIR=bin
SERVER_BIN=$(BIN_DIR)/goSignalsServer

.PHONY: all adminui-install adminui-build server-build build clean \
    dev-build-image dev-up dev-down dev-logs dev-rebuild dev-clean

all: build

# Install JS deps (uses ci if package-lock.json exists)
adminui-install:
	@if [ -f "$(ADMIN_DIR)/package-lock.json" ]; then \
		$(NPM) --prefix $(ADMIN_DIR) ci; \
	else \
		$(NPM) --prefix $(ADMIN_DIR) install; \
	fi

# Build the React admin UI with Vite
adminui-build: adminui-install
	$(NPM) --prefix $(ADMIN_DIR) run build

# Build the Go server. Depends on adminui-build so UI is available at runtime.
server-build: adminui-build
	@mkdir -p $(BIN_DIR)
	$(GO) build -o $(SERVER_BIN) ./$(SERVER_DIR)

# Build everything
build: adminui-build server-build

# Remove build artifacts
clean:
	 rm -rf $(ADMIN_BUILD_DIR) $(SERVER_BIN)

# --- Dev/debug in Docker with Delve ---
# Build the dev image used by docker-compose-dev (installs Delve and mounts source)
dev-build-image:
	 docker build -f Dockerfile-dev -t i2gosignals-dev:latest .

# Bring up the minimal dev stack with the debug-enabled goSignals1
dev-up:
	 docker compose -f docker-compose-dev.yml up -d mongo1 mongo2 mongo3 mongoSetup prometheus grafana goSignals1

# Rebuild the dev image and restart goSignals1
dev-rebuild: dev-build-image
	 docker compose -f docker-compose-dev.yml up -d --no-deps --build goSignals1

# Stop and remove the dev stack containers
dev-down:
	 docker compose -f docker-compose-dev.yml down

# Tail logs from goSignals1
dev-logs:
	 docker compose -f docker-compose-dev.yml logs -f goSignals1

# Remove dev containers and caches (module/build caches)
dev-clean:
	 docker compose -f docker-compose-dev.yml down -v
