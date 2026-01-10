# Root Makefile to build admin UI and Go server

# Variables
NPM?=npm
GO?=go

CONSOLE_DIR=cmd/goSignals
SERVER_DIR=cmd/goSignalsServer
CONFIG_DIR=config
SCIM_CONFIG=$(CONFIG_DIR)/scim
BIN_DIR=bin
SERVER_BIN=$(BIN_DIR)/goSignalsServer

.PHONY: all console-build server-build build clean \
    dev-build-image dev-up dev-down dev-logs dev-rebuild dev-clean

all: build

# Build and install the command line console gosignals
console-build:
	$(GO) build ./$(CONSOLE_DIR)
	$(GO) install ./$(CONSOLE_DIR)

# Build the Go server.
server-build:
	@mkdir -p $(BIN_DIR)
	$(GO) build -o $(SERVER_BIN) ./$(SERVER_DIR)

# Build everything
build: console-build server-build

# Remove build artifacts
clean: dev-clean
	 rm -rf $(ADMIN_BUILD_DIR) $(SERVER_BIN)
	 # rm -f $(SCIM_CONFIG)/iat*.txt $(SCIM_CONFIG)/registration-iat.env $(SCIM_CONFIG)/scim_cluster.env $(SCIM_CONFIG)/cluster-scim-issuer.pem

# --- Dev/debug in Docker with Delve ---
# Build the dev image used by docker-compose-dev (installs Delve and mounts source)
dev-build-image:
	 docker build -f Dockerfile-dev -t i2gosignals-dev:latest .

# Bring up the minimal dev stack with the debug-enabled goSignals1
dev-up:
	 docker compose -f docker-compose-dev.yml up -d mongo1 mongo2 mongo3 mongoSetup prometheus grafana goSignals1

# Rebuild the dev image and restart goSignals1
dev-rebuild: dev-build-image
	 docker compose -f docker-compose-dev.yml up -d --no-deps --build goSignals1 goSignals2

# Stop and remove the dev stack containers
dev-down:
	 docker compose -f docker-compose-dev.yml down

# Tail logs from goSignals1
dev-logs:
	 docker compose -f docker-compose-dev.yml logs -f goSignals1

# Remove dev containers and caches (module/build caches)
dev-clean:
	 docker compose -f docker-compose-dev.yml down -v
	 find $(SCIM_CONFIG) -maxdepth 1 -type f -delete
