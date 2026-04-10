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

.PHONY: all console-build server-build build clean generate-certs \
    dev-build-image dev-up dev-down dev-logs dev-rebuild dev-clean dbclean check-certs

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
build: check-certs console-build server-build

# Check if certificates exist
check-certs:
	@if [ ! -f config/certs/ca-cert.pem ]; then $(MAKE) generate-certs; fi

# Generate TLS certificates
generate-certs:
	$(GO) run ./cmd/genTlsKeys

# Remove build artifacts
clean: dev-clean
	 rm -rf $(ADMIN_BUILD_DIR) $(SERVER_BIN)
	 # rm -f $(SCIM_CONFIG)/iat*.txt $(SCIM_CONFIG)/registration-iat.env $(SCIM_CONFIG)/scim_cluster.env $(SCIM_CONFIG)/cluster-scim-issuer.pem

# --- Dev/debug in Docker with Delve ---
# Build the dev image used by docker-compose-dev (installs Delve and mounts source)
dev-build-image:
	 sh build.sh -n latest

# Bring up the minimal dev stack with the debug-enabled goSignals1
dev-up: check-certs
	 docker compose -f docker-compose-dev.yml up -d mongo1 mongo2 mongo3 mongo-init prometheus grafana keycloak goSignals1 goSignals2 goSsfServer

# Rebuild the dev image and restart goSignals1
dev-rebuild: dev-build-image
	 docker compose -f docker-compose-dev.yml up -d --no-deps --build goSignals1 goSignals2 goSsfServer

dev-reset-spiffe:
	docker compose -f docker-compose-spiffe-dev.yml down -v
	rm $(SCIM_CONFIG)/*.pem $(SCIM_CONFIG)/*.txt $(SCIM_CONFIG)/config.json $(SCIM_CONFIG)/data1/*.pem $(SCIM_CONFIG)/data2/*.pem
	docker compose -f docker-compose-spiffe-dev.yml up -d

# Rebuild the dev image and restart for spiffe
dev-rebuild-spiffe-goSignals: dev-build-image
	 docker compose -f docker-compose-spiffe-dev.yml up -d --no-deps --build goSignals1 goSignals2 goSsfServer

# Stop and remove the dev stack containers
dev-down:
	 docker compose -f docker-compose-dev.yml down

# Reset the mongo cluster database
dbclean:
	 # Database now in Docker volumes, use 'make dev-clean' instead

# Tail logs from goSignals1
dev-logs:
	 docker compose -f docker-compose-dev.yml logs -f goSignals1

# Remove dev containers and caches (module/build caches)
dev-clean:
	 docker compose -f docker-compose-dev.yml down -v
	 $(MAKE) dbclean
	 find $(SCIM_CONFIG) -maxdepth 1 -type f -delete
