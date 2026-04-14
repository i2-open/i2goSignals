# Root Makefile to build Go server

# Variables
GO?=go

CONSOLE_DIR=cmd/goSignals
SERVER_DIR=cmd/goSignalsServer
CONFIG_DIR=config
SCIM_CONFIG=$(CONFIG_DIR)/scim
BIN_DIR=bin
SERVER_BIN=$(BIN_DIR)/goSignalsServer

.PHONY: all build run console-build server-build docker-build build clean clean-scim dev-clean generate-certs check-certs \
	dev-build-image dev-up dev-down dev-logs dev-rebuild run-spiffe-demo \
	dev-reset-spiffe dev-rebuild-spiffe-goSignals

all: build

# Build and install the command line console gosignals
console-build:
	$(GO) build ./$(CONSOLE_DIR)
	$(GO) install ./$(CONSOLE_DIR)

# Build the Go server.
server-build:
	@mkdir -p $(BIN_DIR)
	$(GO) build -o $(SERVER_BIN) ./$(SERVER_DIR)

docker-build:
	sh ./build.sh -n latest

# Build everything
build: check-certs console-build server-build docker-build

# Check if certificates exist
check-certs:
	@if [ ! -f config/certs/ca-cert.pem ]; then $(MAKE) generate-certs; fi

# Generate TLS certificates
generate-certs:
	$(GO) run ./cmd/genTlsKeys

# Remove build artifacts
clean: dev-clean
	rm -rf $(BIN_DIR) goSignals goSignalsServer goSsfServer cluster-monitor genTlsKeys healthcheck
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

clean-scim:
	rm -f -v $(SCIM_CONFIG)/*.pem $(SCIM_CONFIG)/*.jwt $(SCIM_CONFIG)/*.env $(SCIM_CONFIG)/config.json $(SCIM_CONFIG)/data1/*.pem $(SCIM_CONFIG)/data2/*.pem $(SCIM_CONFIG)/data1/*.j* $(SCIM_CONFIG)/data2/*.j*

run-spiffe-demo:
	$(MAKE) dev-build-image
	docker compose -f docker-compose-spiffe.yml up -d

dev-reset-spiffe:
	docker compose -f docker-compose-spiffe-dev.yml down -v
	$(MAKE) clean-scim
	$(MAKE) check-certs
	docker compose -f docker-compose-spiffe-dev.yml up -d

# Rebuild the dev image and restart for spiffe
dev-rebuild-spiffe-goSignals: dev-build-image
	docker compose -f docker-compose-spiffe-dev.yml up -d --no-deps --build goSignals1 goSignals2 goSsfServer

# Stop and remove the dev stack containers
dev-down:
	docker compose -f docker-compose-dev.yml down

# Tail logs from goSignals1
dev-logs:
	docker compose -f docker-compose-dev.yml logs -f goSignals1

# Remove dev containers and caches (module/build caches)
dev-clean:
	docker compose -f docker-compose-dev.yml down -v
	$(MAKE) clean-scim

# Start the docker-compose.yml demo cluster
run:
	$(MAKE) build
	docker compose -f docker-compose.yml up -d