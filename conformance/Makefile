# SSF Conformance — end-to-end orchestration
#
# One entry point for the whole loop: obtain & deploy the OpenID conformance
# suite (with the networking fix), build & deploy the goSignals SUT, mint the
# bootstrap token, verify the suite can actually reach the SUT, and run the
# plans. See README.md for the full story.
#
# Quick start:
#   make all          # deploy suite + SUT, verify networking, run the full matrix
#   make ready        # deploy + verify, but do NOT run the matrix (smoke only)
#   make test         # run the full matrix (assumes `make ready` already passed)
#   make refresh-suite# git pull + rebuild the suite jar + redeploy (gets latest)
#   make help         # list every target
#
# Everything is parameterized; override on the command line, e.g.
#   make all SUITE_REPO=/path/to/conformance-suite PLANS_FILTER=transmitter

SHELL := /usr/bin/env bash

# ---- locations / endpoints -------------------------------------------------
SUITE_REPO        ?= $(HOME)/git/openid-conformance-suite
SUITE_PROJECT     ?= openid-conformance-suite
SUITE_URL         ?= https://localhost.emobix.co.uk:8443
SUT_URL           ?= https://localhost.emobix.co.uk:9443
SUT_METADATA      := $(SUT_URL)/.well-known/ssf-configuration

# Compose invocations (the SUT always builds from the working tree so a run can
# never silently test a stale image; see docker-compose-conformance.build.yml).
SUITE_COMPOSE := docker compose -p $(SUITE_PROJECT) --project-directory "$(SUITE_REPO)" \
                 -f "$(SUITE_REPO)/docker-compose-dev.yml" -f suite-overlay.yml
SUT_COMPOSE   := docker compose -f docker-compose-conformance.yml -f docker-compose-conformance.build.yml

# macOS: the suite jar targets Java 21; pick that JDK explicitly for the build.
JAVA21 := $(shell /usr/libexec/java_home -v 21 2>/dev/null)

READY_TRIES ?= 60

.DEFAULT_GOAL := help
.PHONY: help all ready full test \
        suite suite-pull suite-build suite-up suite-down refresh-suite \
        sut sut-down net-check wait-suite wait-sut \
        down clean status

help: ## List targets
	@echo "SSF conformance orchestration — targets:"
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | sort | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "SUITE_REPO=$(SUITE_REPO)"
	@echo "SUITE_URL =$(SUITE_URL)   SUT_URL=$(SUT_URL)"

# ---- top-level flows -------------------------------------------------------
all: ready test ## Deploy suite + SUT, verify networking, then run the full matrix

ready: suite-up sut wait-sut net-check ## Deploy + verify everything is reachable (no tests)
	@echo "==> READY: suite up (networking patched), SUT up, suite can reach SUT."
	@echo "    Run the matrix with:  make test"

full: refresh-suite sut wait-sut net-check test ## Pull+rebuild the suite jar, then deploy & run everything

# ---- the OpenID conformance suite -----------------------------------------
suite: suite-up ## Bring the suite up with the networking overlay (no rebuild)

suite-pull: ## git pull the conformance suite checkout (ff-only)
	@test -d "$(SUITE_REPO)/.git" || { echo "ERROR: $(SUITE_REPO) is not a git checkout"; exit 1; }
	@echo "==> Updating suite checkout: $(SUITE_REPO)"
	git -C "$(SUITE_REPO)" fetch --prune
	git -C "$(SUITE_REPO)" pull --ff-only

suite-build: ## Rebuild the suite fat jar (Java 21, skip tests/pmd)
	@test -n "$(JAVA21)" || { echo "ERROR: Java 21 not found via /usr/libexec/java_home -v 21"; exit 1; }
	@echo "==> Building suite jar with JAVA_HOME=$(JAVA21)"
	cd "$(SUITE_REPO)" && JAVA_HOME="$(JAVA21)" mvn -B -Dmaven.test.skip -Dpmd.skip clean package

suite-up: ## Start the suite in Docker WITH the localhost.emobix.co.uk->host-gateway overlay
	@echo "==> Starting conformance suite (with networking overlay)"
	$(SUITE_COMPOSE) up -d --build
	@$(MAKE) --no-print-directory wait-suite

refresh-suite: suite-pull suite-build suite-up ## Get the latest suite: pull + rebuild jar + redeploy

suite-down: ## Stop the suite
	-$(SUITE_COMPOSE) down

# ---- the goSignals SUT -----------------------------------------------------
sut: ## Build (from working tree) and start the goSignals SUT stack
	@echo "==> Building + starting SUT (i2gosignals:conformance-dev, from working tree)"
	$(SUT_COMPOSE) up -d --build

sut-down: ## Stop the SUT and drop its Mongo volume
	-$(SUT_COMPOSE) down -v

# Note: there is no `token` target. The per-plan scripts (run-plan.sh,
# run-receiver-plan.sh) mint a fresh bearer via bootstrap-token.sh themselves on
# every run — they must, because each plan does `down -v` + a fresh `up`, which
# wipes the previously registered client. To mint one by hand for the suite's web
# UI, run ./bootstrap-token.sh directly.

# ---- gates / readiness -----------------------------------------------------
net-check: ## Verify the suite container can fetch the SUT transmitter metadata
	@./check-suite-reaches-sut.sh

wait-suite: ## Block until the suite answers on :8443
	@echo "==> Waiting for suite at $(SUITE_URL)"
	@for i in $$(seq 1 $(READY_TRIES)); do \
	  code=$$(curl -sk -o /dev/null -w '%{http_code}' --max-time 3 "$(SUITE_URL)/" 2>/dev/null || echo 000); \
	  if [ "$$code" != "000" ]; then echo "    suite ready (HTTP $$code, attempt $$i)"; exit 0; fi; \
	  sleep 2; \
	done; echo "ERROR: suite not ready after $(READY_TRIES) tries" >&2; exit 1

wait-sut: ## Block until the SUT publishes SSF metadata on :9443
	@echo "==> Waiting for SUT at $(SUT_METADATA)"
	@for i in $$(seq 1 $(READY_TRIES)); do \
	  if curl -fsk -o /dev/null --max-time 3 "$(SUT_METADATA)" 2>/dev/null; then echo "    SUT ready (attempt $$i)"; exit 0; fi; \
	  sleep 1; \
	done; echo "ERROR: SUT not ready after $(READY_TRIES) tries" >&2; $(SUT_COMPOSE) logs --tail=60 gosignals >&2; exit 1

# ---- the matrix ------------------------------------------------------------
test: ## Run the full plan matrix (run-all-plans.sh; honors PLANS_FILTER)
	@echo "==> Running conformance matrix (PLANS_FILTER='$(PLANS_FILTER)')"
	PLANS_FILTER='$(PLANS_FILTER)' SUITE_REPO="$(SUITE_REPO)" ./run-all-plans.sh

# ---- teardown / status -----------------------------------------------------
down: sut-down ## Stop the SUT (leaves the suite running)

clean: sut-down suite-down ## Stop SUT + suite

status: ## Show what's running and which SUT image is under test
	@echo "== suite =="; docker ps --filter "name=openid-conformance-suite" --format '  {{.Names}}\t{{.Image}}\t{{.Status}}' || true
	@echo "== SUT =="; docker ps --filter "name=ssfconf-" --format '  {{.Names}}\t{{.Image}}\t{{.Status}}' || true
	@printf "== suite->SUT reachability ==\n"; ./check-suite-reaches-sut.sh || true
