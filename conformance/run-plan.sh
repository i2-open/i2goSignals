#!/usr/bin/env bash
#
# Run one OpenID conformance plan against a freshly-wiped SUT.
#
# Background: the SUT (goSignalsServer) persists streams in MongoDB. The
# OpenID conformance plans are not hermetic — each plan/module creates
# streams in the SUT and not all modules delete what they created. If a
# zombie stream from a prior plan remains "enabled", goSignals' T3 idle
# keepalive (default 5 min) will eventually push a verification SET to
# the suite's *push endpoint*, which is shared across every plan run
# against the same alias. That zombie push:
#   - carries no Authorization header (the earlier plan didn't set one)
#   - is attributed by the suite to whichever test instance happens to be
#     active at that moment
# which silently fails the current plan's auth-header check
# (OIDSSFEnsureAuthorizationHeaderIsPresentInPushRequest). See
# results/run-2026-06-17.md F1 for the diagnostic trail.
#
# Fix: bracket every plan run with `down -v` + `up -d`. The Mongo volume
# is dropped so no streams (zombie or otherwise) survive across plans;
# every plan starts from a known-clean SUT.
#
# Usage:
#   ./run-plan.sh "<plan-spec>" [<config-path>]
#
# Example:
#   ./run-plan.sh "openid-ssf-transmitter-test-plan[ssf_delivery_mode=push][ssf_server_metadata=discovery][ssf_auth_mode=static]"
#
# Env:
#   SUITE_REPO       path to openid-conformance-suite checkout
#                    (default: ~/git/openid-conformance-suite)
#   SUITE_URL        default https://localhost.emobix.co.uk:8443/
#   SUT_READY_URL    default https://localhost.emobix.co.uk:9443/.well-known/ssf-configuration
#   SUT_READY_TRIES  default 30 (each try sleeps 1s)
#   GOSIGNALS_TOKEN  pass through to bootstrap-token.sh
#   EXTRA_RUNNER_ARGS extra args passed through to scripts/run-test-plan.py
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <plan-spec> [<config-path>]" >&2
    exit 2
fi

PLAN_SPEC="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATH="${2:-$SCRIPT_DIR/suite-configs/ssf-transmitter-gosignals.local.json}"

SUITE_REPO="${SUITE_REPO:-$HOME/git/openid-conformance-suite}"
SUITE_URL="${SUITE_URL:-https://localhost.emobix.co.uk:8443/}"
SUT_READY_URL="${SUT_READY_URL:-https://localhost.emobix.co.uk:9443/.well-known/ssf-configuration}"
SUT_READY_TRIES="${SUT_READY_TRIES:-30}"
EXTRA_RUNNER_ARGS="${EXTRA_RUNNER_ARGS:-}"

COMPOSE_ARGS=(
    -f "$SCRIPT_DIR/docker-compose-conformance.yml"
    -f "$SCRIPT_DIR/docker-compose-conformance.build.yml"
)

if [[ ! -d "$SUITE_REPO" ]]; then
    echo "ERROR: SUITE_REPO not found at $SUITE_REPO" >&2
    exit 1
fi
if [[ ! -x "$SUITE_REPO/.venv/bin/python3" ]]; then
    echo "ERROR: $SUITE_REPO/.venv/bin/python3 not found; create the venv and install scripts/requirements.txt" >&2
    exit 1
fi

mkdir -p "$SCRIPT_DIR/results"

echo "==> Wiping SUT state (docker compose down -v)"
docker compose "${COMPOSE_ARGS[@]}" down -v >/dev/null

echo "==> Starting SUT (docker compose up -d --build)"
# --build forces a rebuild of the gosignals image from the current working tree
# every run (the build override pins :conformance-dev). Without this, a stale
# image silently fails to pick up branch fixes. See feedback_verify_deploy_image.md.
docker compose "${COMPOSE_ARGS[@]}" up -d --build >/dev/null

echo "==> Waiting for SUT to publish SSF metadata at $SUT_READY_URL"
for ((i = 1; i <= SUT_READY_TRIES; i++)); do
    if curl -fsk "$SUT_READY_URL" >/dev/null 2>&1; then
        echo "    SUT ready (attempt $i)"
        break
    fi
    if [[ $i -eq $SUT_READY_TRIES ]]; then
        echo "ERROR: SUT did not become ready within $SUT_READY_TRIES s" >&2
        docker compose "${COMPOSE_ARGS[@]}" logs --tail=80 gosignals >&2 || true
        exit 1
    fi
    sleep 1
done

echo "==> Preflight: can the conformance suite reach this SUT?"
# Guards against the silent networking break that makes every transmitter
# module interrupt at OIDSSFGetDynamicTransmitterConfiguration. See
# check-suite-reaches-sut.sh and README.md "Networking".
"$SCRIPT_DIR/check-suite-reaches-sut.sh"

echo "==> Minting bearer token and templating suite config"
"$SCRIPT_DIR/bootstrap-token.sh" >/dev/null

TRIGGER_PID=""
cleanup_trigger() {
    if [[ -n "$TRIGGER_PID" ]] && kill -0 "$TRIGGER_PID" 2>/dev/null; then
        kill "$TRIGGER_PID" 2>/dev/null || true
        wait "$TRIGGER_PID" 2>/dev/null || true
    fi
}
trap cleanup_trigger EXIT INT TERM

# Per-run TAP file — receives a live tee of the suite runner's stdout/stderr.
# trigger-caep.sh tails this to gate firing on the "Running test module:
# ...stream-caep-interop" signal — without it, the trigger would fire CAEP
# events into whichever earlier CAEP-subscribed module currently held the
# newest stream (e.g. verification-error-push-no-auth), polluting that
# module's "next push is the verification SET" assertion.
RUNNER_TAP="$SCRIPT_DIR/results/runner-tap-tx-$(date -u +%Y%m%dT%H%M%SZ).log"
: >"$RUNNER_TAP"

if [[ "$PLAN_SPEC" == *caep* ]]; then
    echo "==> CAEP plan detected — launching trigger-caep.sh in background"
    TRIGGER_TAP_FILE="$RUNNER_TAP" \
        TRIGGER_LOG="$SCRIPT_DIR/results/trigger-caep-$(date -u +%Y%m%dT%H%M%SZ).log" \
        "$SCRIPT_DIR/trigger-caep.sh" &
    TRIGGER_PID=$!
fi

echo "==> Running plan: $PLAN_SPEC (runner tap: $RUNNER_TAP)"
cd "$SUITE_REPO"
CONFORMANCE_DEV_MODE=1 \
    CONFORMANCE_SERVER="$SUITE_URL" \
    .venv/bin/python3 scripts/run-test-plan.py \
    --export-dir "$SCRIPT_DIR/results" \
    $EXTRA_RUNNER_ARGS \
    "$PLAN_SPEC" \
    "$CONFIG_PATH" 2>&1 | tee "$RUNNER_TAP"

echo "==> Done: $PLAN_SPEC (runner tap: $RUNNER_TAP)"
