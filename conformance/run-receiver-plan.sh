#!/usr/bin/env bash
#
# Run one OpenID conformance **receiver** plan against a freshly-wiped SUT.
#
# For receiver plans the suite plays the Transmitter and waits for goSignals
# (acting as Receiver) to register a stream and exercise the management API
# against the suite's emulated transmitter at
#   https://localhost.emobix.co.uk:8443/test/a/<alias>/...
# Each module in the plan re-points the alias, so the SUT must repeat the
# create+manage+delete cycle once per module. This script drives that loop in
# parallel with `scripts/run-test-plan.py` and tears the driver down when the
# plan exits.
#
# SUT-side knobs that make the manual recipe sufficient (set in
# gosignals-conformance.env):
#   I2SIG_RCV_MANAGEMENT_EXERCISE=true   GET / PATCH / PUT / POST-status on
#                                        each receiver stream once it is
#                                        established (drives happy-path /
#                                        stream-status-update modules).
#   I2SIG_RCV_VERIFY_ON_ESTABLISH=true   issue /verify automatically after
#                                        registration (drives the
#                                        stream-verification module).
#
# Usage:
#   ./run-receiver-plan.sh "<plan-spec>" [<config-path>]
#
# Example:
#   ./run-receiver-plan.sh "openid-ssf-receiver-test-plan[ssf_delivery_mode=push]"
#
# Env:
#   SUITE_REPO            path to openid-conformance-suite checkout
#                         (default: ~/git/openid-conformance-suite)
#   SUITE_URL             default https://localhost.emobix.co.uk:8443/
#   SUT_READY_URL         default https://localhost.emobix.co.uk:9443/.well-known/ssf-configuration
#   SUT_READY_TRIES       default 30
#   RX_TOKEN              default ssf-conformance-rx-token
#                         (must equal `ssf.transmitter.access_token` in the
#                         receiver suite-config; the SUT presents it to the
#                         suite-emulated transmitter on every call)
#   RX_DRIVER_INTERVAL    seconds between create+delete cycles (default 8).
#                         Too low races the suite's module advancement; too
#                         high stalls a fast plan.
#   RX_DRIVER_WINDOW      seconds to keep driving (default 600)
#   GOSIGNALS_CONTAINER   default ssfconf-gosignals
#   EXTRA_RUNNER_ARGS     pass-through to scripts/run-test-plan.py
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <plan-spec> [<config-path>]" >&2
    exit 2
fi

PLAN_SPEC="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATH="${2:-$SCRIPT_DIR/suite-configs/ssf-receiver-gosignals.json}"

SUITE_REPO="${SUITE_REPO:-$HOME/git/openid-conformance-suite}"
SUITE_URL="${SUITE_URL:-https://localhost.emobix.co.uk:8443/}"
SUT_READY_URL="${SUT_READY_URL:-https://localhost.emobix.co.uk:9443/.well-known/ssf-configuration}"
SUT_READY_TRIES="${SUT_READY_TRIES:-30}"
RX_TOKEN="${RX_TOKEN:-ssf-conformance-rx-token}"
RX_DRIVER_INTERVAL="${RX_DRIVER_INTERVAL:-8}"
RX_DRIVER_WINDOW="${RX_DRIVER_WINDOW:-600}"
GOSIGNALS_CONTAINER="${GOSIGNALS_CONTAINER:-ssfconf-gosignals}"
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

# Receiver plans have variant ssf_delivery_mode=push|poll. Default to push if
# omitted; the suite-config alias is fixed regardless.
DELIVERY_MODE="push"
case "$PLAN_SPEC" in
    *ssf_delivery_mode=poll*) DELIVERY_MODE="poll" ;;
    *ssf_delivery_mode=push*) DELIVERY_MODE="push" ;;
esac

# Mint a unique alias per run. The conformance suite holds an alias in
# INTERRUPTED state for ~3 min after a failed plan and refuses re-use during
# that window, so back-to-back runs against a fixed alias deadlock. We splice a
# fresh alias into the imported config and rewrite the audience URL to match.
BASE_ALIAS="$(grep -E '"alias"' "$CONFIG_PATH" | head -1 | sed -E 's/.*"alias"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')"
if [[ -z "$BASE_ALIAS" ]]; then
    echo "ERROR: failed to read alias from $CONFIG_PATH" >&2
    exit 1
fi
RX_ALIAS="${BASE_ALIAS}-$(date -u +%H%M%S)"
RUNTIME_CONFIG="$SCRIPT_DIR/suite-configs/.${BASE_ALIAS}.runtime.json"
sed -E \
    -e "s|\"alias\"[[:space:]]*:[[:space:]]*\"[^\"]+\"|\"alias\": \"$RX_ALIAS\"|" \
    -e "s|/test/a/$BASE_ALIAS|/test/a/$RX_ALIAS|g" \
    "$CONFIG_PATH" >"$RUNTIME_CONFIG"
CONFIG_PATH="$RUNTIME_CONFIG"
TX_URL="${SUITE_URL%/}/test/a/$RX_ALIAS"
echo "==> Plan alias: $RX_ALIAS"

mkdir -p "$SCRIPT_DIR/results"

echo "==> Wiping SUT state (docker compose down -v)"
docker compose "${COMPOSE_ARGS[@]}" down -v >/dev/null

echo "==> Starting SUT (docker compose up -d)"
docker compose "${COMPOSE_ARGS[@]}" up -d >/dev/null

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

# Bootstrap-token mint still useful for any /trigger-event the suite might need
# downstream; harmless for pure receiver runs (suite never calls our APIs).
echo "==> Minting bearer token"
"$SCRIPT_DIR/bootstrap-token.sh" >/dev/null || true

DRIVER_LOG="$SCRIPT_DIR/results/rx-driver-$(date -u +%Y%m%dT%H%M%SZ).log"
DRIVER_PID=""
cleanup_driver() {
    if [[ -n "$DRIVER_PID" ]] && kill -0 "$DRIVER_PID" 2>/dev/null; then
        kill "$DRIVER_PID" 2>/dev/null || true
        wait "$DRIVER_PID" 2>/dev/null || true
    fi
}
trap cleanup_driver EXIT INT TERM

driver_loop() {
    local cycle=0
    local deadline=$(( SECONDS + RX_DRIVER_WINDOW ))
    # Use the CLI's default config dir at /home/nonroot/.goSignals/ — distroless
    # has no shell to (re)create a custom dir owned by nonroot, and that path is
    # already writable by the runtime user.
    local exec_args=(exec -i "$GOSIGNALS_CONTAINER" /app/goSignals)

    echo "[$(date +%H:%M:%S)] driver started (alias=$RX_ALIAS, mode=$DELIVERY_MODE)" >>"$DRIVER_LOG"

    # Wait for the suite to start the first module so the alias points at a
    # live test. The suite gates the per-module ssf-configuration on RUNNING
    # state; before then it returns "Illegal test state change" JSON which the
    # CLI happily parses into an empty config. Poll until we see a real
    # issuer in the response.
    local discovery_url="${TX_URL%/}/.well-known/ssf-configuration"
    local discovery_ok=0
    for ((j=0; j<60; j++)); do
        if curl -fsk "$discovery_url" 2>/dev/null | grep -q '"issuer"[[:space:]]*:[[:space:]]*"http'; then
            discovery_ok=1
            break
        fi
        sleep 2
    done
    if (( discovery_ok == 0 )); then
        echo "[$(date +%H:%M:%S)] giving up: suite never returned a live ssf-configuration" >>"$DRIVER_LOG"
        return
    fi
    echo "[$(date +%H:%M:%S)] suite ssf-configuration live; adding server" >>"$DRIVER_LOG"

    # `add server` is one-shot — alias-already-exists errors out. Try it once;
    # if the alias is already present from a prior run inside the same
    # container, proceed with the create/delete cycle anyway.
    docker "${exec_args[@]}" add server suite "$TX_URL" --token="$RX_TOKEN" \
        >>"$DRIVER_LOG" 2>&1 || \
        echo "[$(date +%H:%M:%S)] add server returned non-zero (alias may already exist)" >>"$DRIVER_LOG"

    while (( SECONDS < deadline )); do
        cycle=$(( cycle + 1 ))
        local alias="rx${cycle}"
        echo "[$(date +%H:%M:%S)] cycle=$cycle create stream ($DELIVERY_MODE)" >>"$DRIVER_LOG"
        # Create. Pipe Y to satisfy ConfirmProceed.
        if printf 'Y\n' | docker "${exec_args[@]}" \
                create stream "$DELIVERY_MODE" receive suite \
                --name="$alias" --events='*' >>"$DRIVER_LOG" 2>&1; then
            sleep "$RX_DRIVER_INTERVAL"
            echo "[$(date +%H:%M:%S)] cycle=$cycle delete stream" >>"$DRIVER_LOG"
            docker "${exec_args[@]}" delete stream "$alias" \
                >>"$DRIVER_LOG" 2>&1 || true
        else
            echo "[$(date +%H:%M:%S)] cycle=$cycle create FAILED (suite may be between modules)" >>"$DRIVER_LOG"
            sleep 2
        fi
    done
    echo "[$(date +%H:%M:%S)] driver window elapsed" >>"$DRIVER_LOG"
}

echo "==> Starting receiver driver (mode=$DELIVERY_MODE, log=$DRIVER_LOG)"
driver_loop &
DRIVER_PID=$!

echo "==> Running plan: $PLAN_SPEC"
cd "$SUITE_REPO"
CONFORMANCE_DEV_MODE=1 \
    CONFORMANCE_SERVER="$SUITE_URL" \
    .venv/bin/python3 scripts/run-test-plan.py \
    --export-dir "$SCRIPT_DIR/results" \
    $EXTRA_RUNNER_ARGS \
    "$PLAN_SPEC" \
    "$CONFIG_PATH"

echo "==> Done: $PLAN_SPEC (driver log: $DRIVER_LOG)"
