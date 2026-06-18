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
RX_DRIVER_WINDOW="${RX_DRIVER_WINDOW:-1800}"
# Delay between the driver's CREATE and DELETE for a single module. The module
# stays in WAITING until it has observed every expected receiver action; for
# most modules that's CREATE + (SUT-side GET/PATCH/PUT/POST/verify driven by
# I2SIG_RCV_MANAGEMENT_EXERCISE / I2SIG_RCV_VERIFY_ON_ESTABLISH) + DELETE. The
# DELETE must come from us, otherwise the module never reaches isFinished().
# This delay lets the SUT auto-exercise complete before we tear down. The
# stream-supported-events module takes longer (suite generates a SET per
# supported event and waits for ACKs).
RX_MODULE_HOLD="${RX_MODULE_HOLD:-30}"
RX_MODULE_HOLD_EVENTS="${RX_MODULE_HOLD_EVENTS:-90}"
# Per-module guard: max seconds we wait for a terminal state after deleting,
# before giving up and moving on (suite's own wait_for_state timeout is ~240s).
RX_MODULE_GUARD="${RX_MODULE_GUARD:-60}"
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

# Mint a stream+event-scoped bearer the CLI presents to the SUT itself when it
# registers the local-side half of the connection (see `add server local` below).
# bootstrap-token.sh prints the token on the line after "Access token:".
echo "==> Minting bearer token"
BOOTSTRAP_OUT="$("$SCRIPT_DIR/bootstrap-token.sh" 2>&1)"
echo "$BOOTSTRAP_OUT" >/dev/null
RX_LOCAL_TOKEN="$(printf '%s\n' "$BOOTSTRAP_OUT" | awk '/^>> Access token:/{getline; print; exit}')"
if [[ -z "$RX_LOCAL_TOKEN" ]]; then
    echo "ERROR: failed to parse access token from bootstrap-token.sh output" >&2
    printf '%s\n' "$BOOTSTRAP_OUT" >&2
    exit 1
fi

# SUT base URL the CLI uses to register the local-side server (extra_hosts in
# docker-compose-conformance.yml maps localhost.emobix.co.uk -> host-gateway so
# the in-container CLI can reach the SUT's own published port).
SUT_BASE_URL="${SUT_READY_URL%/.well-known/ssf-configuration}"

DRIVER_LOG="$SCRIPT_DIR/results/rx-driver-$(date -u +%Y%m%dT%H%M%SZ).log"
RUNNER_TAP="$SCRIPT_DIR/results/runner-tap-$(date -u +%Y%m%dT%H%M%SZ).log"
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
    # SSF §7.2 / RFC 8615 (issue #187): the well-known component is INSERTED
    # between the suite host and the per-alias path, never appended. TX_URL is
    # ${SUITE_URL%/}/test/a/$RX_ALIAS, so split off the host (scheme://authority)
    # and splice /.well-known/ssf-configuration before the /test/a/<alias> path.
    # Append-style (.../test/a/<alias>/.well-known/ssf-configuration) falls
    # through the suite's handleHttp default and throws TestFailureException,
    # poisoning every module.
    local tx_host="${SUITE_URL%/}"
    local tx_path="${TX_URL#"$tx_host"}"
    local discovery_url="${tx_host}/.well-known/ssf-configuration${tx_path%/}"
    local discovery_ok=0
    local discovery_body=""
    for ((j=0; j<60; j++)); do
        discovery_body="$(curl -fsk "$discovery_url" 2>/dev/null || true)"
        if printf '%s' "$discovery_body" | grep -q '"issuer"[[:space:]]*:[[:space:]]*"http'; then
            discovery_ok=1
            break
        fi
        sleep 2
    done
    if (( discovery_ok == 0 )); then
        echo "[$(date +%H:%M:%S)] giving up: suite never returned a live ssf-configuration" >>"$DRIVER_LOG"
        return
    fi
    # Extract suite-side iss + jwks_uri for the connection command (required by
    # CreatePush/PollConnectionCmd when neither half pre-exists).
    local suite_iss suite_jwks
    suite_iss="$(printf '%s' "$discovery_body" | jq -r '.issuer // empty')"
    suite_jwks="$(printf '%s' "$discovery_body" | jq -r '.jwks_uri // empty')"
    if [[ -z "$suite_iss" || -z "$suite_jwks" ]]; then
        echo "[$(date +%H:%M:%S)] giving up: suite ssf-configuration missing issuer or jwks_uri" >>"$DRIVER_LOG"
        return
    fi
    # Explicit events list. The suite does NOT advertise events_supported in
    # its ssf-configuration (and goSignals' '*' expansion needs a connecting
    # config it can pull EventsDelivered from — the poll-connection publisher
    # half has no such source and would marshal events_requested:null, which
    # crashes the suite's gson cast). The list below is the union of SSF +
    # CAEP + RISC standard event URIs from the suite's SsfEvents constants;
    # caep-interop plans only need a subset of these to be present.
    local suite_events="https://schemas.openid.net/secevent/ssf/event-type/verification"
    suite_events+=",https://schemas.openid.net/secevent/ssf/event-type/stream-updated"
    suite_events+=",https://schemas.openid.net/secevent/caep/event-type/session-revoked"
    suite_events+=",https://schemas.openid.net/secevent/caep/event-type/token-claims-change"
    suite_events+=",https://schemas.openid.net/secevent/caep/event-type/credential-change"
    suite_events+=",https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"
    suite_events+=",https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"
    suite_events+=",https://schemas.openid.net/secevent/caep/event-type/session-established"
    suite_events+=",https://schemas.openid.net/secevent/caep/event-type/session-presented"
    suite_events+=",https://schemas.openid.net/secevent/caep/event-type/risk-level-change"
    suite_events+=",https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required"
    suite_events+=",https://schemas.openid.net/secevent/risc/event-type/account-disabled"
    suite_events+=",https://schemas.openid.net/secevent/risc/event-type/account-enabled"
    suite_events+=",https://schemas.openid.net/secevent/risc/event-type/account-purged"
    suite_events+=",https://schemas.openid.net/secevent/risc/event-type/credential-compromise"
    suite_events+=",https://schemas.openid.net/secevent/risc/event-type/identifier-changed"
    suite_events+=",https://schemas.openid.net/secevent/risc/event-type/identifier-recycled"
    suite_events+=",https://schemas.openid.net/secevent/risc/event-type/opt-in"
    suite_events+=",https://schemas.openid.net/secevent/risc/event-type/opt-out-cancelled"
    suite_events+=",https://schemas.openid.net/secevent/risc/event-type/opt-out-effective"
    suite_events+=",https://schemas.openid.net/secevent/risc/event-type/opt-out-initiated"
    suite_events+=",https://schemas.openid.net/secevent/risc/event-type/recovery-activated"
    suite_events+=",https://schemas.openid.net/secevent/risc/event-type/recovery-information-changed"
    echo "[$(date +%H:%M:%S)] suite ssf-configuration live (iss=$suite_iss); adding servers" >>"$DRIVER_LOG"

    # `add server` is one-shot per alias inside the SUT container's CLI config.
    # The compose volume is wiped per plan run, so these always succeed on a
    # fresh start; ignore non-zero so a hot rerun (no compose down) keeps going.
    docker "${exec_args[@]}" add server suite "$TX_URL" --token="$RX_TOKEN" \
        >>"$DRIVER_LOG" 2>&1 || \
        echo "[$(date +%H:%M:%S)] add server suite returned non-zero (alias may already exist)" >>"$DRIVER_LOG"
    # The SUT itself, addressable from inside the container via the host-gateway
    # mapping in docker-compose-conformance.yml. The token must carry 'stream'
    # scope so the CLI can POST to /streams.
    docker "${exec_args[@]}" add server local "$SUT_BASE_URL" --token="$RX_LOCAL_TOKEN" \
        >>"$DRIVER_LOG" 2>&1 || \
        echo "[$(date +%H:%M:%S)] add server local returned non-zero (alias may already exist)" >>"$DRIVER_LOG"

    # Event-driven cycle: each receiver test module needs exactly ONE stream
    # pair. Tail the Python runner's stdout (mirrored to $RUNNER_TAP) and react
    # to per-module state transitions:
    #   - "module id <ID> status changed to WAITING" (first time per ID): the
    #     suite is ready for our stream registration → issue one create.
    #   - "module id <ID> status changed to (FINISHED|INTERRUPTED|REVIEW)": the
    #     module is done → delete the streams.
    # This replaces the old "loop and create as fast as possible" approach,
    # which overran the suite's per-module stream-pool cap with "Too many
    # streams configured for receiver" failures.
    # Per-module state machine. For each module the suite walks through:
    #   CONFIGURED → WAITING (driver: CREATE) → ... SUT-driven ops ... →
    #   (after RX_MODULE_HOLD seconds) driver: DELETE → module observes the
    #   final action → FINISHED/REVIEW (or INTERRUPTED on suite-side failure).
    # The DELETE is what lets the test see the full create/.../delete sequence
    # and reach isFinished(). Waiting for the module to advance before deleting
    # deadlocks the test.
    local current_mod="" current_alias="" current_test_name="" current_started=0 current_deleted=0 current_hold=0
    local -A seen_mods=()
    local last_test_name=""

    do_delete() {
        if (( current_deleted == 1 )) || [[ -z "$current_alias" ]]; then
            return
        fi
        echo "[$(date +%H:%M:%S)] module=$current_mod delete streams (${current_alias}-pub, ${current_alias}-rcv)" >>"$DRIVER_LOG"
        docker "${exec_args[@]}" delete stream "${current_alias}-pub" >>"$DRIVER_LOG" 2>&1 || true
        docker "${exec_args[@]}" delete stream "${current_alias}-rcv" >>"$DRIVER_LOG" 2>&1 || true
        current_deleted=1
    }

    end_current() {
        do_delete
        current_mod="" current_alias="" current_test_name="" current_started=0 current_deleted=0 current_hold=0
    }

    issue_create_for_module() {
        local mod="$1" test_name="$2"
        if [[ -n "${seen_mods[$mod]:-}" ]]; then
            return
        fi
        seen_mods[$mod]=1
        # If a module is already open, force-end it before starting the next
        # (shouldn't normally happen because we end_current on terminal state).
        end_current
        cycle=$(( cycle + 1 ))
        current_mod="$mod"
        current_alias="rx${cycle}"
        current_test_name="$test_name"
        current_started=$SECONDS
        current_deleted=0
        # Pick the SUT-side hold based on the test name. supported-events sends
        # one SET per supported event and waits for ACKs — needs longer.
        if [[ "$test_name" == *supported-events* ]]; then
            current_hold=$RX_MODULE_HOLD_EVENTS
        else
            current_hold=$RX_MODULE_HOLD
        fi
        echo "[$(date +%H:%M:%S)] module=$mod test=$test_name cycle=$cycle create connection ($DELIVERY_MODE) name=$current_alias (hold=${current_hold}s)" >>"$DRIVER_LOG"
        if ! printf 'Y\n' | docker "${exec_args[@]}" \
                create stream "$DELIVERY_MODE" connection suite local \
                --name="$current_alias" --events="$suite_events" \
                --iss="$suite_iss" --iss-jwks-url="$suite_jwks" \
                >>"$DRIVER_LOG" 2>&1; then
            echo "[$(date +%H:%M:%S)] module=$mod cycle=$cycle create FAILED" >>"$DRIVER_LOG"
            return
        fi
        do_exercise_management
    }

    # CLI-driven receiver management exercise (Path A). After the publisher
    # stream is registered on the suite, hit the suite's stream-management API
    # with the operations the OpenID receiver conformance plan expects to see:
    # GET (show), PATCH (patch stream config), PUT (replace stream config), and
    # POST status. The DELETE comes later, gated by current_hold. Each
    # invocation is a one-shot CLI script piped to the in-container goSignals
    # binary — one process startup per cycle rather than one per verb. Failures
    # are logged but never abort the cycle: the conformance suite asserts on
    # observed transmitter-side traffic, so a single failure for one verb still
    # lets the others complete.
    do_exercise_management() {
        local pub_alias="${current_alias}-pub"
        echo "[$(date +%H:%M:%S)] module=$current_mod exercise mgmt (GET/PATCH/PUT/status) on $pub_alias" >>"$DRIVER_LOG"
        # docker exec -i wires our stdin straight into the CLI's stdin, where
        # the goSignals REPL reads commands line-by-line (same path as
        # config/scim/scripts/register.sh's `goSignals </scripts/auto-reg.gosignals`).
        docker "${exec_args[@]}" >>"$DRIVER_LOG" 2>&1 <<EOF || \
            echo "[$(date +%H:%M:%S)] module=$current_mod mgmt-exercise CLI returned non-zero" >>"$DRIVER_LOG"
  show stream $pub_alias
patch stream config $pub_alias --description="conformance: patch from receiver"
replace stream config $pub_alias --description="conformance: replace from receiver" --events=$suite_events
set stream status $pub_alias --state=active --reason="conformance: status exercise"
exit
EOF
    }

    local wait_for_tap=$(( SECONDS + 30 ))
    while [[ ! -f "$RUNNER_TAP" ]] && (( SECONDS < wait_for_tap )); do sleep 1; done
    if [[ ! -f "$RUNNER_TAP" ]]; then
        echo "[$(date +%H:%M:%S)] runner tap never appeared at $RUNNER_TAP" >>"$DRIVER_LOG"
        return
    fi

    exec 3< <(tail -F -n +1 "$RUNNER_TAP" 2>/dev/null)

    while (( SECONDS < deadline )); do
        local line=""
        if IFS= read -r -t 2 -u 3 line; then
            if [[ "$line" =~ Running\ test\ module:\ ([A-Za-z0-9_-]+) ]]; then
                last_test_name="${BASH_REMATCH[1]}"
            elif [[ "$line" =~ module\ id\ ([A-Za-z0-9]+)\ status\ changed\ to\ WAITING ]]; then
                issue_create_for_module "${BASH_REMATCH[1]}" "$last_test_name"
            elif [[ "$line" =~ module\ id\ ([A-Za-z0-9]+)\ status\ changed\ to\ (FINISHED|INTERRUPTED|REVIEW) ]]; then
                local mod="${BASH_REMATCH[1]}" state="${BASH_REMATCH[2]}"
                if [[ "$mod" == "$current_mod" ]]; then
                    echo "[$(date +%H:%M:%S)] module=$mod terminal=$state" >>"$DRIVER_LOG"
                    end_current
                fi
            fi
        fi
        # Drive the per-module timeline:
        #   1. After current_hold seconds, issue DELETE (lets the test observe
        #      the full sequence and advance to FINISHED).
        #   2. If the module hasn't reached terminal state within
        #      RX_MODULE_GUARD seconds after delete, force-end and move on.
        if [[ -n "$current_mod" ]]; then
            local elapsed=$(( SECONDS - current_started ))
            if (( current_deleted == 0 )) && (( elapsed >= current_hold )); then
                do_delete
            elif (( current_deleted == 1 )) && (( elapsed >= current_hold + RX_MODULE_GUARD )); then
                echo "[$(date +%H:%M:%S)] module=$current_mod guard timeout after delete — abandoning" >>"$DRIVER_LOG"
                end_current
            fi
        fi
    done

    end_current
    exec 3<&-
    echo "[$(date +%H:%M:%S)] driver window elapsed" >>"$DRIVER_LOG"
}

echo "==> Starting receiver driver (mode=$DELIVERY_MODE, log=$DRIVER_LOG)"
driver_loop &
DRIVER_PID=$!

echo "==> Running plan: $PLAN_SPEC (runner tap: $RUNNER_TAP)"
cd "$SUITE_REPO"
# Tee the runner's stdout+stderr so the driver can `tail -F` per-module state
# transitions in real time without racing the per-plan log file that
# run-all-plans.sh writes.
CONFORMANCE_DEV_MODE=1 \
    CONFORMANCE_SERVER="$SUITE_URL" \
    .venv/bin/python3 scripts/run-test-plan.py \
    --export-dir "$SCRIPT_DIR/results" \
    $EXTRA_RUNNER_ARGS \
    "$PLAN_SPEC" \
    "$CONFIG_PATH" 2>&1 | tee "$RUNNER_TAP"

echo "==> Done: $PLAN_SPEC (driver log: $DRIVER_LOG, runner tap: $RUNNER_TAP)"
