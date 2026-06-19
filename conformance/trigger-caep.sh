#!/usr/bin/env bash
#
# Drive the conformance suite's CAEP-interop module by injecting CAEP events
# into the running SUT.
#
# The suite's `openid-ssf-transmitter-stream-caep-interop` test creates a
# stream subscribed to a set of CAEP event types, triggers stream
# verification, and then waits up to 60 s for the *transmitter* to deliver
# every type listed in the stream's effective `events_delivered`. Without an
# operator-side trigger the wait times out (see results/run-2026-06-17.md F2).
#
# Why this script is careful about *which* stream it triggers into:
# all modules in the CAEP plan share the suite's single push receiver,
# so any CAEP event we inject lands on the same endpoint that the active
# test is reading from. Earlier modules (verification-push,
# verification-error-push-no-auth, etc.) create CAEP-subscribed streams
# too — if we fire while they are running, their assertions on the next
# push payload pick up *our* CAEP event instead of the verification SET
# they expect, and the modules fail spuriously.
#
# Heuristic:
#   - Re-discover the newest CAEP-subscribed stream on every round.
#   - Only fire into it once it has existed for at least
#     STREAM_MIN_AGE_SECS seconds (default 5). Earlier modules create then
#     delete their streams within ~1 s; the caep-interop module holds its
#     stream open for the 60 s delivery wait. The age gate lets verification
#     dances on earlier modules complete cleanly before we trigger.
#
# This helper:
#   1. Uses the bootstrap bearer (I2SIG_BOOTSTRAP_TOKEN) directly as the
#      authorization for /trigger-event. The handler at
#      internal/server/api_out_of_band.go:715 accepts admin/root client tokens
#      and the key-scope bootstrap bearer; the bootstrap path keeps the harness
#      free of out-of-band admin client provisioning.
#   2. POSTs `POST /trigger-event` with a non-empty `event_data` matching the
#      CAEP 1.0 §3.x required fields for each event type (so the suite's
#      OIDSSFExtractCaepEventData / OIDSSFValidateCaep*Event conditions pass).
#   3. Exits cleanly when the suite deletes the stream or when the wait
#      window elapses.
#
# Intended use: run in the background while `run-plan.sh` invokes the CAEP
# plan. `run-plan.sh` does this automatically when "caep" appears in the
# plan spec; you can also run this script standalone for hand-driven runs.
#
# Env:
#   GOSIGNALS_URL       default https://localhost.emobix.co.uk:9443
#   BOOTSTRAP_TOKEN     default dev-bootstrap-secret
#   MONGO_CONTAINER     default ssfconf-mongo
#   MONGO_DB            default ssfconf
#   TRIGGER_WINDOW      seconds to keep triggering (default 90)
#   TRIGGER_INTERVAL    seconds between trigger rounds (default 4)
#   STREAM_MIN_AGE_SECS minimum stream lifetime before triggering (default 12).
#                       Must be > the verification-test stream lifetime (~10 s)
#                       so we never fire into 1:10/1:11. caep-interop's 60 s
#                       delivery wait gives us plenty of room.
#   SUBJECT_ID          opaque id for the synthetic CAEP subject (default valid)
#   TRIGGER_LOG         optional log file path (default stderr only)
set -euo pipefail

GOSIGNALS_URL="${GOSIGNALS_URL:-https://localhost.emobix.co.uk:9443}"
BOOTSTRAP_TOKEN="${BOOTSTRAP_TOKEN:-dev-bootstrap-secret}"
MONGO_CONTAINER="${MONGO_CONTAINER:-ssfconf-mongo}"
MONGO_DB="${MONGO_DB:-ssfconf}"
TRIGGER_WINDOW="${TRIGGER_WINDOW:-300}"
TRIGGER_INTERVAL="${TRIGGER_INTERVAL:-4}"
STREAM_MIN_AGE_SECS="${STREAM_MIN_AGE_SECS:-20}"
SUBJECT_ID="${SUBJECT_ID:-valid}"
TRIGGER_LOG="${TRIGGER_LOG:-}"

log() {
    local line
    line="[$(date +%H:%M:%S)] trigger-caep: $*"
    echo "$line" >&2
    [[ -n "$TRIGGER_LOG" ]] && echo "$line" >> "$TRIGGER_LOG" || true
}

mongo_eval() {
    docker exec "$MONGO_CONTAINER" mongosh --quiet "$MONGO_DB" --eval "$1" 2>/dev/null
}

# Number of pending (unacked) events queued for the stream. A verification-poll
# test continuously enqueues events; caep-interop after the verification dance
# enters a quiet wait state with pendingEvents == 0. This is the side-channel
# that lets us distinguish "test is actively polling" from "test is waiting for
# operator-driven events".
stream_pending() {
    mongo_eval "print(db.pendingEvents.countDocuments({sid: ObjectId(\"$1\")}))" | tr -d '\r\n '
}

# Returns "sid|created_unix_seconds|event1,event2,..." for the newest stream
# whose events_delivered contains at least one CAEP URN. Empty stdout = none.
find_caep_stream() {
    mongo_eval '
        const s = db.streams.find({events_delivered: {$regex: "secevent/caep/"}})
            .sort({_id: -1}).limit(1).toArray()[0];
        if (!s) { print(""); }
        else {
            const caep = (s.events_delivered || []).filter(e => e.indexOf("secevent/caep/") >= 0);
            const created = Math.floor(s._id.getTimestamp().getTime() / 1000);
            print(s._id.toString() + "|" + created + "|" + caep.join(","));
        }
    '
}

# Emit the CAEP-1.0-required event_data for the given event type as JSON.
# Empty for types that have no required fields.
event_data_for() {
    local evt="$1"
    case "$evt" in
        *credential-change)
            jq -n '{credential_type: "password", change_type: "update"}' ;;
        *device-compliance-change)
            jq -n '{current_status: "compliant", previous_status: "not-compliant"}' ;;
        *session-revoked|*)
            jq -n '{}' ;;
    esac
}

trigger_event() {
    local sid="$1" event_type="$2" token="$3"
    local payload status data
    data="$(event_data_for "$event_type")"
    payload="$(jq -n \
        --arg sid "$sid" \
        --arg evt "$event_type" \
        --arg subid "$SUBJECT_ID" \
        --argjson data "$data" \
        '{stream_id: $sid, event_type: $evt, subject: {format: "opaque", id: $subid}, event_data: $data}')"
    status="$(curl -sk -o /dev/null -w '%{http_code}' \
        -X POST "$GOSIGNALS_URL/trigger-event" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d "$payload")"
    log "  trigger $event_type -> HTTP $status"
}

main() {
    if ! command -v jq >/dev/null 2>&1; then
        log "ERROR: jq is required"; exit 1
    fi
    if ! docker ps --format '{{.Names}}' | grep -qx "$MONGO_CONTAINER"; then
        log "ERROR: mongo container '$MONGO_CONTAINER' is not running"; exit 1
    fi

    local token="$BOOTSTRAP_TOKEN"
    log "using bootstrap bearer for /trigger-event (key scope)"

    # Module-active gate: previously the script's only gates were stream age
    # (>=N seconds) and pendingEvents==0. Both fail when a NON-caep-interop
    # CAEP module (e.g. verification-error-push-no-auth) holds the newest
    # CAEP-subscribed stream: its stream is plenty old, and pendingEvents
    # drops to 0 between the SUT's push retries. trigger-caep.sh then fires
    # device-compliance-change / credential-change / session-revoked events
    # with sub_id={format:"opaque",id:"valid"} into that stream — the SUT
    # dutifully pushes them to the suite's shared /ssf-push endpoint, and
    # the active test's "next push must be a verification SET with state
    # echoed" assertion sees our CAEP event instead and fails.
    #
    # Fix: gate ALL firing on observing the suite's TAP signal that
    # caep-interop is the active module. The suite emits one of:
    #   "Running test module: openid-ssf-transmitter-stream-caep-interop[...]"
    #   "Running test module: openid-ssf-receiver-stream-caep-interop[...]"
    # in its runner stdout. run-plan.sh / run-receiver-plan.sh now tee that
    # stream to TRIGGER_TAP_FILE; we tail it here. Until we see caep-interop,
    # we hold off entirely. Once seen, we proceed with the age + pending
    # heuristics as before (they're still useful for the verify-in-progress
    # phase of caep-interop itself).
    if [[ -n "${TRIGGER_TAP_FILE:-}" ]]; then
        local tap_wait_deadline=$(( SECONDS + TRIGGER_WINDOW ))
        log "waiting for caep-interop module signal in $TRIGGER_TAP_FILE..."
        while (( SECONDS < tap_wait_deadline )); do
            if [[ -f "$TRIGGER_TAP_FILE" ]] && \
                grep -q "Running test module:.*stream-caep-interop" "$TRIGGER_TAP_FILE" 2>/dev/null; then
                log "caep-interop module is now active — beginning trigger discovery"
                break
            fi
            sleep 1
        done
        if [[ -f "$TRIGGER_TAP_FILE" ]] && \
            ! grep -q "Running test module:.*stream-caep-interop" "$TRIGGER_TAP_FILE" 2>/dev/null; then
            log "TRIGGER_TAP_FILE never signaled caep-interop — exiting clean (other modules complete on their own)"
            return 0
        fi
    else
        log "TRIGGER_TAP_FILE unset — falling back to legacy age+pending heuristic (may pollute non-interop modules)"
    fi
    log "watching ${MONGO_DB}.streams for an age>=${STREAM_MIN_AGE_SECS}s CAEP stream (up to ${TRIGGER_WINDOW}s)..."

    local deadline=$(( SECONDS + TRIGGER_WINDOW ))
    local fired_sid=""
    while (( SECONDS < deadline )); do
        local hit; hit="$(find_caep_stream)"
        if [[ -z "$hit" ]]; then
            sleep 1
            continue
        fi
        local sid="${hit%%|*}"
        local rest="${hit#*|}"
        local created="${rest%%|*}"
        local caep_csv="${rest#*|}"
        local now; now="$(date -u +%s)"
        local age=$(( now - created ))
        if (( age < STREAM_MIN_AGE_SECS )); then
            log "newest CAEP stream sid=$sid age=${age}s — waiting for >=${STREAM_MIN_AGE_SECS}s"
            sleep 1
            continue
        fi
        local pending; pending="$(stream_pending "$sid")"
        if [[ "$pending" != "0" ]]; then
            # An active verification-poll test continuously enqueues events.
            # Skip until the queue is empty, which signals the test has moved
            # into a quiet wait state (e.g. caep-interop's delivery window).
            log "stream $sid age=${age}s has $pending pending event(s) — skipping (likely active verification test)"
            sleep 1
            continue
        fi
        # Different stream from last round? Re-announce.
        if [[ "$sid" != "$fired_sid" ]]; then
            log "trigger target sid=$sid (age=${age}s) events=$caep_csv"
            fired_sid="$sid"
        fi
        log "trigger round (stream $sid)"
        IFS=',' read -r -a caep_events <<<"$caep_csv"
        for evt in "${caep_events[@]}"; do
            [[ -z "$evt" ]] && continue
            trigger_event "$sid" "$evt" "$token"
        done
        sleep "$TRIGGER_INTERVAL"
    done
    log "trigger window elapsed; exiting"
}

main "$@"
