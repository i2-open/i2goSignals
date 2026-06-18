#!/usr/bin/env bash
#
# Run every SSF conformance plan (transmitter + receiver, push + poll,
# default + caep-interop) end-to-end and aggregate the results into a single
# Markdown summary under conformance/results/.
#
# Each plan is driven by run-plan.sh (transmitter) or run-receiver-plan.sh
# (receiver). Both wipe the SUT before they begin, so plan-to-plan state never
# leaks. The aggregator does NOT short-circuit on a failing plan — every plan
# in the list runs so a single bad module does not block the rest of the
# matrix.
#
# Usage:
#   ./run-all-plans.sh                 # run the full matrix
#   PLANS_FILTER='transmitter' ./run-all-plans.sh
#                                       # run only plans whose spec contains "transmitter"
#
# Output:
#   results/run-YYYY-MM-DDTHHMMSS.md   aggregate summary
#   results/run-<ts>-<plan>.log         per-plan stdout/stderr
#   results/*.zip                       per-plan signed export from the suite
#
# Env knobs (all forwarded to the per-plan scripts):
#   SUITE_REPO, SUITE_URL, SUT_READY_URL, SUT_READY_TRIES,
#   RX_TOKEN, RX_DRIVER_INTERVAL, RX_DRIVER_WINDOW,
#   GOSIGNALS_CONTAINER, EXTRA_RUNNER_ARGS
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TS_HUMAN="$(date -u +%Y-%m-%dT%H%M%SZ)"
SUMMARY="$SCRIPT_DIR/results/run-${TS_HUMAN}.md"
mkdir -p "$SCRIPT_DIR/results"

PLANS_FILTER="${PLANS_FILTER:-}"

# (script, plan-spec) pairs. Keep transmitter plans first so a clean run
# baselines the SUT before the receiver flow exercises new code paths.
PLANS=(
    "run-plan.sh|openid-ssf-transmitter-test-plan[ssf_delivery_mode=push][ssf_server_metadata=discovery][ssf_auth_mode=static]"
    "run-plan.sh|openid-ssf-transmitter-test-plan[ssf_delivery_mode=poll][ssf_server_metadata=discovery][ssf_auth_mode=static]"
    "run-plan.sh|openid-ssf-transmitter-caep-test-plan[ssf_delivery_mode=push][ssf_server_metadata=discovery][ssf_auth_mode=static]"
    "run-plan.sh|openid-ssf-transmitter-caep-test-plan[ssf_delivery_mode=poll][ssf_server_metadata=discovery][ssf_auth_mode=static]"
    "run-receiver-plan.sh|openid-ssf-receiver-test-plan[ssf_delivery_mode=push]"
    "run-receiver-plan.sh|openid-ssf-receiver-test-plan[ssf_delivery_mode=poll]"
    "run-receiver-plan.sh|openid-ssf-receiver-caep-test-plan[ssf_delivery_mode=push]"
    "run-receiver-plan.sh|openid-ssf-receiver-caep-test-plan[ssf_delivery_mode=poll]"
)

{
    echo "# SSF Conformance — run ${TS_HUMAN}"
    echo
    echo "| # | Driver | Plan | Status | Log |"
    echo "|---|---|---|---|---|"
} >"$SUMMARY"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

i=0
for entry in "${PLANS[@]}"; do
    i=$(( i + 1 ))
    script="${entry%%|*}"
    plan="${entry#*|}"

    if [[ -n "$PLANS_FILTER" && "$plan" != *"$PLANS_FILTER"* ]]; then
        echo "| $i | $script | \`$plan\` | SKIP (filter) | |" >>"$SUMMARY"
        SKIP_COUNT=$(( SKIP_COUNT + 1 ))
        continue
    fi

    slug="$(echo "$plan" | tr -c 'A-Za-z0-9' '-' | tr -s '-' | sed 's/^-//;s/-$//')"
    log="$SCRIPT_DIR/results/run-${TS_HUMAN}-${slug}.log"

    echo
    echo "================================================================"
    echo " [$i/${#PLANS[@]}] $script $plan"
    echo " log: $log"
    echo "================================================================"

    status="PASS"
    if ! "$SCRIPT_DIR/$script" "$plan" >"$log" 2>&1; then
        status="FAIL"
    fi
    # Even a 0-exit run can hide module failures; surface them in the summary.
    if grep -qE 'FAILURE|status: FAILED' "$log" 2>/dev/null; then
        status="${status} (modules-failed)"
    fi

    case "$status" in
        PASS) PASS_COUNT=$(( PASS_COUNT + 1 )) ;;
        *)    FAIL_COUNT=$(( FAIL_COUNT + 1 )) ;;
    esac
    echo "| $i | $script | \`$plan\` | $status | [\`$(basename "$log")\`]($(basename "$log")) |" >>"$SUMMARY"
done

{
    echo
    echo "## Totals"
    echo
    echo "- pass: $PASS_COUNT"
    echo "- fail/regressed: $FAIL_COUNT"
    echo "- skipped: $SKIP_COUNT"
} >>"$SUMMARY"

echo
echo "==> Aggregate summary: $SUMMARY"
