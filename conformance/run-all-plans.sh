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

# Accumulator for the Findings section: one TSV row per non-PASS condition,
# harvested from each plan's signed export and rendered (deduped) after the whole
# matrix runs. This is what turns the bare P/W/R/F counts in the table into the
# actual "here is the warning/error" list, so reading the summary no longer means
# diving into per-plan logs or zips.
FINDINGS_TSV="$(mktemp -t ssf-findings.XXXXXX)"
trap 'rm -f "$FINDINGS_TSV"' EXIT

# Prune per-plan logs and summary markdowns older than RESULTS_RETAIN_DAYS days.
# Without this, results/ grows unbounded and the FAILED grep in the aggregator
# below can re-match stale logs the next time someone audits the dir.
RESULTS_RETAIN_DAYS="${RESULTS_RETAIN_DAYS:-14}"
find "$SCRIPT_DIR/results" -maxdepth 1 -type f \( -name 'run-*' -o -name 'rx-driver-*' -o -name 'runner-tap-*' -o -name 'trigger-caep-*' \) -mtime "+${RESULTS_RETAIN_DAYS}" -delete 2>/dev/null || true

PLANS_FILTER="${PLANS_FILTER:-}"

# (script, plan-spec) pairs. Keep transmitter plans first so a clean run
# baselines the SUT before the receiver flow exercises new code paths.
PLANS=(
    "run-plan.sh|openid-ssf-transmitter-test-plan[ssf_delivery_mode=push][ssf_server_metadata=discovery][ssf_auth_mode=static]"
    "run-plan.sh|openid-ssf-transmitter-test-plan[ssf_delivery_mode=poll][ssf_server_metadata=discovery][ssf_auth_mode=static]"
    "run-plan.sh|openid-ssf-transmitter-caep-test-plan[ssf_delivery_mode=push][ssf_server_metadata=discovery][ssf_auth_mode=static]"
    "run-plan.sh|openid-ssf-transmitter-caep-test-plan[ssf_delivery_mode=poll][ssf_server_metadata=discovery][ssf_auth_mode=static]"
    # Receiver plans now require ssf_auth_mode (suite >= v5.1.45 added SsfAuthMode +
    # ClientAuthType to the receiver modules). With ssf_auth_mode=static the suite
    # marks client_auth_type "not applicable" (the receiver presents a pre-shared
    # bearer), so it is NOT specified. Omitting ssf_auth_mode fails plan creation
    # with "requires a value for variant 'client_auth_type'" (no export produced).
    "run-receiver-plan.sh|openid-ssf-receiver-test-plan[ssf_delivery_mode=push][ssf_auth_mode=static]"
    "run-receiver-plan.sh|openid-ssf-receiver-test-plan[ssf_delivery_mode=poll][ssf_auth_mode=static]"
    "run-receiver-plan.sh|openid-ssf-receiver-caep-test-plan[ssf_delivery_mode=push][ssf_auth_mode=static]"
    "run-receiver-plan.sh|openid-ssf-receiver-caep-test-plan[ssf_delivery_mode=poll][ssf_auth_mode=static]"
)

# Score one plan by reading the suite's signed export zip — the only authoritative
# source for per-module results. The per-plan stdout/stderr log is noisy
# (TAP emits "result=FAILURE" lines for individual conditions even inside
# modules that gate as WARNING), so the previous grep-the-log heuristic
# mislabeled operationally-passing plans as FAIL (modules-failed). Each
# zip contains one `test-log-<module-id>.json` per module, each with an
# authoritative `.testInfo.result` ∈ {PASSED, WARNING, REVIEW, FAILED,
# SKIPPED} and `.testInfo.status` ∈ {FINISHED, INTERRUPTED, ...}.
#
# Args:
#   $1 = zip path
# Echoes a single line:
#   "<plan-status>|<counts-string>"
# where plan-status ∈ {PASS, WARNING, REVIEW, FAIL} and counts-string is
# a compact P/W/R/F/I/S breakdown.
score_plan_zip() {
    local zip="$1"
    local workdir
    workdir="$(mktemp -d)"
    if ! unzip -q "$zip" -d "$workdir" 2>/dev/null; then
        rm -rf "$workdir"
        echo "FAIL|export-unreadable"
        return
    fi
    local p=0 w=0 r=0 f=0 in=0 s=0 other=0
    local interrupted_seen=""
    local json
    for json in "$workdir"/test-log-*.json; do
        [[ -f "$json" ]] || continue
        local result status
        result="$(jq -r '.testInfo.result // "MISSING"' "$json" 2>/dev/null)"
        status="$(jq -r '.testInfo.status // "MISSING"' "$json" 2>/dev/null)"
        # INTERRUPTED at the module level is always fatal regardless of
        # whatever .result says — count it separately so we can show it.
        if [[ "$status" == "INTERRUPTED" ]]; then
            in=$(( in + 1 ))
            interrupted_seen="yes"
            continue
        fi
        case "$result" in
            PASSED)  p=$(( p + 1 )) ;;
            WARNING) w=$(( w + 1 )) ;;
            REVIEW)  r=$(( r + 1 )) ;;
            FAILED)  f=$(( f + 1 )) ;;
            SKIPPED) s=$(( s + 1 )) ;;
            *)       other=$(( other + 1 )) ;;
        esac
    done
    rm -rf "$workdir"
    local counts="P=${p} W=${w} R=${r} F=${f} I=${in} S=${s}"
    [[ "$other" -gt 0 ]] && counts="${counts} ?=${other}"
    # Plan status precedence:
    #   FAIL    — any FAILED, INTERRUPTED, or unknown-state module
    #   REVIEW  — at least one REVIEW (human attention needed)
    #   WARNING — at least one WARNING and no harder issues
    #   PASS    — all PASSED (SKIPPED is treated as neutral)
    local plan_status
    if [[ "$f" -gt 0 || "$in" -gt 0 || "$other" -gt 0 ]]; then
        plan_status="FAIL"
    elif [[ "$r" -gt 0 ]]; then
        plan_status="REVIEW"
    elif [[ "$w" -gt 0 ]]; then
        plan_status="WARNING"
    else
        plan_status="PASS"
    fi
    echo "${plan_status}|${counts}"
}

# Harvest every non-PASS condition from a plan's export zip into the global
# FINDINGS_TSV accumulator. One row per condition:
#   <plan-label> <module> <result> <condition> <requirements> <message>
# Module-level INTERRUPTED is annotated onto the result (e.g. FAILURE/INTERRUPTED)
# so a systemic break (all modules dying at the same condition) is obvious. The
# message has tabs/newlines/pipes squashed so it stays one clean Markdown cell.
#
# Args: $1 = zip path, $2 = compact plan label
collect_findings() {
    local zip="$1" label="$2"
    local workdir
    workdir="$(mktemp -d)"
    if ! unzip -q "$zip" -d "$workdir" 2>/dev/null; then
        rm -rf "$workdir"
        return
    fi
    local json
    for json in "$workdir"/test-log-*.json; do
        [[ -f "$json" ]] || continue
        jq -r --arg label "$label" '
            .testInfo.testName as $m
            | (.testInfo.status // "") as $st
            | .results[]?
            | select(.result? and (.result | test("^(FAILURE|WARNING|REVIEW)$")))
            | [ $label,
                ($m // "?"),
                (if $st == "INTERRUPTED" then .result + "/INTERRUPTED" else .result end),
                (.src // "-"),
                ((.requirements // []) | join(", ")),
                ((.msg // "") | gsub("[\r\n\t|]"; " "))
              ] | @tsv
        ' "$json" 2>/dev/null >>"$FINDINGS_TSV"
    done
    rm -rf "$workdir"
}

# Find the newest zip in results/ matching the plan's test-plan name. The
# suite drops one zip per `run-test-plan.py` invocation, so a snapshot-and-
# diff against the pre-run zip list reliably picks the export this run
# produced even when multiple plans share the same plan name with different
# variants (the suite encodes variant into the zip name as `-poll`/`-push`/
# `-default`/`-static`).
find_plan_zip() {
    local plan="$1"
    local since_epoch="$2"
    # Extract the plan name (before the first `[`) so we can match the
    # suite's zip naming, e.g. `openid-ssf-transmitter-caep-test-plan-*`.
    local plan_name="${plan%%\[*}"
    # Encode variants into a substring filter — the zip name includes them
    # without the `[ssf_…=]` decoration, so just look for the values.
    local variant_marker=""
    if [[ "$plan" == *"ssf_delivery_mode=push"* ]]; then variant_marker="-push"; fi
    if [[ "$plan" == *"ssf_delivery_mode=poll"* ]]; then variant_marker="-poll"; fi
    local newest=""
    local newest_ts=0
    local zip
    for zip in "$SCRIPT_DIR/results/${plan_name}"*.zip; do
        [[ -f "$zip" ]] || continue
        [[ -n "$variant_marker" && "$zip" != *"${variant_marker}"* ]] && continue
        local ts
        ts="$(stat -f %m "$zip" 2>/dev/null || stat -c %Y "$zip" 2>/dev/null || echo 0)"
        if [[ "$ts" -gt "$newest_ts" && "$ts" -ge "$since_epoch" ]]; then
            newest_ts="$ts"
            newest="$zip"
        fi
    done
    echo "$newest"
}

{
    echo "# SSF Conformance — run ${TS_HUMAN}"
    echo
    echo "| # | Driver | Plan | Status | Modules (P/W/R/F/I/S) | Log |"
    echo "|---|---|---|---|---|---|"
} >"$SUMMARY"

PASS_COUNT=0
WARN_COUNT=0
REVIEW_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

i=0
for entry in "${PLANS[@]}"; do
    i=$(( i + 1 ))
    script="${entry%%|*}"
    plan="${entry#*|}"

    if [[ -n "$PLANS_FILTER" && "$plan" != *"$PLANS_FILTER"* ]]; then
        echo "| $i | $script | \`$plan\` | SKIP (filter) | | |" >>"$SUMMARY"
        SKIP_COUNT=$(( SKIP_COUNT + 1 ))
        continue
    fi

    slug="$(echo "$plan" | tr -c 'A-Za-z0-9' '-' | tr -s '-' | sed 's/^-//;s/-$//')"
    log="$SCRIPT_DIR/results/run-${TS_HUMAN}-${slug}.log"

    # Compact, cross-referenceable label for the Findings section. The matrix
    # table above maps this same #index to the full plan spec.
    fam="tx"; [[ "$plan" == *receiver* ]] && fam="rx"
    [[ "$plan" == *caep* ]] && fam="${fam}-caep"
    dmode="?"
    [[ "$plan" == *ssf_delivery_mode=push* ]] && dmode="push"
    [[ "$plan" == *ssf_delivery_mode=poll* ]] && dmode="poll"
    plan_label="#${i} ${fam}[${dmode}]"

    echo
    echo "================================================================"
    echo " [$i/${#PLANS[@]}] $script $plan"
    echo " log: $log"
    echo "================================================================"

    pre_epoch="$(date +%s)"
    runner_failed=""
    if ! "$SCRIPT_DIR/$script" "$plan" >"$log" 2>&1; then
        runner_failed="yes"
    fi

    # Score from the signed export. If no zip appeared, that itself is a
    # failure — surface it explicitly rather than silently passing.
    zip_path="$(find_plan_zip "$plan" "$pre_epoch")"
    counts=""
    if [[ -n "$zip_path" && -f "$zip_path" ]]; then
        IFS='|' read -r status counts < <(score_plan_zip "$zip_path")
        collect_findings "$zip_path" "$plan_label"
    else
        status="FAIL"
        counts="no-export"
    fi
    if [[ -n "$runner_failed" && "$status" == "PASS" ]]; then
        # Runner exited non-zero but every captured module passed. Don't
        # claim PASS — surface as REVIEW so a human checks the log.
        status="REVIEW"
        counts="${counts} runner-rc!=0"
    fi

    case "$status" in
        PASS)    PASS_COUNT=$(( PASS_COUNT + 1 )) ;;
        WARNING) WARN_COUNT=$(( WARN_COUNT + 1 )) ;;
        REVIEW)  REVIEW_COUNT=$(( REVIEW_COUNT + 1 )) ;;
        *)       FAIL_COUNT=$(( FAIL_COUNT + 1 )) ;;
    esac
    echo "| $i | $script | \`$plan\` | $status | $counts | [\`$(basename "$log")\`]($(basename "$log")) |" >>"$SUMMARY"
done

{
    echo
    echo "## Findings"
    echo
    if [[ -s "$FINDINGS_TSV" ]]; then
        echo "Every non-PASS condition across all plans — the actual warnings,"
        echo "reviews, and failures behind the counts above, taken from each plan's"
        echo "signed export. The Plan column's #index matches the table at the top."
        echo
        echo "| Plan | Module | Result | Condition | Requirements | Message |"
        echo "|---|---|---|---|---|---|"
        sort -u "$FINDINGS_TSV" | while IFS=$'\t' read -r f_plan f_mod f_res f_cond f_req f_msg; do
            echo "| $f_plan | $f_mod | $f_res | \`$f_cond\` | $f_req | $f_msg |"
        done
    else
        echo "None — every module passed (no warnings, reviews, failures, or interruptions)."
    fi
} >>"$SUMMARY"

{
    echo
    echo "## Totals"
    echo
    echo "- pass:    $PASS_COUNT"
    echo "- warning: $WARN_COUNT"
    echo "- review:  $REVIEW_COUNT"
    echo "- fail:    $FAIL_COUNT"
    echo "- skipped: $SKIP_COUNT"
    echo
    echo "Status precedence per plan (worst-of):"
    echo "FAIL > REVIEW > WARNING > PASS. INTERRUPTED modules and missing"
    echo "exports count as FAIL. SKIPPED modules are neutral. Module counts"
    echo "shown as P=passed W=warning R=review F=failed I=interrupted S=skipped."
} >>"$SUMMARY"

echo
echo "==> Aggregate summary: $SUMMARY"
