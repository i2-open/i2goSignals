#!/usr/bin/env bash
# Smoke test for the dev observability stack (issue #57).
#
# Run after `make dev-up`. Codifies the acceptance criteria so the test
# becomes a single command operators (and CI) can run.
#
# Exits non-zero on first failure with a clear message identifying which
# criterion failed.

# pipefail is intentionally NOT enabled: several predicates use
# `docker logs ... | grep -m1`, where grep closes stdin after the first match
# and the producer exits 141 (SIGPIPE). Under pipefail that becomes a false
# negative. The script's failure modes are explicit `fail` calls.
set -eu

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

ok() { echo "  OK: $1"; }

LOKI_URL=${LOKI_URL:-http://localhost:3100}
GRAFANA_URL=${GRAFANA_URL:-http://localhost:3000}
GRAFANA_AUTH=${GRAFANA_AUTH:-admin:grafana}
PROMETHEUS_URL=${PROMETHEUS_URL:-http://localhost:9090}
WAIT_SECS=${WAIT_SECS:-90}

wait_for() {
    local desc="$1"
    local check="$2"
    local elapsed=0
    # The check runs in a subshell with pipefail disabled. Predicates like
    # `docker logs ... | grep -m1` succeed at grep but the upstream sees
    # SIGPIPE (exit 141), and with pipefail that bubbles up as a false-negative.
    until ( set +o pipefail; eval "$check" >/dev/null 2>&1 ); do
        elapsed=$((elapsed+2))
        if [ "$elapsed" -ge "$WAIT_SECS" ]; then
            fail "timeout waiting for $desc (${WAIT_SECS}s)"
        fi
        sleep 2
    done
}

echo "1) Loki readiness..."
wait_for "Loki /ready" "curl -fsS ${LOKI_URL}/ready"
ok "Loki ready"

echo "2) Grafana datasource provisioning includes Loki..."
wait_for "Grafana API" "curl -fsS -u ${GRAFANA_AUTH} ${GRAFANA_URL}/api/datasources"
ds_json=$(curl -fsS -u "${GRAFANA_AUTH}" "${GRAFANA_URL}/api/datasources")
echo "$ds_json" | grep -q '"type":"loki"' \
    || fail "Grafana does not list Loki datasource: $ds_json"
ok "Loki datasource present in Grafana"

echo "3) gosignals1 emits JSON to stdout with default attrs..."
wait_for "gosignals1 JSON log line" \
    "docker logs gosignals1 2>&1 | grep -m1 -E '\"service\":\"gosignals\"'"
log_line=$(docker logs gosignals1 2>&1 | grep -m1 -E '"service":"gosignals"')
for field in '"service":"gosignals"' '"node_id":' '"cluster_name":"dev-local"' '"version":' '"level":'; do
    echo "$log_line" | grep -q "$field" \
        || fail "expected field $field missing in gosignals1 JSON log line: $log_line"
done
ok "gosignals1 stdout JSON includes service, node_id, cluster_name=dev-local, version, level"

echo "4) Loki exposes the expected goSignals label set..."
expected_labels=(service node_id cluster_name component level version)
wait_for "Loki label 'service'" \
    "curl -fsS ${LOKI_URL}/loki/api/v1/labels | grep -q '\"service\"'"
labels_json=$(curl -fsS "${LOKI_URL}/loki/api/v1/labels")
for lbl in "${expected_labels[@]}"; do
    echo "$labels_json" | grep -q "\"$lbl\"" \
        || fail "label '$lbl' not present in Loki labels: $labels_json"
done
ok "all six expected labels present"

echo "5) High-cardinality fields are NOT promoted to labels..."
for forbidden in stream_id jti audience issuer remote_addr trace_id; do
    if echo "$labels_json" | grep -q "\"$forbidden\""; then
        fail "label '$forbidden' MUST NOT be a Loki label (cardinality discipline)"
    fi
done
ok "stream_id, jti, audience, issuer, remote_addr, trace_id not in labels"

echo "6) LogQL query for {service=\"gosignals\"} returns success..."
end_ns=$(date +%s)000000000
start_ns=$(( $(date +%s) - 600 ))000000000
query='%7Bservice%3D%22gosignals%22%7D'
resp=$(curl -fsS "${LOKI_URL}/loki/api/v1/query_range?query=${query}&limit=10&start=${start_ns}&end=${end_ns}")
echo "$resp" | grep -q '"status":"success"' \
    || fail "LogQL query did not return success: $resp"
ok "LogQL query returns success"

echo "7) Alloy container is not currently error-spamming..."
# Filter to the last 60s only: on warm starts Alloy drains historical docker
# log entries that fall outside Loki's ingest window and prints "entry too far
# behind" errors. That's expected boot churn, not a steady-state failure mode.
err_count=$(docker logs --since 60s alloy 2>&1 | grep -cE 'level=error|"level":"error"' || true)
[ "$err_count" -lt 20 ] \
    || fail "alloy logged $err_count error lines in the last 60s (threshold 20)"
ok "alloy steady-state errors below threshold (${err_count} in last 60s)"

echo "8) Pre-existing dev services still healthy..."
for c in mongo1 mongo2 mongo3 gosignals1 gosignals2 gossfserver prometheus grafana; do
    state=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo "missing")
    [ "$state" = "running" ] \
        || fail "container $c is in state '$state', expected running"
done
ok "all expected dev containers running"

echo "9) i2scim peers visible in Loki labels (issue #73)..."
# The SCIM peers run the i2scim-universal image which emits JSON logs with
# service=i2scim once QUARKUS_LOG_CONSOLE_JSON=true is set. node_id and
# cluster_name come from the env block on each container.
for lbl_val in 'i2scim' 'scim_cluster1' 'scim_cluster2' 'dev-local'; do
    echo "$labels_json" >/dev/null  # labels_json fetched in section 4
done
# Re-query label *values* rather than label *names* — names were checked
# in section 4. Here we verify the SCIM peers produced lines with the
# expected discriminators.
service_values=$(curl -fsS "${LOKI_URL}/loki/api/v1/label/service/values")
echo "$service_values" | grep -q '"i2scim"' \
    || fail "service=i2scim not seen in Loki label values: $service_values"
node_values=$(curl -fsS "${LOKI_URL}/loki/api/v1/label/node_id/values")
for n in scim_cluster1 scim_cluster2; do
    echo "$node_values" | grep -q "\"$n\"" \
        || fail "node_id=$n not seen in Loki: $node_values"
done
cluster_values=$(curl -fsS "${LOKI_URL}/loki/api/v1/label/cluster_name/values")
echo "$cluster_values" | grep -q '"dev-local"' \
    || fail "cluster_name=dev-local not seen in Loki: $cluster_values"
ok "i2scim peers labelled with service/node_id/cluster_name"

echo "10) LogQL filter by SCIM node_id returns only that peer..."
end_ns=$(date +%s)000000000
start_ns=$(( $(date +%s) - 600 ))000000000
query='%7Bnode_id%3D%22scim_cluster1%22%7D'
resp=$(curl -fsS "${LOKI_URL}/loki/api/v1/query_range?query=${query}&limit=10&start=${start_ns}&end=${end_ns}")
echo "$resp" | grep -q '"status":"success"' \
    || fail "LogQL query for scim_cluster1 did not return success: $resp"
# Negative check: response must not surface scim_cluster2 stream labels.
if echo "$resp" | grep -q '"node_id":"scim_cluster2"'; then
    fail "LogQL query for scim_cluster1 leaked scim_cluster2 streams"
fi
ok "node_id=scim_cluster1 query returns only that peer"

echo "11) Prometheus scrapes both i2scim peers (issue #73)..."
wait_for "Prometheus /api/v1/targets" \
    "curl -fsS ${PROMETHEUS_URL}/api/v1/targets"
targets_json=$(curl -fsS "${PROMETHEUS_URL}/api/v1/targets")
echo "$targets_json" | grep -q '"job":"i2scim"' \
    || fail "Prometheus has no i2scim scrape job: $targets_json"
for peer in scim_cluster1 scim_cluster2; do
    echo "$targets_json" | grep -qE "\"scrapeUrl\":\"http://${peer}:8080/q/metrics\"" \
        || fail "i2scim job missing target ${peer}:8080/q/metrics"
done
# At least one of the two should be up=1 after warm-up. The script intentionally
# does not demand both up since a slow SCIM container should not fail the run.
echo "$targets_json" | grep -qE '"job":"i2scim".*"health":"up"' \
    || fail "no i2scim target is health=up in Prometheus"
ok "i2scim job present with both peers, at least one healthy"

echo "12) Existing {service=\"gosignals\"} query still returns rows..."
end_ns=$(date +%s)000000000
start_ns=$(( $(date +%s) - 600 ))000000000
query='%7Bservice%3D%22gosignals%22%7D'
resp=$(curl -fsS "${LOKI_URL}/loki/api/v1/query_range?query=${query}&limit=10&start=${start_ns}&end=${end_ns}")
echo "$resp" | grep -q '"status":"success"' \
    || fail "regression: gosignals LogQL query did not return success: $resp"
# Expect at least one stream in the result so we know existing logs still flow.
echo "$resp" | grep -q '"stream":' \
    || fail "regression: gosignals query returned no streams"
ok "no regression on goSignals log path"

echo ""
echo "All observability acceptance criteria passed."
