#!/usr/bin/env sh
# register.sh — Register SPIRE workload entries for all i2goSignals services.

set -e

SPIRE_CLI="/usr/local/bin/spire-server"
SOCKET="/run/spire/sockets/registration.sock"
TRUST_DOMAIN="cluster.i2gosignals.internal"

# Wait for server to be ready for CLI calls
echo "Waiting for SPIRE server at $SOCKET..."
until $SPIRE_CLI healthcheck -socketPath "$SOCKET" >/dev/null 2>&1; do
    sleep 2
done

get_agent_id() {
    # Pick the LATEST agent ID from the server. This handles cases where old agents
    # persist in the database after a partial environment reset.
    # We use the standard output format and parse the SPIFFE ID line.
    $SPIRE_CLI agent list -socketPath "$SOCKET" 2>/dev/null \
        | grep "SPIFFE ID" | tail -1 | awk -F': ' '{print $2}' | xargs echo
}

# Wait for an agent to join (with a timeout)
echo "Waiting for SPIRE agent to join (attest)..."
MAX_RETRIES=30
RETRY_COUNT=0
AGENT_ID=""

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    AGENT_ID=$(get_agent_id)
    if [ -n "$AGENT_ID" ]; then
        break
    fi
    RETRY_COUNT=$((RETRY_COUNT + 1))
    echo "  (No agent found yet, retry $RETRY_COUNT/$MAX_RETRIES...)"
    sleep 2
done

if [ -z "$AGENT_ID" ]; then
    echo "ERROR: timed out waiting for SPIRE agent to join the server." >&2
    echo "Current agent list (raw):" >&2
    $SPIRE_CLI agent list -socketPath "$SOCKET" >&2
    exit 1
fi
echo "Using agent SPIFFE ID: $AGENT_ID"

# Cleanup: remove ALL existing entries before re-registering.
# This ensures we have a clean state and every entry uses the current AGENT_ID.
echo "Cleaning up all existing workload entries..."
$SPIRE_CLI entry show -socketPath "$SOCKET" | grep "Entry ID" | awk '{print $4}' | xargs -I {} $SPIRE_CLI entry delete -socketPath "$SOCKET" -entryID {} || true

register_workload() {
    SPIFFE_PATH=$1
    shift
    echo "Registering spiffe://${TRUST_DOMAIN}/$SPIFFE_PATH..."
    for SELECTOR in "$@"; do
        echo "  Adding selector: $SELECTOR"
        $SPIRE_CLI entry create \
            -socketPath "$SOCKET" \
            -spiffeID "spiffe://${TRUST_DOMAIN}/$SPIFFE_PATH" \
            -parentID "$AGENT_ID" \
            -selector "$SELECTOR" >/dev/null \
            || echo "  (Error creating entry for $SPIFFE_PATH with $SELECTOR)"
    done
}

# Same as register_workload but sets a per-entry x509 SVID TTL.
# Used for workloads (e.g. MongoDB) that cannot hot-reload their TLS cert.
# The TTL should match ca_ttl in server.conf so the cert remains valid for
# the full lifetime of the process without requiring a restart.
register_workload_with_ttl() {
    SPIFFE_PATH=$1
    TTL=$2
    shift 2
    echo "Registering spiffe://${TRUST_DOMAIN}/$SPIFFE_PATH (x509SVIDTTL=${TTL})..."
    for SELECTOR in "$@"; do
        echo "  Adding selector: $SELECTOR"
        $SPIRE_CLI entry create \
            -socketPath "$SOCKET" \
            -spiffeID "spiffe://${TRUST_DOMAIN}/$SPIFFE_PATH" \
            -parentID "$AGENT_ID" \
            -x509SVIDTTL "$TTL" \
            -selector "$SELECTOR" >/dev/null \
            || echo "  (Error creating entry for $SPIFFE_PATH with $SELECTOR)"
    done
}

# ----------------------------------------------------------------------------
# Core Services
# ----------------------------------------------------------------------------

# goSignals nodes (cluster components)
register_workload "workload/gosignals-node" \
    "docker:label:com.i2gosignals.role:gosignals-node" \
    "docker:container_name:gosignals1" \
    "docker:container_name:gosignals2" \
    "docker:container_name:goSignals1" \
    "docker:container_name:goSignals2"

# goSsfServer (security event publisher)
register_workload "workload/gossf-node" \
    "docker:label:com.i2gosignals.role:gossf-node" \
    "docker:container_name:gossfserver" \
    "docker:container_name:goSsfServer"

# MongoDB Replica Set & Initialization.
# SVIDs use the server default TTL (1h). The mongo_spiffe_init.sh renewal loop
# calls db.adminCommand({rotateCertificates:1}) on each node after writing
# updated cert files, enabling hot reload of both the server cert and CA bundle
# without restarting mongod. See docs/spiffe_support.md for details.
register_workload "workload/mongodb" \
    "docker:label:com.i2gosignals.role:mongodb" \
    "docker:container_name:mongo-init" \
    "docker:container_name:mongo1" \
    "docker:container_name:mongo2" \
    "docker:container_name:mongo3" \
    "unix:uid:0" \
    "unix:uid:999"

# ----------------------------------------------------------------------------
# Infrastructure & Monitoring
# ----------------------------------------------------------------------------

# Databases & IAM
register_workload "workload/postgres" \
    "docker:container_name:postgres" \
    "docker:label:com.i2gosignals.role:postgres"

register_workload "workload/keycloak" \
    "docker:container_name:keycloak-signals" \
    "docker:container_name:keycloak"

# Monitoring Stack
register_workload "workload/prometheus" \
    "docker:container_name:prometheus"

register_workload "workload/grafana" \
    "docker:container_name:grafana"

# ----------------------------------------------------------------------------
# SCIM Services
# ----------------------------------------------------------------------------
register_workload "workload/scim" \
    "docker:container_name:scim-ssf-setup" \
    "docker:container_name:scimSsfSetup" \
    "docker:container_name:scim_cluster1" \
    "docker:container_name:scim_cluster2"

echo ""
echo "Registration complete. Final entry list for agent $AGENT_ID:"
$SPIRE_CLI entry show -socketPath "$SOCKET" | grep -B 2 "$AGENT_ID"

# ----------------------------------------------------------------------------
# Federation bootstrap (cross-domain) — uncomment and adapt for each partner:
#
# To federate with a partner SSF deployment:
# 1. On our SPIRE server:
#      docker exec spire-server /usr/local/bin/spire-server bundle show \
#          -socketPath /run/spire/sockets/registration.sock \
#          -format spiffe > our-bundle.json
#    Send our-bundle.json to the partner out-of-band.
#
# 2. On the partner's SPIRE server (they run):
#      spire-server bundle set \
#          -format spiffe \
#          -id spiffe://cluster.i2gosignals.internal \
#          < our-bundle.json
#
# 3. Receive the partner's bundle and import it:
#      $SPIRE_CLI bundle set \
#          -socketPath "$SOCKET" \
#          -format spiffe \
#          -id spiffe://partner.example.com \
#          < partner-bundle.json
#
# 4. Register a federated workload entry:
#      $SPIRE_CLI entry create \
#          -socketPath "$SOCKET" \
#          -spiffeID "spiffe://${TRUST_DOMAIN}/workload/gosignals-node" \
#          -parentID "$AGENT_ID" \
#          -selector "docker:label:com.i2gosignals.role:gosignals-node" \
#          -federatesWith "spiffe://partner.example.com"
# ----------------------------------------------------------------------------
