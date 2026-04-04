#!/usr/bin/env sh
# register.sh — Register SPIRE workload entries for all i2goSignals services.
#
# Run this script after the SPIRE server and agent have started:
#   docker exec spire-server sh /etc/spire/registration/register.sh
#
# The script is idempotent: re-running it updates existing entries.

set -e

SPIRE_CLI="/opt/spire/bin/spire-server"
SOCKET="/tmp/spire-registration.sock"
TRUST_DOMAIN="cluster.i2gosignals.internal"

# ----------------------------------------------------------------------------
# Helper: get the SPIRE agent SPIFFE ID (used as parent for workload entries)
# ----------------------------------------------------------------------------
get_agent_id() {
    # With join_token attestation the agent ID is derived from the join token.
    # With docker attestation it is derived from the container ID.
    # Fall back to querying the live agent list.
    $SPIRE_CLI agent list -registrationUDSPath "$SOCKET" 2>/dev/null \
        | grep "SPIFFE ID" | head -1 | awk '{print $3}'
}

AGENT_ID=$(get_agent_id)
if [ -z "$AGENT_ID" ]; then
    echo "ERROR: no SPIRE agents found. Has the agent joined the server?" >&2
    exit 1
fi
echo "Using agent SPIFFE ID: $AGENT_ID"

# ----------------------------------------------------------------------------
# goSignals node (push/poll transmitter, inter-cluster wakeup)
# ----------------------------------------------------------------------------
echo "Registering gosignals-node..."
$SPIRE_CLI entry create \
    -registrationUDSPath "$SOCKET" \
    -spiffeID "spiffe://${TRUST_DOMAIN}/workload/gosignals-node" \
    -parentID "$AGENT_ID" \
    -selector "docker:label:com.i2gosignals.role:gosignals-node" \
    -ttl 3600 \
    || echo "(entry may already exist)"

# ----------------------------------------------------------------------------
# goSsfServer node
# ----------------------------------------------------------------------------
echo "Registering gossf-node..."
$SPIRE_CLI entry create \
    -registrationUDSPath "$SOCKET" \
    -spiffeID "spiffe://${TRUST_DOMAIN}/workload/gossf-node" \
    -parentID "$AGENT_ID" \
    -selector "docker:label:com.i2gosignals.role:gossf-node" \
    -ttl 3600 \
    || echo "(entry may already exist)"

# ----------------------------------------------------------------------------
# MongoDB nodes (mTLS client certificate for database connections)
# Currently registered to allow any workload to act as a MongoDB client;
# tighten with specific selectors in production.
# ----------------------------------------------------------------------------
# echo "Registering mongodb-client..."
# $SPIRE_CLI entry create \
#     -registrationUDSPath "$SOCKET" \
#     -spiffeID "spiffe://${TRUST_DOMAIN}/workload/mongodb-client" \
#     -parentID "$AGENT_ID" \
#     -selector "docker:label:com.i2gosignals.role:gosignals-node" \
#     -ttl 3600 \
#     || echo "(entry may already exist)"

echo ""
echo "Registration complete. Listing all entries:"
$SPIRE_CLI entry show -registrationUDSPath "$SOCKET"

# ----------------------------------------------------------------------------
# Federation bootstrap (cross-domain) — uncomment and adapt for each partner:
#
# To federate with a partner SSF deployment:
# 1. On our SPIRE server:
#      docker exec spire-server /opt/spire/bin/spire-server bundle show \
#          -registrationUDSPath /tmp/spire-registration.sock \
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
#          -registrationUDSPath "$SOCKET" \
#          -format spiffe \
#          -id spiffe://partner.example.com \
#          < partner-bundle.json
#
# 4. Register a federated workload entry:
#      $SPIRE_CLI entry create \
#          -registrationUDSPath "$SOCKET" \
#          -spiffeID "spiffe://${TRUST_DOMAIN}/workload/gosignals-node" \
#          -parentID "$AGENT_ID" \
#          -selector "docker:label:com.i2gosignals.role:gosignals-node" \
#          -federatesWith "spiffe://partner.example.com"
# ----------------------------------------------------------------------------
