#!/usr/bin/env bash
#
# Mint the bearer token the OpenID conformance suite uses (ssf.transmitter.access_token)
# and write a ready-to-import suite config at suite-configs/ssf-transmitter-gosignals.local.json.
#
# The suite (STATIC auth mode) presents this one token for BOTH stream management
# and /poll. goSignals requires `stream` (or admin) for management and `event`
# for /poll, so the token MUST carry both `stream` and `event`.
#
# Token source, in priority order:
#   1. bootstrap /iat -> /register, requesting scopes "$SCOPES" (default
#      "stream event"). As of v0.12.0-alpha.2, /register mints `event` into the
#      registered client token, so this single token drives BOTH stream
#      management and /poll. This is the default path.
#   2. $GOSIGNALS_TOKEN   - a pre-minted bearer you supply, used verbatim. Use
#      this to test with a token minted out-of-band.
#
# Usage:
#   ./bootstrap-token.sh                       # default /iat -> /register flow
#   GOSIGNALS_TOKEN="eyJ..." ./bootstrap-token.sh   # use a supplied stream+event token
#
# Env:
#   GOSIGNALS_URL    default https://localhost.emobix.co.uk:9443
#   BOOTSTRAP_TOKEN  default dev-bootstrap-secret  (must match I2SIG_BOOTSTRAP_TOKEN)
#   SCOPES           default "stream event"
set -euo pipefail

GOSIGNALS_URL="${GOSIGNALS_URL:-https://localhost.emobix.co.uk:9443}"
BOOTSTRAP_TOKEN="${BOOTSTRAP_TOKEN:-dev-bootstrap-secret}"
SCOPES="${SCOPES:-stream event}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="$SCRIPT_DIR/suite-configs/ssf-transmitter-gosignals.json"
OUT="$SCRIPT_DIR/suite-configs/ssf-transmitter-gosignals.local.json"

# --- JSON helpers (jq preferred, python3 fallback) -------------------------
json_field() { # json_field <field>   (reads stdin)
  if command -v jq >/dev/null 2>&1; then
    jq -r ".$1 // empty"
  else
    python3 -c "import sys,json;print(json.load(sys.stdin).get('$1',''))"
  fi
}
scopes_json_array() { # "stream event" -> ["stream","event"]
  if command -v jq >/dev/null 2>&1; then
    printf '%s' "$SCOPES" | jq -R 'split(" ") | map(select(length>0))'
  else
    python3 -c "import sys,json;print(json.dumps(sys.argv[1].split()))" "$SCOPES"
  fi
}

TOKEN="${GOSIGNALS_TOKEN:-}"

if [[ -n "$TOKEN" ]]; then
  echo ">> Using supplied GOSIGNALS_TOKEN (assumed to carry: $SCOPES)"
else
  echo ">> Minting IAT via $GOSIGNALS_URL/iat (bootstrap bearer)"
  # /iat is a GET in goSignals (routers.go: GenerateIat, http.MethodGet).
  IAT="$(curl -sk -X GET "$GOSIGNALS_URL/iat" \
          -H "Authorization: Bearer $BOOTSTRAP_TOKEN" | json_field token)"
  if [[ -z "$IAT" ]]; then
    echo "ERROR: failed to obtain IAT (check BOOTSTRAP_TOKEN / server up)." >&2
    exit 1
  fi

  echo ">> Registering client via $GOSIGNALS_URL/register (scopes: $SCOPES)"
  BODY="$(printf '{"email":"ssf-conformance@example.com","description":"OIDF SSF conformance","scopes":%s}' "$(scopes_json_array)")"
  TOKEN="$(curl -sk -X POST "$GOSIGNALS_URL/register" \
            -H "Authorization: Bearer $IAT" \
            -H "Content-Type: application/json" \
            -d "$BODY" | json_field token)"
  if [[ -z "$TOKEN" ]]; then
    echo "ERROR: registration returned no token." >&2
    exit 1
  fi
fi

# --- write the suite config with the token substituted ---------------------
sed "s|__GOSIGNALS_STREAM_EVENT_TOKEN__|$TOKEN|" "$TEMPLATE" > "$OUT"

echo
echo ">> Access token:"
echo "$TOKEN"
echo
echo ">> Wrote suite config: $OUT"
echo "   Import it on the conformance suite's schedule-test page, or pass it to"
echo "   .gitlab-ci/run-tests.sh as the transmitter config path."
