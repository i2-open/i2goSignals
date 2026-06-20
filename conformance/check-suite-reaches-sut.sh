#!/usr/bin/env bash
#
# Preflight gate: assert the OpenID conformance suite can actually FETCH the
# SUT's transmitter metadata. This is the check whose absence let a silent
# networking break produce "8/8 interrupted" runs (2026-06-20).
#
# Why it can break: the suite, when run in Docker, fetches the SUT at
# https://localhost.emobix.co.uk:9443/...  `localhost.emobix.co.uk` is real
# public DNS that resolves to 127.0.0.1 — which, inside the suite's `server`
# container, is the CONTAINER's own loopback, not the host where the SUT is
# published. Result: "Connection refused" and every transmitter module
# interrupts at OIDSSFGetDynamicTransmitterConfiguration.
#
# Fix: bring the suite up with conformance/suite-overlay.yml, which maps
# localhost.emobix.co.uk -> host-gateway in the server container (`make suite-up`).
#
# This script execs curl INSIDE the suite server container (the only place the
# real fetch happens). If the suite runs natively on the host instead of in
# Docker, 127.0.0.1 already is the host, so it skips with a note.
#
# Usage:  ./check-suite-reaches-sut.sh [<metadata-path>]
# Env:
#   SUITE_SERVER       suite server container name (auto-discovered by default)
#   SUT_URL_INTERNAL   default https://localhost.emobix.co.uk:9443
set -euo pipefail

SUT_PATH="${1:-/.well-known/ssf-configuration}"
SUT_URL_INTERNAL="${SUT_URL_INTERNAL:-https://localhost.emobix.co.uk:9443}"
SUITE_SERVER="${SUITE_SERVER:-$(docker ps --filter "name=openid-conformance-suite-server" --format '{{.Names}}' | head -1)}"

if [[ -z "$SUITE_SERVER" ]]; then
    echo "    net-check: no Dockerized suite server container found." >&2
    echo "    net-check: if the suite runs natively, localhost.emobix.co.uk->127.0.0.1 already" >&2
    echo "    net-check: reaches the host-published SUT; skipping in-container reachability check." >&2
    exit 0
fi

code="$(docker exec "$SUITE_SERVER" curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "$SUT_URL_INTERNAL$SUT_PATH" 2>/dev/null || echo 000)"
if [[ "$code" == "200" ]]; then
    echo "    net-check: suite ($SUITE_SERVER) reaches SUT $SUT_URL_INTERNAL$SUT_PATH (HTTP $code) — OK"
    exit 0
fi

cat >&2 <<EOF
ERROR: the conformance suite cannot reach the SUT.
       container : $SUITE_SERVER
       url       : $SUT_URL_INTERNAL$SUT_PATH
       result    : HTTP $code (000 = connection refused/timeout)

       The Dockerized suite resolves localhost.emobix.co.uk to its own loopback,
       so the SUT (published on the host at 127.0.0.1:9443) is invisible to it.
       Bring the suite up with the networking overlay:

           make suite-up

       (adds 'extra_hosts: localhost.emobix.co.uk:host-gateway' to the suite
       server via conformance/suite-overlay.yml). See README.md "Networking".
EOF
exit 1
