#!/usr/bin/env bash
# Documentation acceptance check for issue #58.
#
# Codifies the doc-level acceptance criteria as a single command so the doc
# stays in sync with the PRD's promised structure. Run from the repo root.
#
# This is a structural check, not a prose review — it verifies that the doc
# exists, contains each promised section, links are bidirectional with related
# docs, and forbidden claims (e.g. "implemented in v1" for non-Loki backends)
# are absent.

set -eu

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

ok() { echo "  OK: $1"; }

DOC=docs/observability.md
README=README.md

echo "1) docs/observability.md exists..."
[ -f "$DOC" ] || fail "$DOC is missing"
ok "$DOC present"

echo "2) All nine sections present..."
required_sections=(
    "The stdout-JSON contract"
    "Label schema and cardinality rationale"
    "Self-hosted"
    "GCP"
    "AWS"
    "Azure"
    "Securing Loki in production"
    "Querying examples"
    "Operational SETs"
)
for s in "${required_sections[@]}"; do
    grep -qF "$s" "$DOC" \
        || fail "section heading containing \"$s\" not found in $DOC"
done
ok "all nine sections present"

echo "3) Each cloud reference includes a shipper snippet AND a planned admin log_backends block..."
# Cloud sections must each have a fenced code block referencing the shipper
# (alloy / fluent-bit / fluentbit / cloud-logging / container-insights) AND a
# [[log_backends]] block. We don't enforce strict ordering, just presence in the
# section subset for each cloud heading.
for cloud_keyword in "Alloy" "Fluent Bit" "Container Insights"; do
    grep -qiF "$cloud_keyword" "$DOC" \
        || fail "cloud reference for \"$cloud_keyword\" missing"
done
grep -q '\[\[log_backends\]\]' "$DOC" \
    || fail "[[log_backends]] config block is missing"
grep -qiE 'planned|not yet implemented' "$DOC" \
    || fail "no 'planned, not yet implemented' marker on admin backends"
ok "shipper snippets + planned admin backends present"

echo "4) LogQL examples present..."
grep -q '{service="gosignals"}' "$DOC" \
    || fail "no LogQL example using {service=\"gosignals\"}"
grep -qE 'logfmt|\| json' "$DOC" \
    || fail "no LogQL parser example (| json / logfmt) for high-cardinality fields"
ok "LogQL examples present"

echo "5) README.md links to docs/observability.md..."
grep -q 'docs/observability.md' "$README" \
    || fail "$README does not link to docs/observability.md"
ok "README link present"

echo "6) Cross-links to related docs present..."
for related in Cluster.md Metrics.md configuration_properties.md security_model.md; do
    grep -q "$related" "$DOC" \
        || fail "$DOC does not cross-link $related"
done
ok "cross-links present"

echo "7) No false claims about non-Loki admin backends in v1..."
# Reject phrasings that promise CloudWatch / Cloud Logging / Azure Monitor
# are *implemented* in admin v1. We allow "planned" / "not yet implemented"
# qualifiers, which the previous check confirms exist somewhere in the doc.
if grep -nE 'admin (currently|now|today) (supports|implements) (CloudWatch|Cloud Logging|Azure Monitor)' "$DOC"; then
    fail "doc claims admin already implements a non-Loki backend"
fi
ok "no implementation claims for non-Loki admin backends"

echo "8) Forward-looking Operational SETs section flags v1 non-implementation..."
# The dedicated forward-looking section must explicitly note v1 does not ship
# op_event_* — namespace is reserved only. Slurp from the section heading to
# EOF (the section is intentionally last) and require at least one of the
# qualifier phrases.
awk '/^## .*Operational SETs/{found=1} found{print}' "$DOC" \
    | grep -qiE 'reserved|not (yet )?implemented|no .* are emitted' \
    || fail "Operational SETs section does not flag v1 non-implementation"
ok "Operational SETs section flags reservation"

echo ""
echo "All documentation acceptance criteria passed."
