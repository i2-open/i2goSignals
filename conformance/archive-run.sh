#!/usr/bin/env bash
#
# Collapse the artifacts of the most recent conformance run into a single zip and
# prune results/ back to just a copy of that run's Markdown summary.
#
# run-all-plans.sh leaves a pile of loose artifacts in results/: the aggregate
# `run-<ts>.md` summary, one `run-<ts>-<plan>.log` per plan, the per-plan signed
# export zips, and the rx-driver / runner-tap / trigger-caep driver logs. After a
# matrix run you almost always only want to *read* the summary; everything else is
# drill-down detail kept just in case. This bundles that pile into one
# `run-<ts>-archive.zip` and leaves the summary sitting next to it so the directory
# stays legible run-over-run.
#
# Wired in as the final step of `make all`. Safe to run by hand at any time, and a
# no-op if there is nothing to archive. Subdirectories under results/ (e.g. a manual
# archive-*/ snapshot) and any previously written *-archive.zip are left untouched.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"

cd "$RESULTS_DIR" 2>/dev/null || { echo "==> archive-run: no results/ directory, nothing to do"; exit 0; }

# Newest aggregate summary == the run we just finished; its name stamps the archive.
summary="$(ls -t run-*.md 2>/dev/null | head -1 || true)"
if [[ -z "$summary" ]]; then
    echo "==> archive-run: no run-*.md summary in results/, nothing to archive"
    exit 0
fi
archive="${summary%.md}-archive.zip"

# Gather every loose top-level artifact except the .gitignore and any prior archive.
# Glob skips dotfiles and (with the type check) directories, so subdir snapshots and
# the .gitignore survive. The newest summary is included so the bundle is complete.
shopt -s nullglob
loose=()
for f in *; do
    [[ -f "$f" ]] || continue
    [[ "$f" == *-archive.zip ]] && continue
    loose+=("$f")
done

if [[ "${#loose[@]}" -eq 0 ]]; then
    echo "==> archive-run: results/ already clean (only $summary present)"
    exit 0
fi

# Build the archive, then delete every loose artifact except the summary we keep.
rm -f "$archive"
zip -q "$archive" "${loose[@]}"
for f in "${loose[@]}"; do
    [[ "$f" == "$summary" ]] && continue
    rm -f "$f"
done

echo "==> archive-run: bundled ${#loose[@]} artifact(s) into results/$archive"
echo "    kept a copy of the summary: results/$summary"
