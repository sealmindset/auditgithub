#!/usr/bin/env bash
# Reproduce the before/after table in the UI design-system report pair.
#
# "Before" is not a memory of what the code used to look like. It is the same
# committed auditor run against the tree as it stands at a git ref, so both
# columns are produced by identical logic and identical thresholds. Change the
# auditor and both columns move together; that is the point.
#
# The default ref is the branch point this work started from. Pass another ref
# to compare against something else.
#
#   ./scripts/report/ui-baseline-compare.sh [ref]
set -euo pipefail

cd "$(dirname "$0")/../.."
REF="${1:-HEAD}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

git archive "$REF" src/web-ui | tar -x -C "$WORK"
BASE="$WORK/src/web-ui"

# The auditors live outside the archived subtree at some refs, so copy today's
# in. This is deliberate: the comparison is "same ruler, two trees".
mkdir -p "$BASE/scripts"
cp src/web-ui/scripts/audit-ui.py src/web-ui/scripts/check-contrast.py "$BASE/scripts/"

echo "=============================================================="
echo "BEFORE  (git $REF, measured with today's auditors)"
echo "=============================================================="
( cd "$BASE" && python3 scripts/audit-ui.py ) || true
echo
( cd "$BASE" && python3 scripts/check-contrast.py | tail -1 ) || true

echo
echo "=============================================================="
echo "AFTER   (working tree)"
echo "=============================================================="
( cd src/web-ui && python3 scripts/audit-ui.py ) || true
echo
( cd src/web-ui && python3 scripts/check-contrast.py | tail -1 ) || true
