#!/usr/bin/env bash
#
# Read-only capture of a real cluster (CONTEXT, required), compared with the
# previous capture. Nothing on the
# cluster is changed: capture only lists and reads.
#
# Output goes to .truthform/<context>/ (gitignored). The previous capture is
# kept as .truthform/<context>.prev so each run shows:
#   - which objects changed since last time (compare)
#   - which API fields appeared or disappeared (schema-diff), for example
#     after upgrading the platform or an operator on it
set -euo pipefail

CONTEXT=${CONTEXT:?set CONTEXT to the kube context to capture, e.g. CONTEXT=kind-mycluster}
BIN=${BIN:-bin/truthform}
cd "$(dirname "$0")/.."

out=".truthform/$CONTEXT"
prev=".truthform/$CONTEXT.prev"
mkdir -p .truthform
if [ -f "$out/snapshot.yaml" ]; then
  rm -rf "$prev"
  mv "$out" "$prev"
fi

"$BIN" capture --context "$CONTEXT" --out "$out"

# compare and schema-diff exit 2 when they find differences, which here is the
# expected report, not a failure. Any other non-zero (1: could not read a
# snapshot) must still fail the run; a bare "|| true" would hide it.
allow_diff() { "$@" || { rc=$?; [ "$rc" -eq 2 ] || exit "$rc"; }; }

if [ -f "$prev/snapshot.yaml" ]; then
  echo "== objects changed since the previous capture"
  allow_diff "$BIN" compare "$prev" "$out"
  echo "== API fields added or removed since the previous capture"
  allow_diff "$BIN" schema-diff "$prev" "$out"
else
  echo "first capture of $CONTEXT; the next run will compare against it"
fi
