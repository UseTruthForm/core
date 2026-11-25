#!/usr/bin/env bash
#
# Upgrade compatibility: does this build read the snapshots the last release
# wrote, and does the last release read this build's? Run before every tag;
# the release notes say what it found.
#
#   1. build the last release (PREV, the newest tag by default) and this tree
#   2. run every restore drill in both trees with TRUTHFORM_KEEP_SNAPSHOTS
#      set, so each build writes a snapshot per platform from the same fakes
#      (Kubernetes from a real API server, when TRUTHFORM_KUBE_ASSETS is set)
#   3. have each build compare the other's snapshot with its own
#
# A build that cannot read the other's snapshot fails the run (compare exits
# 1). Differences are printed and do not fail it: a change of capture rules
# may be meant, and belongs in the release notes. The last release refusing
# a snapshot under capture rules newer than its own is by design: printed as
# REFUSED, it does not fail the run, and the notes must say there is no
# going back to that release with such a snapshot. It makes no request and
# touches nothing but WORK. Usage:
#   scripts/compat.sh                 # against the newest tag
#   PREV=v0.1.0-beta.22 scripts/compat.sh
set -uo pipefail

cd "$(dirname "$0")/.."
PREV=${PREV:-$(git tag --sort=-creatordate | head -1)}
WORK=${WORK:-$(mktemp -d)}
PKGS="./internal/awscc ./internal/azarm ./internal/gcp ./internal/saas ./internal/kube"
HOOK=internal/drilltest/drilltest.go

echo "== this tree against $PREV (work: $WORK)"
git worktree add -q --detach "$WORK/prev-tree" "$PREV" || exit 1
trap 'git worktree remove --force "$WORK/prev-tree" >/dev/null 2>&1' EXIT

# A release from before the drill kept its snapshots is given this tree's
# drill helper: it is test code, and writes with that build's own snapshot
# package.
if ! grep -q TRUTHFORM_KEEP_SNAPSHOTS "$WORK/prev-tree/$HOOK"; then
  echo "   $PREV does not keep drill snapshots; using this tree's drill helper there"
  cp "$HOOK" "$WORK/prev-tree/$HOOK"
fi

go build -o "$WORK/new" ./cmd/truthform || exit 1
(cd "$WORK/prev-tree" && go build -o "$WORK/prev" ./cmd/truthform) || exit 1

echo "== drills write their snapshots"
TRUTHFORM_KEEP_SNAPSHOTS="$WORK/snap-new" go test -count=1 -run 'Drill' $PKGS >"$WORK/drill-new.log" 2>&1 ||
  { tail -30 "$WORK/drill-new.log"; echo "this tree's drills failed"; exit 1; }
(cd "$WORK/prev-tree" && TRUTHFORM_KEEP_SNAPSHOTS="$WORK/snap-prev" go test -count=1 -run 'Drill' $PKGS) >"$WORK/drill-prev.log" 2>&1 ||
  { tail -30 "$WORK/drill-prev.log"; echo "$PREV's drills failed"; exit 1; }

fail=0
check() { # label binary theirs ours
  local out code
  out=$("$2" compare "$3" "$4" 2>&1); code=$?
  case $code in
    0) printf '   ok        %s\n' "$1" ;;
    2) printf '   DIFFERS   %s\n' "$1"; printf '%s\n' "$out" | sed 's/^/               /' | head -12 ;;
    *) # A snapshot under capture rules newer than a build's own is
       # refused by design. It still means no going back to that build:
       # the release notes must say so.
       if [ "$2" = "$WORK/prev" ] && printf '%s' "$out" | grep -q 'read it with a newer TruthForm'; then
         printf '   REFUSED   %s: newer capture rules, as designed; say in the notes that %s cannot read it\n' "$1" "$PREV"
         refused=1
       else
         printf '   CANNOT READ  %s\n' "$1"; printf '%s\n' "$out" | sed 's/^/               /' | head -6; fail=1
       fi ;;
  esac
}
for d in "$WORK"/snap-new/*/; do
  n=$(basename "$d")
  platform=$(sed -n 's/^platform: //p' "$d/snapshot.yaml")
  if [ ! -d "$WORK/snap-prev/$n" ]; then
    printf '   new drill %s (%s): %s has none to compare\n' "$n" "$platform" "$PREV"
    out=$("$WORK/prev" compare "$d" "$d" 2>&1) && printf '   ok        %s reads this build'"'"'s %s (%s)\n' "$PREV" "$n" "$platform" ||
      { printf '   CANNOT READ  %s reads this build'"'"'s %s (%s)\n%s\n' "$PREV" "$n" "$platform" "$out"; fail=1; }
    continue
  fi
  check "this build reads $PREV's $n ($platform)" "$WORK/new" "$WORK/snap-prev/$n" "$d"
  check "$PREV reads this build's $n ($platform)" "$WORK/prev" "$d" "$WORK/snap-prev/$n"
done
if [ $fail != 0 ]; then
  echo "== NOT COMPATIBLE: see CANNOT READ above"
elif [ "${refused:-0}" = 1 ]; then
  echo "== this build reads $PREV's snapshots; $PREV refuses those marked REFUSED above (newer capture rules)"
else
  echo "== each build reads the other's snapshots"
fi
exit $fail
