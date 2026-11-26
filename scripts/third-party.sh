#!/usr/bin/env bash
# The licences of what is compiled into a TruthForm binary: Go itself and
# every module, on every platform a release is built for.
#
#   scripts/third-party.sh               # check only
#   scripts/third-party.sh NOTICES.txt   # check, and write the notices file
#
# The check fails when a module's licence is not on the list below. Every
# licence on it lets a binary be handed on under any terms, provided the
# licence text goes with it; the notices file is that text, and each
# release archive carries it. A copyleft or unrecognised licence would ask
# for more than that, so it stops here for a person to read.
set -euo pipefail

ALLOWED="Apache-2.0,MIT,BSD-3-Clause,BSD-2-Clause,ISC"
# Pinned: the tool decides what counts as which licence.
TOOL="github.com/google/go-licenses/v2@v2.0.1"
# What build-release.sh builds for. Modules differ by platform (the
# keychain on each, for one), so each is read.
PLATFORMS="linux darwin windows"
OWN="github.com/usetruthform/core"
OUT="${1:-}"

tmp="$(mktemp -d)"
trap 'chmod -R u+w "$tmp" 2>/dev/null; rm -rf "$tmp"' EXIT
# Built here with the Go in use: the tool tells the standard library apart
# by this Go's GOROOT, and one built by another Go takes it for modules
# without a licence.
GOBIN="$tmp/bin" GOOS= GOARCH= go install "$TOOL"

for os in $PLATFORMS; do
  # Warnings (assembly files it cannot read for imports) are kept quiet;
  # a failure prints them.
  if ! GOOS="$os" "$tmp/bin/go-licenses" check ./cmd/truthform \
      --allowed_licenses="$ALLOWED" --ignore "$OWN" 2>"$tmp/check.log"; then
    cat "$tmp/check.log" >&2
    echo "third-party: a module built for $os has a licence outside: $ALLOWED" >&2
    exit 1
  fi
  [ -z "$OUT" ] && continue
  GOOS="$os" "$tmp/bin/go-licenses" save ./cmd/truthform \
    --save_path "$tmp/save-$os" --ignore "$OWN" 2>"$tmp/save.log" || { cat "$tmp/save.log" >&2; exit 1; }
  # Saved read-only, as the module cache holds them: the next platform's
  # copy of the same file could not replace it.
  chmod -R u+w "$tmp/save-$os"
  mkdir -p "$tmp/all"
  cp -R "$tmp/save-$os/." "$tmp/all/"
done
if [ -z "$OUT" ]; then
  echo "third-party: every module's licence is one of: $ALLOWED"
  exit 0
fi

{
  echo "TruthForm includes the software below. Each part is under its own"
  echo "licence, reproduced here as that licence asks."
  echo
  echo "================================================================"
  echo "Go (the standard library and runtime)"
  echo "================================================================"
  echo
  cat "$(go env GOROOT)/LICENSE"
  # Sorted by path with a fixed locale: the same file from the same commit.
  (cd "$tmp/all" && find . -type f | LC_ALL=C sort) | while read -r f; do
    f="${f#./}"
    echo
    echo "================================================================"
    echo "${f%/*} (${f##*/})"
    echo "================================================================"
    echo
    cat "$tmp/all/$f"
  done
} > "$OUT"
echo "third-party: wrote $OUT"
