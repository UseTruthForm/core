#!/usr/bin/env bash
# Builds the release binaries: every platform a customer runs StackDNA on,
# in two editions each.
#
#   full          capture, diff and restore
#   capture-only  restore disabled and every request behind the read-only
#                 guard: the binary to hand a client for information
#                 gathering, which cannot write to anything it reaches
#
# Each binary is stamped with the version, commit and build time (stackdna
# version prints them), stripped, and built without cgo, so it is one file
# with nothing to install. Archives (zip for Windows, tar.gz elsewhere) and
# SHA256SUMS go in dist/.
#
#   scripts/build-release.sh v0.1.0
#   NO_ARCHIVE=1 scripts/build-release.sh v0.1.0-test   # binaries only
set -euo pipefail

VERSION="${1:?usage: scripts/build-release.sh <version, e.g. v0.1.0>}"
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || { echo "version must look like v0.1.0 or v0.1.0-beta.1, not $VERSION" >&2; exit 1; }
COMMIT="$(git rev-parse --short=12 HEAD)"
BUILT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# A release built from uncommitted changes could not be traced to source.
if [ -n "$(git status --porcelain -- cmd internal go.mod go.sum)" ] && [ -z "${ALLOW_DIRTY:-}" ]; then
  echo "uncommitted changes in the source; commit them (or ALLOW_DIRTY=1 for a local test build)" >&2
  exit 1
fi
OUT="${OUT:-dist}"
rm -rf "$OUT"; mkdir -p "$OUT"

TARGETS="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"
for target in $TARGETS; do
  os="${target%/*}"; arch="${target#*/}"
  for edition in full capture-only; do
    name="stackdna_${VERSION#v}_${os}_${arch}"
    tags=()
    if [ "$edition" = capture-only ]; then
      name="${name}_capture-only"; tags=(-tags captureonly)
    fi
    exe=stackdna; [ "$os" = windows ] && exe=stackdna.exe
    mkdir -p "$OUT/$name"
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath "${tags[@]}" \
      -ldflags "-s -w -X main.version=$VERSION -X main.commit=$COMMIT -X main.built=$BUILT" \
      -o "$OUT/$name/$exe" ./cmd/stackdna
    cp README.md "$OUT/$name/"
    [ -n "${NO_ARCHIVE:-}" ] && continue
    if [ "$os" = windows ]; then
      (cd "$OUT" && zip -qr "$name.zip" "$name")
    else
      tar -C "$OUT" -czf "$OUT/$name.tar.gz" "$name"
    fi
    rm -rf "${OUT:?}/$name"
  done
done
if [ -z "${NO_ARCHIVE:-}" ]; then
  (cd "$OUT" && sha256sum -- *.zip *.tar.gz > SHA256SUMS)
fi
ls -l "$OUT"
