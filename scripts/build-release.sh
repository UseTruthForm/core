#!/usr/bin/env bash
# Builds the release binaries: every platform a customer runs TruthForm on,
# in two editions each.
#
#   full          capture, diff and restore
#   capture-only  restore disabled and every request behind the read-only
#                 guard: the binary to hand a client for information
#                 gathering, which cannot write to anything it reaches
#
# Each binary is stamped with the version, commit and build time (truthform
# version prints them), stripped, and built without cgo, so it is one file
# with nothing to install. Archives (zip for Windows, tar.gz elsewhere) and
# SHA256SUMS go in dist/. Each archive carries TruthForm's LICENSE and
# NOTICE, and THIRD_PARTY_NOTICES.txt, the licences of Go and of every module in the
# binary, which those licences ask to travel with it.
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
# An unset variable builds binaries that cannot sign in to Cloudflare, with
# nothing else wrong with them. The release workflow refuses that; a local
# run only warns, because a test build needs no sign-in.
if [ -z "${TRUTHFORM_CLOUDFLARE_CLIENT_ID:-}" ]; then
  echo "WARNING: TRUTHFORM_CLOUDFLARE_CLIENT_ID is not set: these binaries will have no Cloudflare sign-in" >&2
fi

# Before anything is built: a module under a licence nobody has read stops
# the release. Binaries-only test builds are handed to nobody and skip it.
NOTICES=""
if [ -z "${NO_ARCHIVE:-}" ]; then
  NOTICES="$(mktemp)"
  bash "$(dirname "$0")/third-party.sh" "$NOTICES"
fi

TARGETS="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"
for target in $TARGETS; do
  os="${target%/*}"; arch="${target#*/}"
  for edition in full capture-only; do
    name="truthform_${VERSION#v}_${os}_${arch}"
    tags=()
    if [ "$edition" = capture-only ]; then
      name="${name}_capture-only"; tags=(-tags captureonly)
    fi
    exe=truthform; [ "$os" = windows ] && exe=truthform.exe
    mkdir -p "$OUT/$name"
    # ${tags[@]+...}: an empty array under set -u aborts macOS's bash 3.2.
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath ${tags[@]+"${tags[@]}"} \
      -ldflags "-s -w -X main.version=$VERSION -X main.commit=$COMMIT -X main.built=$BUILT -X github.com/usetruthform/core/internal/saas.CloudflareClientID=${TRUTHFORM_CLOUDFLARE_CLIENT_ID:-}" \
      -o "$OUT/$name/$exe" ./cmd/truthform
    # The user's README and guides, not the repository's README: that one
    # is for people building TruthForm (the dev loop, drills), and an
    # archive should explain itself without a trip to the repository.
    cp packaging/README.md "$OUT/$name/README.md"
    cp LICENSE NOTICE "$OUT/$name/"
    [ -n "$NOTICES" ] && cp "$NOTICES" "$OUT/$name/THIRD_PARTY_NOTICES.txt"
    mkdir -p "$OUT/$name/docs"
    cp docs/guide.md docs/permissions.md docs/agents.md "$OUT/$name/docs/"
    [ -n "${NO_ARCHIVE:-}" ] && continue
    if [ "$os" = windows ]; then
      # zip is not on every machine (Git Bash on Windows lacks it).
      if command -v zip >/dev/null; then
        (cd "$OUT" && zip -qr "$name.zip" "$name")
      else
        (cd "$OUT" && { python3 -m zipfile -c "$name.zip" "$name" 2>/dev/null || python -m zipfile -c "$name.zip" "$name"; })
      fi
    else
      tar -C "$OUT" -czf "$OUT/$name.tar.gz" "$name"
    fi
    rm -rf "${OUT:?}/$name"
  done
done
if [ -z "${NO_ARCHIVE:-}" ]; then
  (cd "$OUT" && sha256sum -- *.zip *.tar.gz > SHA256SUMS)
  rm -f "$NOTICES"
fi
ls -l "$OUT"
