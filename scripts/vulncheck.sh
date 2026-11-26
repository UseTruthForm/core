#!/usr/bin/env bash
# Scans the binary a customer runs for known vulnerabilities in Go and in
# every module compiled into it, and fails when one is found. CI runs it on
# every pull request and the release workflow on the commit it builds.
#
# The built binary is scanned, not the source: it names the exact Go and
# module versions shipped, and it covers the full edition, which holds
# everything the capture-only one does.
#
# A finding is fixed by raising the go line or the module in go.mod, never
# by an exception here.
#
#   scripts/vulncheck.sh
set -euo pipefail

# Pinned: a scanner that changes under a release is one more thing to trust.
GOVULNCHECK="golang.org/x/vuln/cmd/govulncheck@v1.10.0"

dir="$(mktemp -d)"
trap 'rm -rf "$dir"' EXIT
CGO_ENABLED=0 go build -trimpath -o "$dir/truthform" ./cmd/truthform
go run "$GOVULNCHECK" -mode binary "$dir/truthform"
