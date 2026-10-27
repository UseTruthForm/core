#!/usr/bin/env bash
# Regenerates internal/onboard/templates/aws-read-addon.json: the reads a
# capture needs that AWS's ReadOnlyAccess does not grant. Every source is
# AWS's public documentation, so it needs no AWS credentials. Review the
# diff: it is what a capture role is given. CI runs it weekly
# (.github/workflows/aws-reads.yml).
set -euo pipefail
go run ./internal/onboard/awsreads/gen "$@"
