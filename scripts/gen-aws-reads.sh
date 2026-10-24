#!/usr/bin/env bash
# Regenerates internal/onboard/templates/aws-read-addon.json: the reads a
# capture needs that AWS's managed ReadOnlyAccess does not grant, from the
# CloudFormation registry schemas. Run it when AWS changes either, and
# review the diff: it is what the capture role is given.
#
#   AWS_PROFILE=<a profile allowed iam:GetPolicy> scripts/gen-aws-reads.sh
set -euo pipefail
arn=arn:aws:iam::aws:policy/ReadOnlyAccess
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
ver="$(aws iam get-policy --policy-arn "$arn" --region us-east-1 --query Policy.DefaultVersionId --output text)"
aws iam get-policy-version --policy-arn "$arn" --version-id "$ver" --region us-east-1 \
  --query PolicyVersion.Document --output json > "$tmp/ro.json"
go run ./internal/onboard/awsreads/gen --readonly-policy "$tmp/ro.json" --version "$ver" "$@"
