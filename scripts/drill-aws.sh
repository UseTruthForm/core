#!/usr/bin/env bash
# The AWS restore drill against a real account: the disaster case.
#
#   seed an app with the plain AWS CLI (not StackDNA)
#   capture it twice; the digests must match
#   DELETE the app
#   restore it from the snapshot; every resource must be applied
#   diff the account against the snapshot; there must be no differences
#   delete everything again, and capture to prove the region is back to its
#   baseline
#
# Free tier only: VPC, subnet, SQS queue, SSM Standard parameter, API Gateway
# REST API and resource. Each costs nothing to create or to hold, and Cloud
# Control calls are free. Not used: Secrets Manager (charged monthly per
# secret), KMS, NAT gateways, Elastic IPs.
#
# Everything is named stackdna-drill*. Cleanup finds resources by those names,
# not by remembered IDs, so it also removes what a restore created, and it
# runs on exit even when a step fails.
#
#   PROFILE=tf-pilot-automation REGION=us-east-2 scripts/drill-aws.sh
set -euo pipefail

PROFILE="${PROFILE:-tf-pilot-automation}"
REGION="${REGION:-us-east-2}"
BIN="${BIN:-bin/stackdna}"
OUT="${OUT:-.stackdna/aws-drill}"
TYPES='AWS::EC2::VPC,AWS::EC2::Subnet,AWS::SQS::Queue,AWS::SSM::Parameter,AWS::ApiGateway::RestApi,AWS::ApiGateway::Resource'
N=stackdna-drill

# Git Bash on Windows rewrites arguments that look like paths, which turns
# the parameter name /stackdna-drill/env into C:/Program Files/Git/...
export MSYS_NO_PATHCONV=1
aws() { command aws --profile "$PROFILE" --region "$REGION" "$@"; }
sd() { "$BIN" "$@" --platform aws --profile "$PROFILE" --region "$REGION" --types "$TYPES"; }
step() { printf '\n== %s\n' "$*"; }

cleanup() {
  step "cleanup: delete every $N resource in $REGION"
  for api in $(aws apigateway get-rest-apis --query "items[?name=='$N'].id" --output text); do
    # API Gateway allows one REST API deletion per 30s per account.
    until aws apigateway delete-rest-api --rest-api-id "$api" 2>/dev/null; do sleep 10; done
    echo "deleted rest api $api"
  done
  # By exact name: list-queues is eventually consistent and missed a queue
  # created seconds earlier, which leaked it while cleanup reported nothing.
  if q=$(aws sqs get-queue-url --queue-name "$N-jobs" --query QueueUrl --output text 2>/dev/null); then
    aws sqs delete-queue --queue-url "$q"; echo "deleted queue $q"
  fi
  aws ssm delete-parameter --name "/$N/env" 2>/dev/null && echo "deleted parameter /$N/env" || true
  for vpc in $(aws ec2 describe-vpcs --filters "Name=tag:Name,Values=$N" --query 'Vpcs[].VpcId' --output text); do
    for sn in $(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc" --query 'Subnets[].SubnetId' --output text); do
      aws ec2 delete-subnet --subnet-id "$sn"; echo "deleted subnet $sn"
    done
    aws ec2 delete-vpc --vpc-id "$vpc"; echo "deleted vpc $vpc"
  done
}

# AWS list APIs are eventually consistent: a capture taken seconds after a
# create can miss it (the first real run missed the SQS queue, and the two
# captures differed). Wait until Cloud Control lists what was just made.
wait_listed() {
  local type=$1 needle=$2 i
  for i in $(seq 1 24); do
    aws cloudcontrol list-resources --type-name "$type" --query 'ResourceDescriptions[].Identifier' --output text | grep -qF "$needle" && return 0
    sleep 5
  done
  echo "FAIL: $type $needle still not listed after 2 minutes" >&2; return 1
}

wait_all() {
  wait_listed AWS::EC2::VPC vpc-
  wait_listed AWS::SQS::Queue "$N-jobs"
  wait_listed AWS::SSM::Parameter "/$N/env"
  wait_listed AWS::ApiGateway::RestApi "$(aws apigateway get-rest-apis --query "items[?name=='$N'].id" --output text)"
  echo "all listed by Cloud Control"
}

seed() {
  step "seed with the AWS CLI"
  vpc=$(aws ec2 create-vpc --cidr-block 10.42.0.0/16 \
    --tag-specifications "ResourceType=vpc,Tags=[{Key=Name,Value=$N},{Key=team,Value=shop}]" --query Vpc.VpcId --output text)
  aws ec2 create-subnet --vpc-id "$vpc" --cidr-block 10.42.1.0/24 --availability-zone "${REGION}a" \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=$N-app}]" --query Subnet.SubnetId --output text
  # SQS refuses a queue name for 60 seconds after it was deleted.
  until aws sqs create-queue --queue-name "$N-jobs" --attributes VisibilityTimeout=60 --tags team=shop --query QueueUrl --output text 2>"$OUT/sqs.err"; do
    grep -q QueueDeletedRecently "$OUT/sqs.err" || { cat "$OUT/sqs.err" >&2; return 1; }
    echo "queue name held after a recent delete; retrying in 15s"; sleep 15
  done
  aws ssm put-parameter --name "/$N/env" --type String --value prod --tags Key=team,Value=shop --output text
  api=$(aws apigateway create-rest-api --name "$N" --query id --output text)
  root=$(aws apigateway get-resources --rest-api-id "$api" --query "items[?path=='/'].id" --output text)
  aws apigateway create-resource --rest-api-id "$api" --parent-id "$root" --path-part orders --query id --output text
  echo "seeded vpc $vpc, rest api $api"
  wait_all
}

[ -x "$BIN" ] || [ -x "$BIN.exe" ] || { echo "build first: go build -o $BIN ./cmd/stackdna" >&2; exit 1; }
[ -x "$BIN" ] || BIN="$BIN.exe"
rm -rf "$OUT"; mkdir -p "$OUT"
aws sts get-caller-identity --query Arn --output text

# After cleanup, the region must capture exactly as it did before the drill.
# Without this, a resource cleanup missed would leak silently.
verify_clean() {
  [ -f "$OUT/baseline/snapshot.yaml" ] || return 0
  step "verify: $REGION is back to its baseline"
  sd diff --from "$OUT/baseline" || { echo "LEAK: resources above were left behind"; return 1; }
}

# Leftovers from an interrupted run would be captured as part of the app.
cleanup
trap 'cleanup; verify_clean' EXIT

step "baseline: what $REGION holds before the drill"
sd capture --out "$OUT/baseline"
seed
step "capture twice"
sd capture --baseline "$OUT/baseline" --out "$OUT/snap"
sd capture --baseline "$OUT/baseline" --out "$OUT/snap2" >/dev/null
d1=$(grep '^digest:' "$OUT/snap/snapshot.yaml"); d2=$(grep '^digest:' "$OUT/snap2/snapshot.yaml")
[ "$d1" = "$d2" ] || { echo "FAIL: two captures differ: $d1 vs $d2"; "$BIN" compare "$OUT/snap" "$OUT/snap2" || true; exit 1; }
echo "deterministic: $d1"

step "disaster: delete the app"
cleanup
# SQS refuses to recreate a queue name for 60 seconds after deleting it,
# and restore does not retry, so the drill waits rather than fail on it.
echo "waiting 65s for SQS to release the queue name"; sleep 65

step "restore from the snapshot"
sd restore --from "$OUT/snap"
wait_all
step "diff: the account must match the snapshot"
sd diff --baseline "$OUT/baseline" --from "$OUT/snap"
echo "DRILL PASSED"
