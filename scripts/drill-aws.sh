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
# Free while empty: VPC, subnet, security group, SQS queues (one the other's
# dead-letter queue), SSM Standard parameter, API Gateway REST API and
# resource, SNS topic, an EventBridge rule targeting the topic (DISABLED, so
# it never fires), a CloudWatch log group, an ECR repository and an S3
# bucket. Cloud Control calls are free. Not used: Secrets Manager (charged
# monthly per secret), KMS, NAT gateways, Elastic IPs, IAM (the sandbox
# user's PowerUserAccess has no IAM writes).
#
# The references are the point: the rule names the topic by ARN, the queue's
# RedrivePolicy names the dead-letter queue's ARN inside a JSON string, and
# the security group names the VPC. The group's ingress rule is also listed
# as a resource of its own, so it must not be restored twice. A restore must remap every one.
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
TYPES='AWS::EC2::VPC,AWS::EC2::Subnet,AWS::EC2::SecurityGroup,AWS::EC2::SecurityGroupIngress,AWS::EC2::SecurityGroupEgress,AWS::SQS::Queue,AWS::SSM::Parameter,AWS::ApiGateway::RestApi,AWS::ApiGateway::Resource,AWS::SNS::Topic,AWS::Events::Rule,AWS::Logs::LogGroup,AWS::ECR::Repository,AWS::S3::Bucket'
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
  if aws events describe-rule --name "$N-nightly" >/dev/null 2>&1; then
    ids=$(aws events list-targets-by-rule --rule "$N-nightly" --query 'Targets[].Id' --output text)
    [ -n "$ids" ] && aws events remove-targets --rule "$N-nightly" --ids $ids >/dev/null
    aws events delete-rule --name "$N-nightly"; echo "deleted rule $N-nightly"
  fi
  for t in $(aws sns list-topics --query "Topics[?ends_with(TopicArn, ':$N-alerts')].TopicArn" --output text); do
    aws sns delete-topic --topic-arn "$t"; echo "deleted topic $t"
  done
  if q=$(aws sqs get-queue-url --queue-name "$N-dlq" --query QueueUrl --output text 2>/dev/null); then
    aws sqs delete-queue --queue-url "$q"; echo "deleted queue $q"
  fi
  aws logs delete-log-group --log-group-name "/$N/app" 2>/dev/null && echo "deleted log group /$N/app" || true
  aws ecr delete-repository --repository-name "$N" --force >/dev/null 2>&1 && echo "deleted ecr repository $N" || true
  aws s3api delete-bucket --bucket "$BUCKET" 2>/dev/null && echo "deleted bucket $BUCKET" || true
  for vpc in $(aws ec2 describe-vpcs --filters "Name=tag:Name,Values=$N" --query 'Vpcs[].VpcId' --output text); do
    for sg in $(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$vpc" --query "SecurityGroups[?GroupName!='default'].GroupId" --output text); do
      aws ec2 delete-security-group --group-id "$sg"; echo "deleted security group $sg"
    done
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
  wait_listed AWS::SQS::Queue "$N-dlq"
  wait_listed AWS::SNS::Topic ":$N-alerts"
  wait_listed AWS::Events::Rule "$N-nightly"
  wait_listed AWS::Logs::LogGroup "/$N/app"
  wait_listed AWS::ECR::Repository "$N"
  wait_listed AWS::S3::Bucket "$BUCKET"
  echo "all listed by Cloud Control"
}

seed() {
  step "seed with the AWS CLI"
  vpc=$(aws ec2 create-vpc --cidr-block 10.42.0.0/16 \
    --tag-specifications "ResourceType=vpc,Tags=[{Key=Name,Value=$N},{Key=team,Value=shop}]" --query Vpc.VpcId --output text)
  aws ec2 create-subnet --vpc-id "$vpc" --cidr-block 10.42.1.0/24 --availability-zone "${REGION}a" \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=$N-app}]" --query Subnet.SubnetId --output text
  sg=$(aws ec2 create-security-group --vpc-id "$vpc" --group-name "$N-web" --description "StackDNA drill"     --tag-specifications "ResourceType=security-group,Tags=[{Key=Name,Value=$N-web}]" --query GroupId --output text)
  # A rule AWS also lists as its own AWS::EC2::SecurityGroupIngress.
  aws ec2 authorize-security-group-ingress --group-id "$sg" --protocol tcp --port 443 --cidr 10.42.0.0/16 >/dev/null
  # SQS refuses a queue name for 60 seconds after it was deleted.
  for qn in "$N-dlq" "$N-jobs"; do
    attrs="VisibilityTimeout=60"
    if [ "$qn" = "$N-jobs" ]; then
      dlq=$(aws sqs get-queue-attributes --queue-url "$(aws sqs get-queue-url --queue-name "$N-dlq" --query QueueUrl --output text)" --attribute-names QueueArn --query Attributes.QueueArn --output text)
      printf '{"VisibilityTimeout":"60","RedrivePolicy":"{\\"deadLetterTargetArn\\":\\"%s\\",\\"maxReceiveCount\\":\\"5\\"}"}' "$dlq" > "$OUT/attrs.json"
      attrs="file://$OUT/attrs.json"
    fi
    until aws sqs create-queue --queue-name "$qn" --attributes "$attrs" --tags team=shop --query QueueUrl --output text 2>"$OUT/sqs.err"; do
      grep -q QueueDeletedRecently "$OUT/sqs.err" || { cat "$OUT/sqs.err" >&2; return 1; }
      echo "queue name held after a recent delete; retrying in 15s"; sleep 15
    done
  done
  topic=$(aws sns create-topic --name "$N-alerts" --query TopicArn --output text)
  aws events put-rule --name "$N-nightly" --schedule-expression "cron(0 3 * * ? *)" --state DISABLED --description "StackDNA drill" >/dev/null
  aws events put-targets --rule "$N-nightly" --targets "Id"="alerts","Arn"="$topic" >/dev/null
  aws logs create-log-group --log-group-name "/$N/app"
  aws logs put-retention-policy --log-group-name "/$N/app" --retention-in-days 7
  aws ecr create-repository --repository-name "$N" --image-tag-mutability IMMUTABLE >/dev/null
  aws s3api create-bucket --bucket "$BUCKET" --create-bucket-configuration "LocationConstraint=$REGION" >/dev/null
  aws ssm put-parameter --name "/$N/env" --type String --value prod --tags Key=team,Value=shop --output text
  api=$(aws apigateway create-rest-api --name "$N" --query id --output text)
  root=$(aws apigateway get-resources --rest-api-id "$api" --query "items[?path=='/'].id" --output text)
  aws apigateway create-resource --rest-api-id "$api" --parent-id "$root" --path-part orders --query id --output text
  echo "seeded vpc $vpc, rest api $api"
  wait_all
}

[ -x "$BIN" ] || [ -x "$BIN.exe" ] || { echo "build first: go build -o $BIN ./cmd/stackdna" >&2; exit 1; }
# Bucket names are global across AWS: the account ID keeps this one ours.
BUCKET="$N-$(aws sts get-caller-identity --query Account --output text)-$REGION"
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
