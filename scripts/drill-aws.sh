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
# bucket, and in IAM (global) a role and a customer managed policy attached
# to it, and a Lambda function with its own execution role. Cloud Control calls are free. Not used: Secrets Manager (charged
# monthly per secret), KMS, NAT gateways, Elastic IPs.
#
# IAM needs writes PowerUserAccess does not give: the sandbox user holds an
# extra policy allowing them only on roles and policies named
# stackdna-drill* (docs/drills.md). IAM=0 leaves IAM out, for an account
# without it.
#
# The references are the point: the rule names the topic by ARN, the queue's
# RedrivePolicy names the dead-letter queue's ARN inside a JSON string, and
# the security group names the VPC, and the IAM policy names the queue by ARN
# and is attached to the role by name. The group's ingress rule is also
# listed as a resource of its own, so it must not be restored twice. A
# restore must remap every one.
#
# Everything is named stackdna-drill*. Cleanup finds resources by those names,
# not by remembered IDs, so it also removes what a restore created, and it
# runs on exit even when a step fails.
#
#   PROFILE=tf-pilot-automation REGION=us-east-2 scripts/drill-aws.sh
#
# With TARGET_REGION set, the app is seeded and captured in REGION, deleted
# there (the region is lost), and restored into TARGET_REGION: zones are
# paired by zone ID and the region in values and ARNs follows. Both
# regions' baselines are in the capture policy, and both regions are
# cleaned and verified.
set -euo pipefail

PROFILE="${PROFILE:-tf-pilot-automation}"
REGION="${REGION:-us-east-2}"
TARGET="${TARGET_REGION:-$REGION}"
XREGION=false; [ "$TARGET" = "$REGION" ] || XREGION=true
BIN="${BIN:-bin/stackdna}"
OUT="${OUT:-.stackdna/aws-drill}"
TYPES='AWS::EC2::VPC,AWS::EC2::Subnet,AWS::EC2::SecurityGroup,AWS::EC2::SecurityGroupIngress,AWS::EC2::SecurityGroupEgress,AWS::SQS::Queue,AWS::SSM::Parameter,AWS::ApiGateway::RestApi,AWS::ApiGateway::Resource,AWS::SNS::Topic,AWS::Events::Rule,AWS::Logs::LogGroup,AWS::ECR::Repository,AWS::S3::Bucket'
N=stackdna-drill
# Across regions the bucket is left out: bucket names are global, and a name
# just deleted in one region cannot be created in another while S3 still
# holds it ("A conflicting conditional operation is currently in progress",
# us-east-2 to us-east-1, 2026-10-22). In a real region loss the name stays
# taken, so a bucket restored elsewhere needs another name.
if $XREGION; then TYPES="${TYPES/,AWS::S3::Bucket/}"; fi
IAM="${IAM:-1}"
# Lambda needs an execution role, so it comes with IAM.
if [ "$IAM" = 1 ]; then TYPES="$TYPES,AWS::IAM::Role,AWS::IAM::ManagedPolicy,AWS::Lambda::Function"; fi
# A function's code is write-only: AWS never returns it, so a snapshot
# cannot hold it and the restore is given it, as a customer would give it.
VALUES=()

# Git Bash on Windows rewrites arguments that look like paths, which turns
# the parameter name /stackdna-drill/env into C:/Program Files/Git/...
export MSYS_NO_PATHCONV=1
aws() { command aws --profile "$PROFILE" --region "$REGION" "$@"; }
sd() { "$BIN" "$@" --platform aws --profile "$PROFILE" --region "$REGION" --types "$TYPES"; }
step() { printf '\n== %s\n' "$*"; }
# on_region REGION CMD...: run CMD with aws and sd pointed at another region.
on_region() { local REGION=$1; shift; "$@"; }

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
  if [ "$IAM" = 1 ]; then cleanup_iam; fi
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

# IAM is global: a cross-region drill cleans it twice, harmlessly. By name,
# like everything else; a policy must be detached and its old versions
# deleted before IAM lets it go.
cleanup_iam() {
  local arn="arn:aws:iam::$ACCOUNT:policy/$N-read"
  if aws iam get-policy --policy-arn "$arn" >/dev/null 2>&1; then
    for r in $(aws iam list-entities-for-policy --policy-arn "$arn" --query 'PolicyRoles[].RoleName' --output text); do
      aws iam detach-role-policy --role-name "$r" --policy-arn "$arn"
    done
    for v in $(aws iam list-policy-versions --policy-arn "$arn" --query 'Versions[?!IsDefaultVersion].VersionId' --output text); do
      aws iam delete-policy-version --policy-arn "$arn" --version-id "$v"
    done
    aws iam delete-policy --policy-arn "$arn"; echo "deleted policy $arn"
  fi
  # The function before its role: a role still in use can be deleted,
  # and the function would be left pointing at nothing.
  aws lambda delete-function --function-name "$N-fn" 2>/dev/null && echo "deleted function $N-fn" || true
  if aws iam get-role --role-name "$N-fn" >/dev/null 2>&1; then
    aws iam delete-role --role-name "$N-fn"; echo "deleted role $N-fn"
  fi
  if aws iam get-role --role-name "$N-app" >/dev/null 2>&1; then
    for a in $(aws iam list-attached-role-policies --role-name "$N-app" --query 'AttachedPolicies[].PolicyArn' --output text); do
      aws iam detach-role-policy --role-name "$N-app" --policy-arn "$a"
    done
    for ip in $(aws iam list-role-policies --role-name "$N-app" --query 'PolicyNames[]' --output text); do
      aws iam delete-role-policy --role-name "$N-app" --policy-name "$ip"
    done
    aws iam delete-role --role-name "$N-app"; echo "deleted role $N-app"
  fi
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
  # The seed always makes the bucket; a cross-region restore does not.
  $XREGION || wait_listed AWS::S3::Bucket "$BUCKET"
  if [ "$IAM" = 1 ]; then
    wait_listed AWS::IAM::Role "$N-app"
    wait_listed AWS::IAM::ManagedPolicy "policy/$N-read"
    wait_listed AWS::Lambda::Function "$N-fn"
  fi
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
  if [ "$IAM" = 1 ]; then
    printf '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' > "$OUT/trust.json"
    aws iam create-role --role-name "$N-app" --assume-role-policy-document "file://$OUT/trust.json"       --description "StackDNA drill" --tags Key=team,Value=shop --query Role.Arn --output text
    jobs_arn=$(aws sqs get-queue-attributes --queue-url "$(aws sqs get-queue-url --queue-name "$N-jobs" --query QueueUrl --output text)" --attribute-names QueueArn --query Attributes.QueueArn --output text)
    printf '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["sqs:ReceiveMessage","sqs:DeleteMessage"],"Resource":"%s"}]}' "$jobs_arn" > "$OUT/policy.json"
    pol=$(aws iam create-policy --policy-name "$N-read" --policy-document "file://$OUT/policy.json" --description "StackDNA drill" --query Policy.Arn --output text)
    aws iam attach-role-policy --role-name "$N-app" --policy-arn "$pol"
    # A function: its role is named by ARN, and its environment names the
    # queue by URL, two more references to remap. Never invoked, so free.
    printf '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' > "$OUT/fn-trust.json"
    fnrole=$(aws iam create-role --role-name "$N-fn" --assume-role-policy-document "file://$OUT/fn-trust.json" --description "StackDNA drill" --query Role.Arn --output text)
    jobs_url=$(aws sqs get-queue-url --queue-name "$N-jobs" --query QueueUrl --output text)
    # python3 first: Linux and macOS often have no "python".
    "$(command -v python3 || command -v python)" - "$OUT/fn.zip" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("index.py", "def handler(event, context):\n    return {'ok': True}\n")
PY
    printf 'AWS::Lambda::Function/%s:\n  Code:\n    ZipFile: |\n      def handler(event, context):\n          return {"ok": True}\n' "$N-fn" > "$OUT/values.yaml"
    # A new role is not assumable by Lambda for some seconds after IAM
    # says it exists.
    until aws lambda create-function --function-name "$N-fn" --runtime python3.12 --handler index.handler \
        --role "$fnrole" --zip-file "fileb://$OUT/fn.zip" --environment "Variables={JOBS_QUEUE=$jobs_url}" \
        --tags team=shop --query FunctionArn --output text 2>"$OUT/fn.err"; do
      grep -q "cannot be assumed" "$OUT/fn.err" || { cat "$OUT/fn.err" >&2; return 1; }
      echo "role not assumable by Lambda yet; retrying in 5s"; sleep 5
    done
  fi
  api=$(aws apigateway create-rest-api --name "$N" --query id --output text)
  root=$(aws apigateway get-resources --rest-api-id "$api" --query "items[?path=='/'].id" --output text)
  aws apigateway create-resource --rest-api-id "$api" --parent-id "$root" --path-part orders --query id --output text
  echo "seeded vpc $vpc, rest api $api"
  wait_all
}

[ -x "$BIN" ] || [ -x "$BIN.exe" ] || { echo "build first: go build -o $BIN ./cmd/stackdna" >&2; exit 1; }
# Bucket names are global across AWS: the account ID keeps this one ours.
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
BUCKET="$N-$ACCOUNT-$REGION"
[ -x "$BIN" ] || BIN="$BIN.exe"
rm -rf "$OUT"; mkdir -p "$OUT"
aws sts get-caller-identity --query Arn --output text

# After cleanup, the region must capture exactly as it did before the drill.
# Without this, a resource cleanup missed would leak silently.
verify_clean() {
  [ -f "$OUT/baseline/snapshot.yaml" ] || return 0
  step "verify: $REGION is back to its baseline"
  sd diff --from "$OUT/baseline" || { echo "LEAK: resources above were left behind"; return 1; }
  if [ "$TARGET" != "$REGION" ] && [ -f "$OUT/baseline-target/snapshot.yaml" ]; then
    step "verify: $TARGET is back to its baseline"
    on_region "$TARGET" sd diff --from "$OUT/baseline-target" || { echo "LEAK: resources above were left behind in $TARGET"; return 1; }
  fi
}
cleanup_all() { cleanup; [ "$TARGET" = "$REGION" ] || on_region "$TARGET" cleanup; }

# Leftovers from an interrupted run would be captured as part of the app.
cleanup_all
trap 'cleanup_all; verify_clean' EXIT

step "baseline: what $REGION holds before the drill"
sd capture --out "$OUT/baseline"
BASES="$OUT/baseline"
if [ "$TARGET" != "$REGION" ]; then
  step "baseline: what $TARGET holds before the drill"
  on_region "$TARGET" sd capture --out "$OUT/baseline-target"
  BASES="$OUT/baseline,$OUT/baseline-target"
fi
seed
step "capture twice"
sd capture --baseline "$BASES" --out "$OUT/snap"
sd capture --baseline "$BASES" --out "$OUT/snap2" >/dev/null
d1=$(grep '^digest:' "$OUT/snap/snapshot.yaml"); d2=$(grep '^digest:' "$OUT/snap2/snapshot.yaml")
[ "$d1" = "$d2" ] || { echo "FAIL: two captures differ: $d1 vs $d2"; "$BIN" compare "$OUT/snap" "$OUT/snap2" || true; exit 1; }
echo "deterministic: $d1"

step "disaster: delete the app"
cleanup
# SQS refuses to recreate a queue name for 60 seconds after deleting it,
# and restore does not retry, so the drill waits rather than fail on it.
echo "waiting 65s for SQS to release the queue name"; sleep 65

step "restore from the snapshot into $TARGET"
t0=$(date +%s)
[ -f "$OUT/values.yaml" ] && VALUES=(--values "$OUT/values.yaml")
on_region "$TARGET" sd restore --from "$OUT/snap" ${VALUES[@]+"${VALUES[@]}"}
echo "restore took $(( $(date +%s) - t0 ))s"
on_region "$TARGET" wait_all
step "diff: $TARGET must match the snapshot"
on_region "$TARGET" sd diff --baseline "$BASES" --from "$OUT/snap"
echo "DRILL PASSED"

# Drift: someone edits two resources by hand. A plain restore must leave
# them alone and say so (exit 3); --update must put them right.
update_phase() {
  step "update: drift two resources in $REGION, then restore --update"
  aws sqs set-queue-attributes --queue-url "$(aws sqs get-queue-url --queue-name "$N-jobs" --query QueueUrl --output text)" --attributes VisibilityTimeout=30
  aws logs put-retention-policy --log-group-name "/$N/app" --retention-in-days 14
  code=0; sd restore --from "$OUT/snap" ${VALUES[@]+"${VALUES[@]}"} > "$OUT/restore-plain.txt" || code=$?
  cat "$OUT/restore-plain.txt"
  [ "$code" = 3 ] || { echo "restore without --update exited $code on a drifted account, want 3" >&2; exit 1; }
  grep -q "not modified (--update modifies it)" "$OUT/restore-plain.txt" || { echo "restore did not report the drift" >&2; exit 1; }
  sd restore --from "$OUT/snap" --update ${VALUES[@]+"${VALUES[@]}"}
  sd diff --baseline "$BASES" --from "$OUT/snap"
  echo "UPDATE PASSED"
}
on_region "$TARGET" update_phase
