#!/usr/bin/env bash
# The GCP restore drill against a real project: the disaster case.
#
#   seed with gcloud (not StackDNA); capture twice, the digests must match
#   DELETE what was seeded; restore it from the snapshot
#   diff the project against the snapshot: no differences
#   delete it again, and require the project to match its baseline
#
# Free, and needs no billing: a service account and an email notification
# channel (whose ID the server assigns). Not used:
#   - log-based metrics: creating one needs billing enabled
#     (BILLING_DISABLED in my-sandbox-project), though holding one is free;
#   - custom IAM roles: a deleted role's ID cannot be reused for 37 days, so
#     delete-then-restore in one project cannot succeed for them;
#   - alert policies: Cloud Monitoring charges for alerting conditions.
#
# Cloud Asset Inventory, which lists what exists, lags changes by up to a
# few minutes. Steps that read it after a change retry until it settles and
# say how long that took; one that never settles fails.
#
#   PROJECT=<id> scripts/drill-gcp.sh
set -euo pipefail

PROJECT="${PROJECT:?set PROJECT to a sandbox project ID}"
BIN="${BIN:-bin/stackdna}"
OUT="${OUT:-.stackdna/gcp-drill}"
SA=stackdna-drill
CHANNEL="StackDNA drill"
TYPES='iam.googleapis.com/ServiceAccount,monitoring.googleapis.com/NotificationChannel'

# No MSYS_NO_PATHCONV here (unlike the AWS and Azure drills): gcloud's own
# launcher needs Git Bash's path conversion, and no argument starts with /.
sd() { "$BIN" "$@" --platform gcp --project "$PROJECT" --types "$TYPES"; }
step() { printf '\n== %s\n' "$*"; }
token() { gcloud auth print-access-token; }
mon() { curl -sS -H "Authorization: Bearer $(token)" -H "X-Goog-User-Project: $PROJECT" -H "Content-Type: application/json" "$@"; }

channels() {
  mon "https://monitoring.googleapis.com/v3/projects/$PROJECT/notificationChannels" |
    python -I -c "import json,sys; [print(c['name']) for c in json.load(sys.stdin).get('notificationChannels',[]) if c.get('displayName')==sys.argv[1]]" "$CHANNEL"
}

cleanup() {
  step "cleanup: delete the drill's resources"
  if gcloud iam service-accounts describe "$SA@$PROJECT.iam.gserviceaccount.com" --project "$PROJECT" >/dev/null 2>&1; then
    gcloud iam service-accounts delete "$SA@$PROJECT.iam.gserviceaccount.com" --project "$PROJECT" --quiet
  fi
  for c in $(channels); do
    mon -X DELETE "https://monitoring.googleapis.com/v3/$c?force=true" >/dev/null && echo "deleted $c"
  done
}

seed() {
  step "seed with gcloud"
  gcloud iam service-accounts create "$SA" --display-name "StackDNA drill" --project "$PROJECT" --quiet
  mon -X POST "https://monitoring.googleapis.com/v3/projects/$PROJECT/notificationChannels" \
    -d '{"type":"email","displayName":"'"$CHANNEL"'","labels":{"email_address":"stackdna-drill@example.com"}}' >/dev/null
  echo "seeded"
}

# until_settled CMD...: retry for up to 10 minutes while the inventory lags.
until_settled() {
  local i
  for i in $(seq 1 20); do
    if "$@" >"$OUT/attempt.log" 2>&1; then
      [ "$i" -gt 1 ] && echo "(settled after $i attempts: Cloud Asset Inventory lag)"
      cat "$OUT/attempt.log"
      return 0
    fi
    sleep 30
  done
  cat "$OUT/attempt.log"
  return 1
}

seeded2() { sd capture --out "$OUT/probe" | grep -q "^captured 2 resources"; }

[ -x "$BIN" ] || [ -x "$BIN.exe" ] || { echo "build first: go build -o $BIN ./cmd/stackdna" >&2; exit 1; }
[ -x "$BIN" ] || BIN="$BIN.exe"
rm -rf "$OUT"; mkdir -p "$OUT"
gcloud config get-value account

cleanup
verify_clean() {
  [ -f "$OUT/baseline/snapshot.yaml" ] || return 0
  step "verify: the project is back to its baseline"
  until_settled sd diff --from "$OUT/baseline" || { echo "LEAK: resources above were left behind"; return 1; }
}
trap 'cleanup; verify_clean' EXIT

step "baseline: what the project holds before the drill"
until_settled sd capture --out "$OUT/baseline"
seed
step "wait for the inventory to list both"
until_settled seeded2
step "capture twice"
sd capture --baseline "$OUT/baseline" --out "$OUT/snap"
sd capture --baseline "$OUT/baseline" --out "$OUT/snap2" >/dev/null
d1=$(grep '^digest:' "$OUT/snap/snapshot.yaml"); d2=$(grep '^digest:' "$OUT/snap2/snapshot.yaml")
[ "$d1" = "$d2" ] || { echo "FAIL: two captures differ: $d1 vs $d2"; "$BIN" compare "$OUT/snap" "$OUT/snap2" || true; exit 1; }
grep -q "^objects: 2$" "$OUT/snap/snapshot.yaml" || { echo "FAIL: snapshot does not hold the 2 seeded resources"; cat "$OUT/snap/snapshot.yaml"; exit 1; }
echo "deterministic: $d1"

step "disaster: delete the drill's resources"
cleanup
step "restore from the snapshot"
t0=$(date +%s)
sd restore --from "$OUT/snap"
echo "restore took $(( $(date +%s) - t0 ))s"
step "diff: the project must match the snapshot"
until_settled sd diff --baseline "$OUT/baseline" --from "$OUT/snap"
echo "DRILL PASSED"

# Drift: someone edits both resources by hand (the channel's description,
# since its display name is its identity here). A plain restore must leave
# them alone and say so (exit 3); --update must put them right.
step "update: drift both resources, then restore --update"
gcloud iam service-accounts update "$SA@$PROJECT.iam.gserviceaccount.com" --display-name "edited by hand" --project "$PROJECT" --quiet >/dev/null
for c in $(channels); do
  mon -X PATCH "https://monitoring.googleapis.com/v3/$c?updateMask=description" -d '{"description":"edited by hand"}' >/dev/null
done
drifted() { ! sd diff --baseline "$OUT/baseline" --from "$OUT/snap" >/dev/null; }
until_settled drifted
code=0; sd restore --from "$OUT/snap" > "$OUT/restore-plain.txt" || code=$?
cat "$OUT/restore-plain.txt"
[ "$code" = 3 ] || { echo "FAIL: restore without --update exited $code on a drifted project, want 3"; exit 1; }
grep -q "not modified (--update modifies it)" "$OUT/restore-plain.txt" || { echo "FAIL: restore did not report the drift"; exit 1; }
sd restore --from "$OUT/snap" --update
until_settled sd diff --baseline "$OUT/baseline" --from "$OUT/snap"
echo "UPDATE PASSED"
