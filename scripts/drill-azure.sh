#!/usr/bin/env bash
# The Azure restore drill against a real subscription: the disaster case.
#
#   seed an app with the az CLI (not StackDNA)
#   capture it twice; the digests must match
#   DELETE the app's resource group
#   restore it from the snapshot; every resource must be applied
#   diff the subscription against the snapshot; there must be no differences
#   delete it again and capture, to prove the subscription is back to its
#   baseline
#
# Free only: a resource group, network security group, virtual network with
# a subnet that references the NSG, a user-assigned managed identity, a
# Reader role assignment for that identity on the group, and a delete lock
# on the group. The assignment proves the principal remap: restoring the
# identity creates a new principal, and the assignment must follow it.
# None is metered. Not used: VMs, storage, public IPs, Log Analytics. An
# App Service plan and web app (Free F1) were in the first run, to test a
# map keyed by resource ID against Azure, but the subscription's F1 quota is
# 0 ("Current Limit (F1 VMs): 0"); that case stays covered by the fake.
#
# Creating a virtual network makes Azure create NetworkWatcherRG if the
# subscription has none; cleanup deletes it again only in that case.
#
#   SUBSCRIPTION=<id> LOCATION=eastus scripts/drill-azure.sh
set -euo pipefail

SUBSCRIPTION="${SUBSCRIPTION:?set SUBSCRIPTION to a sandbox subscription ID}"
LOCATION="${LOCATION:-eastus}"
BIN="${BIN:-bin/stackdna}"
OUT="${OUT:-.stackdna/azure-drill}"
RG=stackdna-drill-rg
N=stackdna-drill

# Git Bash on Windows rewrites arguments that look like paths, which turns
# resource IDs (/subscriptions/...) into C:/Program Files/Git/subscriptions/...
export MSYS_NO_PATHCONV=1
az() { command az "$@" --subscription "$SUBSCRIPTION" --only-show-errors; }
sd() { "$BIN" "$@" --platform azure --subscription "$SUBSCRIPTION"; }
step() { printf '\n== %s\n' "$*"; }

had_watcher=$(az group exists --name NetworkWatcherRG)

unlock() {
  # A CanNotDelete lock blocks deleting the group; it goes first.
  for l in $(az lock list --resource-group "$RG" --query "[].id" -o tsv 2>/dev/null); do
    az lock delete --ids "$l" && echo "deleted lock $l"
  done
}

cleanup() {
  step "cleanup: delete $RG"
  if [ "$(az group exists --name "$RG")" = true ]; then
    unlock
    az group delete --name "$RG" --yes
    echo "deleted $RG"
  fi
  if [ "$had_watcher" = false ] && [ "$(az group exists --name NetworkWatcherRG)" = true ]; then
    az group delete --name NetworkWatcherRG --yes
    echo "deleted NetworkWatcherRG (created by Azure during the drill)"
  fi
}

seed() {
  step "seed with the az CLI"
  az group create --name "$RG" --location "$LOCATION" --tags team=shop -o none
  az network nsg create -g "$RG" -n "$N-nsg" -l "$LOCATION" -o none
  az network nsg rule create -g "$RG" --nsg-name "$N-nsg" -n allow-https --priority 100 \
    --access Allow --direction Inbound --protocol Tcp --destination-port-ranges 443 -o none
  az network vnet create -g "$RG" -n "$N-vnet" -l "$LOCATION" --address-prefixes 10.42.0.0/16 \
    --subnet-name app --subnet-prefixes 10.42.1.0/24 --network-security-group "$N-nsg" -o none
  principal=$(az identity create -g "$RG" -n "$N-id" -l "$LOCATION" --query principalId -o tsv)
  rgid=$(az group show --name "$RG" --query id -o tsv)
  # principalType skips the directory lookup that fails for a few seconds
  # after an identity is created (replication delay).
  az role assignment create --assignee-object-id "$principal" --assignee-principal-type ServicePrincipal     --role Reader --scope "$rgid" -o none
  az lock create --name "$N-lock" --lock-type CanNotDelete --resource-group "$RG" --notes "StackDNA drill" -o none
  echo "seeded $RG"
}

[ -x "$BIN" ] || [ -x "$BIN.exe" ] || { echo "build first: go build -o $BIN ./cmd/stackdna" >&2; exit 1; }
[ -x "$BIN" ] || BIN="$BIN.exe"
rm -rf "$OUT"; mkdir -p "$OUT"
az account show --query "{name:name, id:id}" -o tsv

# Leftovers from an interrupted run would be captured as part of the app.
cleanup

verify_clean() {
  [ -f "$OUT/baseline/snapshot.yaml" ] || return 0
  step "verify: the subscription is back to its baseline"
  sd diff --from "$OUT/baseline" || { echo "LEAK: resources above were left behind"; return 1; }
}
trap 'cleanup; verify_clean' EXIT

step "baseline: what the subscription holds before the drill"
sd capture --out "$OUT/baseline"
seed
step "capture twice"
sd capture --baseline "$OUT/baseline" --out "$OUT/snap"
sd capture --baseline "$OUT/baseline" --out "$OUT/snap2" >/dev/null
d1=$(grep '^digest:' "$OUT/snap/snapshot.yaml"); d2=$(grep '^digest:' "$OUT/snap2/snapshot.yaml")
[ "$d1" = "$d2" ] || { echo "FAIL: two captures differ: $d1 vs $d2"; "$BIN" compare "$OUT/snap" "$OUT/snap2" || true; exit 1; }
echo "deterministic: $d1"

step "disaster: delete $RG"
unlock
az group delete --name "$RG" --yes

step "restore from the snapshot"
sd restore --from "$OUT/snap"
# The restored assignment must name the restored identity's new principal.
newp=$(az identity show -g "$RG" -n "$N-id" --query principalId -o tsv)
az role assignment list --scope "$(az group show --name "$RG" --query id -o tsv)" --query "[?principalId=='$newp'].roleDefinitionName" -o tsv | grep -qx Reader   || { echo "FAIL: the restored role assignment does not name the restored identity ($newp)"; exit 1; }
echo "role assignment follows the restored identity's new principal $newp"
step "diff: the subscription must match the snapshot"
sd diff --baseline "$OUT/baseline" --from "$OUT/snap"
echo "DRILL PASSED"

# Drift: someone tags two resources by hand. A plain restore must leave
# them alone and say so (exit 3); --update must put them right, and the
# identity must keep its principal (an update, not a re-creation).
step "update: drift two resources, then restore --update"
for id in "$(az identity show -g "$RG" -n "$N-id" --query id -o tsv)" "$(az network nsg show -g "$RG" -n "$N-nsg" --query id -o tsv)"; do
  az tag update --resource-id "$id" --operation Merge --tags edited=by-hand -o none
done
code=0; sd restore --from "$OUT/snap" > "$OUT/restore-plain.txt" || code=$?
cat "$OUT/restore-plain.txt"
[ "$code" = 3 ] || { echo "FAIL: restore without --update exited $code on a drifted subscription, want 3"; exit 1; }
grep -q "not modified (--update modifies it)" "$OUT/restore-plain.txt" || { echo "FAIL: restore did not report the drift"; exit 1; }
sd restore --from "$OUT/snap" --update
[ "$(az identity show -g "$RG" -n "$N-id" --query principalId -o tsv)" = "$newp" ] || { echo "FAIL: the update changed the identity's principal"; exit 1; }
sd diff --baseline "$OUT/baseline" --from "$OUT/snap"
echo "UPDATE PASSED"
