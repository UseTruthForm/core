#!/usr/bin/env bash
#
# Restore drill on two throwaway kind clusters. A backup that has never been
# restored is not a backup; this proves one round trip end to end:
#
#   1. recreate the destination cluster empty and capture it as the
#      distribution baseline (kind's own add-ons, which a new cluster brings)
#   2. load testdata/k8s into the source cluster
#   3. capture it twice and require identical digests (determinism: CI can
#      only regenerate snapshots meaningfully if the output is stable)
#   4. require the captured objects to be exactly the fixture: no more (the
#      baseline failed to filter), no less (something was dropped)
#   5. restore into the destination and require no differences
#
# It only ever touches the two kind clusters it names. Usage:
#   scripts/drill-kind.sh            # keep clusters afterwards
#   KEEP=0 scripts/drill-kind.sh     # delete the destination at the end
set -euo pipefail

SRC=${SRC:-stackdna-src}
DST=${DST:-stackdna-dst}
BIN=${BIN:-bin/stackdna}
WORK=${WORK:-$(mktemp -d)}

cd "$(dirname "$0")/.."
go build -o "$BIN" ./cmd/stackdna

kind get clusters | grep -qx "$SRC" || kind create cluster --name "$SRC" --wait 120s
# The destination is rebuilt every run: a baseline taken from a cluster that
# has held drill objects would hide them, and the diff would prove nothing.
kind delete cluster --name "$DST" >/dev/null 2>&1 || true
kind create cluster --name "$DST" --wait 120s

echo "== baseline: fresh $DST"
"$BIN" capture --context "kind-$DST" --out "$WORK/baseline"

echo "== load fixture into $SRC"
kubectl --context "kind-$SRC" apply -f testdata/k8s/workload.yaml
kubectl --context "kind-$SRC" wait --for=condition=Established crd/widgets.example.stackdna.org --timeout=60s
kubectl --context "kind-$SRC" apply -f testdata/k8s/widget.yaml
kubectl --context "kind-$SRC" -n shop rollout status deploy/shop-api --timeout=120s

echo "== capture twice"
"$BIN" capture --context "kind-$SRC" --baseline "$WORK/baseline" --out "$WORK/snap-a"
"$BIN" capture --context "kind-$SRC" --baseline "$WORK/baseline" --out "$WORK/snap-b" >/dev/null
a=$(grep '^digest:' "$WORK/snap-a/snapshot.yaml"); b=$(grep '^digest:' "$WORK/snap-b/snapshot.yaml")
if [ "$a" != "$b" ]; then
  echo "FAIL: two captures of an unchanged cluster differ"; "$BIN" compare "$WORK/snap-a" "$WORK/snap-b" || true; exit 1
fi
echo "deterministic: both captures $a"

echo "== captured set is exactly the fixture"
expected="apiextensions.k8s.io/v1/CustomResourceDefinition/_cluster/widgets.example.stackdna.org
apps/v1/Deployment/shop/shop-api
core/v1/ConfigMap/shop/shop-config
core/v1/Namespace/_cluster/shop
core/v1/PersistentVolumeClaim/shop/shop-data
core/v1/Secret/shop/shop-db
core/v1/Service/shop/shop-api
core/v1/ServiceAccount/shop/shop-api
example.stackdna.org/v1/Widget/shop/blue-widget
networking.k8s.io/v1/Ingress/shop/shop
networking.k8s.io/v1/NetworkPolicy/shop/shop-api-ingress
rbac.authorization.k8s.io/v1/Role/shop/read-config
rbac.authorization.k8s.io/v1/RoleBinding/shop/shop-api-read-config"
actual=$(cd "$WORK/snap-a/objects" && find . -name '*.yaml' | sed 's|^\./||; s|\.yaml$||' | sort)
if [ "$actual" != "$expected" ]; then
  echo "FAIL: captured set differs from the fixture"; diff <(echo "$expected") <(echo "$actual") || true; exit 1
fi
echo "exactly the 13 fixture objects"

# Snapshots are reviewed and diffed with other tools, so every file must load
# in a strict YAML 1.1 reader too (a bare "=" once made a snapshot unreadable
# to PyYAML, and a bare "yes" would have read back as true).
if python3 -c 'import yaml' 2>/dev/null || python -c 'import yaml' 2>/dev/null; then
  PY=$(command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' 2>/dev/null && echo python3 || echo python)
  # A parse error raises and exits non-zero, which stops the drill (set -e).
  "$PY" - "$WORK/snap-a" <<'PY'
import os, sys, yaml
count = 0
for d, _, files in os.walk(sys.argv[1]):
    for f in files:
        if f.endswith(".yaml"):
            with open(os.path.join(d, f), encoding="utf-8") as fh:
                yaml.safe_load(fh)
            count += 1
print(f"strict YAML 1.1 (PyYAML): all {count} snapshot files parse")
PY
else
  echo "SKIPPED: PyYAML not installed, YAML 1.1 portability not checked"
fi

echo "== restore into $DST (secret values read live from $SRC, never from disk)"
"$BIN" restore --context "kind-$DST" --from "$WORK/snap-a" --secrets-from-context "kind-$SRC"

echo "== diff $DST against the snapshot"
kubectl --context "kind-$DST" -n shop rollout status deploy/shop-api --timeout=120s
"$BIN" diff --context "kind-$DST" --baseline "$WORK/baseline" --from "$WORK/snap-a"

echo "== secret values arrived (compared by hash, never printed)"
h() { kubectl --context "kind-$1" -n shop get secret shop-db -o jsonpath='{.data}' | sha256sum | cut -c1-16; }
[ "$(h "$SRC")" = "$(h "$DST")" ] && echo "shop-db data identical in $SRC and $DST" || { echo "FAIL: secret data differs"; exit 1; }

echo "DRILL PASSED. Snapshot: $WORK/snap-a"
if [ "${KEEP:-1}" = 0 ]; then kind delete cluster --name "$DST"; fi
