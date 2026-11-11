#!/usr/bin/env bash
#
# Fetch the etcd and kube-apiserver binaries that the API-server drill
# (internal/kubetest) runs, and print the directory to export:
#
#   export TRUTHFORM_KUBE_ASSETS="$(scripts/envtest-assets.sh)"
#
# They are the binaries controller-runtime's envtest uses, from its official
# release index; the Kubernetes version is pinned so every run tests the same
# server.
set -euo pipefail
K8S_VERSION=${K8S_VERSION:-1.37.0}
DIR=${ENVTEST_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/truthform/envtest}
GOBIN="$DIR/bin" go install sigs.k8s.io/controller-runtime/tools/setup-envtest@v0.25.2 >&2
"$DIR/bin/setup-envtest" use "$K8S_VERSION" --bin-dir "$DIR/assets" -p path
