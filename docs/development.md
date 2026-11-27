# Developing TruthForm

How to build and test TruthForm, and how its restore drills work. To
contribute, see also [CONTRIBUTING.md](../CONTRIBUTING.md).

## The restore drill

The drill is written once, in `internal/drilltest`, against the platform
contract (`internal/platform`), so every adapter must pass the same test. It
runs at two levels:

| Level | Where | Time | What runs |
|---|---|---|---|
| API server | `go test ./...` (every save, every PR) | ~20s | Two real etcd and kube-apiserver pairs (`internal/kubetest`); no nodes or Docker |
| Full fidelity | `scripts/drill-kind.sh` (on demand; the `full-drill` PR label) | ~2 min | Two kind clusters with running controllers |

Get the API-server binaries once with
`export TRUTHFORM_KUBE_ASSETS="$(scripts/envtest-assets.sh)"`. Without them the
drill is skipped with a message locally, and fails in CI.

### The kind drill

```bash
scripts/drill-kind.sh
```

This builds two kind clusters. It loads a realistic app (`testdata/k8s`: a
Deployment, Service, ConfigMap, Secret, RBAC, PVC, NetworkPolicy and Ingress, plus
a CRD and a custom resource) into the source, then:

1. captures it twice and requires identical digests;
2. requires the snapshot to be exactly the 13 fixture objects;
3. restores into the fresh destination and requires `diff` to find nothing;
4. checks the secret values arrived intact, comparing them by hash.

CI runs it on pull requests labelled `full-drill`, or when started by
hand. Every pull request runs the same capture, restore and diff against
two real API servers instead (`TestDrillOnAPIServer`, no Docker, seconds).

## Local dev loop

```bash
tilt up --port 10352   # 10350 belongs to a platform Tilt
```

| Resource | When it runs | What it does |
|---|---|---|
| `build`, `unit-tests` | Every save | Build and test in about 14 seconds warm |
| `restore-drill` | On click | The full kind round trip above, about 2 minutes |
| `capture-platform` | On click | A read-only capture of the platform cluster (`kind-tiltdev`). It compares with the previous capture, and `schema-diff` shows which API fields a platform or operator upgrade added or removed |

All of it is local and free. Snapshots of real clusters go to `.truthform/`,
which is gitignored. Resources for other platforms are added along with their
adapters, never before.


## Drills against real accounts

`scripts/drill-aws.sh`, `scripts/drill-azure.sh` and `scripts/drill-gcp.sh`
delete and restore free resources in a sandbox account, subscription or
project, and require an empty diff. They need a sandbox you own; see
[drills.md](drills.md) for how ours are set up.
