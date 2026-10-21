# StackDNA

Capture what is running, so it can be recreated.

StackDNA is infrastructure-as-code in reverse. You don't write IaC and then manage
state files. Instead, StackDNA reads the live system through the platform's own
APIs and writes a normalised snapshot that can recreate it. The live system is
the source of truth, so there is no state to manage. The snapshot is plain YAML
that you can review, commit and diff.

**Status: early development.** Kubernetes works end to end. AWS (every
Cloud Control type in the CloudFormation registry) passes its restore drill
against a schema-driven fake; it has not yet run against a real account. See
[AWS](docs/architecture.md#aws-cloud-control-driven-by-the-registry). Other
platforms are on the [roadmap](docs/architecture.md#roadmap). It is a single Go binary, with no
Pulumi or Terraform dependency.

## Commands

```bash
go build -o bin/stackdna ./cmd/stackdna

stackdna capture --context kind-src --out snap/ [--baseline base/] [--include-system]
stackdna restore --context kind-dst --from snap/ [--secrets-from-context kind-src]
stackdna diff    --context kind-dst --from snap/ [--baseline base/]
stackdna compare snap-a/ snap-b/
stackdna schema-diff old/ new/

stackdna capture --platform aws --region eu-west-1 --profile sandbox --out snap/ [--types 'AWS::S3::*,AWS::IAM::Role']
stackdna restore --platform aws --region eu-west-1 --profile dr --from snap/ [--values write-only.yaml]
stackdna aws-coverage   # offline: what the public registry lets StackDNA capture
```

- **capture** discovers every resource type the cluster serves, including custom
  resources no StackDNA code knows about. It keeps what someone configured and
  strips what the server generated: UIDs, `resourceVersion`, status and
  allocated cluster IPs. It writes one YAML file per object, plus
  `coverage.yaml`, which lists everything it did not take and why.
- **restore** applies a snapshot with server-side apply, in dependency order:
  CRDs first (and it waits until they are established), admission webhooks
  last. It never deletes anything.
- **diff** captures a live cluster under the same rules and reports missing,
  extra and changed objects, naming each changed field.

Exit codes: `0` ok · `1` error · `2` differences found · `3` incomplete (the
snapshot was written, but some types couldn't be read, or a restore applied only
some objects).

## API fields keep up by themselves

Terraform and Pulumi build each API's fields into a provider release, so a
field an API added last month doesn't exist for them until a new provider
ships. StackDNA keeps no field list in its code:

- **Capture** reads whatever the live API returns, so new fields are captured
  as soon as the API serves them.
- **Each snapshot fingerprints the schema** that each captured type published
  at that moment, in `schemas/<group>/<version>/<kind>.yaml`. The field paths
  come from the API's own OpenAPI document.
- **`stackdna schema-diff old/ new/`** shows exactly what each API added or
  removed between two captures, for example across a cluster or operator
  upgrade:

  ```
  changed       example.stackdna.org/v1 Widget
      + spec.shape
  ```

- **Restore uses strict field validation,** so a field the target API doesn't
  know about fails loudly instead of being dropped.

## Rules it keeps

- **Deterministic.** An unchanged system captures to byte-identical files, so CI
  can regenerate snapshots and the diff shows only real change. The snapshot
  stores no capture time or machine details.
- **Nothing silently left out.** Every skipped object and type is in
  `coverage.yaml` with a reason, such as "owned by ReplicaSet/x, whose
  controller recreates it" or "events are a log, not configuration".
- **Secret values never reach the snapshot.** Only the key names are kept.
  Restore refuses to create a secret with empty values. Pass
  `--secrets-from-context` to read the values live from a source cluster;
  they go straight from one API to the other and are never written to disk.
- **The distribution baseline.** Capture a fresh, empty cluster of the same kind
  once (kind, EKS, AKS...) and pass it as `--baseline`. Objects identical to it
  are the distribution's own add-ons and are skipped. An add-on someone
  modified differs from its baseline copy, so it is captured.

## Proof: the restore drill

The drill is written once, in `internal/drilltest`, against the platform
contract (`internal/platform`), so every adapter must pass the same test. It
runs at two levels:

| Level | Where | Time | What runs |
|---|---|---|---|
| API server | `go test ./...` (every save, every PR) | ~20s | Two real etcd and kube-apiserver pairs (`internal/kubetest`); no nodes or Docker |
| Full fidelity | `scripts/drill-kind.sh` (on demand; the `full-drill` PR label) | ~2 min | Two kind clusters with running controllers |

Get the API-server binaries once with
`export STACKDNA_KUBE_ASSETS="$(scripts/envtest-assets.sh)"`. Without them the
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

CI runs the same drill on every pull request.

## Local dev loop

```bash
tilt up --port 10352   # 10350 belongs to a platform Tilt
```

| Resource | When it runs | What it does |
|---|---|---|
| `build`, `unit-tests` | Every save | Build and test in about 14 seconds warm |
| `restore-drill` | On click | The full kind round trip above, about 2 minutes |
| `capture-platform` | On click | A read-only capture of the platform cluster (`kind-tiltdev`). It compares with the previous capture, and `schema-diff` shows which API fields a platform or operator upgrade added or removed |

All of it is local and free. Snapshots of real clusters go to `.stackdna/`,
which is gitignored. Resources for other platforms are added along with their
adapters, never before.
