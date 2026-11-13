# TruthForm

Capture what is running, so it can be recreated.

TruthForm is infrastructure-as-code in reverse. You don't write IaC and then manage
state files. Instead, TruthForm reads the live system through the platform's own
APIs and writes a normalised snapshot that can recreate it. The live system is
the source of truth, so there is no state to manage. The snapshot is plain YAML
that you can review, commit and diff.

**Status: early development.** Kubernetes works end to end. AWS (every
Cloud Control type in the CloudFormation registry) passes its restore drill
against a schema-driven fake. It also passed the disaster drill against a
real account (`scripts/drill-aws.sh`: 21 resources across 17 types, an
IAM role, a managed policy and a Lambda function among them, all free
while empty, deleted and restored with no diff), but most types haven't met real AWS yet. Azure (every
type with a published definition) passes its drill against a fake, and the
disaster drill against a real subscription (`scripts/drill-azure.sh`: 7
free resources, from the resource group to role assignments and a lock,
deleted and restored with no diff). GCP (Cloud Asset Inventory
plus Discovery documents) passes its drill against a fake, and the disaster
drill against a real project (`scripts/drill-gcp.sh`). SaaS providers run on
one OpenAPI-driven engine: GitHub (a real read-only capture works) and
Cloudflare (fake only so far). A restore only creates what is missing;
`restore --update` also brings drifted resources back in line, and passed
against real AWS, Azure and GCP (each drill drifts resources by hand, then
requires an empty diff). Agents get the same knowledge over MCP
(`truthform mcp`): every field of a type, which are required, set by the
platform, secret or fixed at creation, with the platform's docs, plus
read-only capture and diff; restore is deliberately not a tool. See
[AWS](docs/architecture.md#aws-cloud-control-driven-by-the-registry). Other
platforms are on the [roadmap](docs/architecture.md#roadmap). It is a single Go binary, with no
Pulumi or Terraform dependency.

**Using TruthForm:** the [user guide](docs/guide.md) and the
[permissions](docs/permissions.md) to grant on each platform.

## Commands

```bash
go build -o bin/truthform ./cmd/truthform

truthform capture --context kind-src --out snap/ [--baseline base/] [--include-system]
truthform restore --context kind-dst --from snap/ [--secrets-from-context kind-src]
truthform diff    --context kind-dst --from snap/ [--baseline base/]
truthform compare snap-a/ snap-b/
truthform schema-diff old/ new/
truthform plan rebuild --from snap/   # offline: what a rebuild needs that the snapshot does not hold

truthform capture --platform aws --region eu-west-1 --profile sandbox --out snap/ [--types 'AWS::S3::*,AWS::IAM::Role']
truthform restore --platform aws --region eu-west-1 --profile dr --from snap/ [--values write-only.yaml]
truthform aws-coverage   # offline: what the public registry lets TruthForm capture

truthform capture --platform azure --subscription <id> --out snap/ [--types 'Microsoft.Network/*']
truthform restore --platform azure --subscription <id> --from snap/ [--values secrets.yaml]

truthform permissions --platform aws --account 111122223333 --principal arn:aws:iam::111122223333:role/ops [--write dir/]
truthform check --platform aws --region us-east-1 --profile truthform-reader
```

- **permissions** writes the grant TruthForm needs as a template for the
  platform's own tool and prints the commands to deploy, verify and remove
  it, with no placeholders. It grants nothing. See [docs/agents.md](docs/agents.md)
  for guiding someone through it.
- **check** names the identity TruthForm runs as, warns about root users,
  long-lived keys and write access a capture does not need, and runs a
  capture written nowhere to show what it can read, type by type.

- **capture** discovers every resource type the cluster serves, including custom
  resources no TruthForm code knows about. It keeps what someone configured and
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

## A whole environment in one command

```bash
truthform capture --config environment.yaml --out snap/   # every target, read-only
truthform diff    --config environment.yaml --from snap/  # drift, per target
```

The config lists each system (see `examples/environment.yaml`). Kubernetes
contexts, AWS regions, Azure subscriptions and GCP projects can be mixed.
Targets are captured in parallel into `snap/<target>/`. A target that fails
is recorded and does not stop the others. The exit code is the worst
result: `1` for a failed target, `3` for an incomplete one.

The config is strict. A misspelled key or a missing field fails before
anything runs, because a typo that silently dropped a cluster would produce
a snapshot that looks complete. Restore stays per target and deliberate.

Every snapshot gets a **`REPORT.md`** for people. It leads with anything
incomplete, then says what was captured, what was skipped and why, which
types weren't captured and why, and what is never in a snapshot by design
(data, secret values). The environment gets a summary report too.
`truthform report <dir>` regenerates one. Reports carry no timestamps, so an
unchanged system gives an unchanged report.

A capture of four sandboxes (kind-tiltdev, AWS, Azure, GCP), from one
config, took 29s and was complete.

## API fields keep up by themselves

Terraform and Pulumi build each API's fields into a provider release, so a
field an API added last month doesn't exist for them until a new provider
ships. TruthForm keeps no field list in its code:

- **Capture** reads whatever the live API returns, so new fields are captured
  as soon as the API serves them.
- **Each snapshot fingerprints the schema** that each captured type published
  at that moment, in `schemas/<group>/<version>/<kind>.yaml`. The field paths
  come from the API's own OpenAPI document.
- **`truthform schema-diff old/ new/`** shows exactly what each API added or
  removed between two captures, for example across a cluster or operator
  upgrade:

  ```
  changed       example.truthform.org/v1 Widget
      + spec.shape
  ```

- **Restore uses strict field validation,** so a field the target API doesn't
  know about fails loudly instead of being dropped.

## Rules it keeps

- **Capture and diff cannot write.** On every platform, they run behind a
  guard on the HTTP transport that refuses anything except reads and
  credential exchanges *before it leaves the machine*. It's an allow-list,
  so an unrecognised request is refused, never let through. `go build
  -tags captureonly` produces a binary with no working restore, in which
  every client sits behind the guard. That is the build to hand a client
  for information gathering.
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
  For a rebuild with no source cluster left, `--secrets-from` reads each
  from where a file of references says (1Password, Azure Key Vault, an
  environment variable, a file, a command); `truthform plan secrets`
  writes that file to fill in and checks it against each capture.
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
