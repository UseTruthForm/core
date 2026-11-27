# TruthForm

**Capture what is running, so it can be recreated.**

TruthForm is infrastructure-as-code in reverse. Instead of writing IaC and
keeping state files in step with reality, you point TruthForm at what is
running: a Kubernetes cluster, an AWS account, an Azure subscription, a GCP
project, a GitHub or Cloudflare organisation. It reads it through the
platform's own APIs and writes a **snapshot**: plain YAML you can review,
commit and diff. From a snapshot it can:

- **diff** what is running now against what was captured, field by field;
- **restore** what is missing, into the same place or a fresh one;
- **translate** an Azure environment into AWS or GCP terms (beta).

There is no state to manage: the live system is the source of truth. It is
one Go binary, with no Terraform or Pulumi underneath, and it sends nothing
anywhere except to the platforms you point it at.

## Status

**Beta.** Snapshots are format 2, and every release reads snapshots from
earlier ones. What has been proven, and where:

| Platform | Captures | Proven against |
|---|---|---|
| Kubernetes | every type the cluster serves, custom resources included | capture, restore and diff on two real API servers in every CI run, and on two kind clusters with running controllers; real clusters read-only every day |
| AWS | every Cloud Control type in the CloudFormation registry | a fake driven by the registry's schemas; a real account deleted and restored with no diff (21 resources across 17 types, IAM included) |
| Azure | every type with a published API definition | a fake; a real subscription deleted and restored with no diff (7 resources, role assignments and a lock among them); an environment of 2,000+ resources captured read-only every day |
| GCP | every Cloud Asset Inventory type with a Discovery document | a fake; a real project deleted and restored with no diff |
| GitHub, Cloudflare | from each one's OpenAPI description | GitHub: a real read-only capture. Cloudflare: a fake only |

`restore --update`, which brings drifted resources back in line, passed on
real AWS, Azure and GCP. **Translate** (Azure to AWS or GCP) is newer: what
it writes restores into the fakes and has passed `restore --dry-run`
against a real AWS account and GCP project, but no translated snapshot has
been restored into a real one yet. What is not handled is listed in
[Known limits](docs/guide.md#known-limits).

## Install

From a [release](https://github.com/UseTruthForm/core/releases): download
the archive for your platform, check it, and put `truthform` on your `PATH`.

```sh
sha256sum -c SHA256SUMS --ignore-missing
tar -xzf truthform_<version>_linux_amd64.tar.gz
./truthform_<version>_linux_amd64/truthform version
```

Or with Go (the version in `go.mod`, currently 1.27.4; Go downloads it
itself unless `GOTOOLCHAIN=local`):

```sh
go install github.com/usetruthform/core/cmd/truthform@latest   # or, from a clone:
go build ./cmd/truthform
```

Every release comes in two editions. **Full** captures, diffs and restores.
**Capture-only** has no restore, and every request it makes goes through a
read-only guard, so it cannot change anything it reaches: build it with
`go build -tags captureonly -o truthform-capture-only ./cmd/truthform`.
`truthform version` says which you have.

## Try it in five minutes

No cloud account needed: [kind](https://kind.sigs.k8s.io/) and Docker are
enough.

```sh
kind create cluster --name tf-try --wait 2m
truthform capture --context kind-tf-try --out base/      # the empty cluster: what kind itself provides

kubectl --context kind-tf-try create namespace shop
kubectl --context kind-tf-try -n shop create deployment web --image=nginx
kubectl --context kind-tf-try -n shop create configmap settings --from-literal=colour=blue
kubectl --context kind-tf-try -n shop create secret generic db --from-literal=password=hunter2

truthform capture --context kind-tf-try --baseline base/ --out snap/
```

`snap/` holds four objects: the namespace, the Deployment, the ConfigMap
and the Secret. `snap/REPORT.md` says what was captured, what was skipped
and why. The ReplicaSet and Pods are skipped because the Deployment
recreates them; kind's own objects are skipped because they match the
baseline. The Secret holds its key names only: its value never reaches the
snapshot.

Now break something, and bring it back:

```sh
kubectl --context kind-tf-try -n shop delete configmap settings
kubectl --context kind-tf-try -n shop scale deployment/web --replicas=3

truthform diff --context kind-tf-try --baseline base/ --from snap/     # exit 2: one missing, one changed
truthform restore --context kind-tf-try --from snap/ --secrets-from-context kind-tf-try
truthform diff --context kind-tf-try --baseline base/ --from snap/     # no differences
```

Each line of `diff` names an object as `apiVersion|Kind|namespace|name`
and the field that differs. A snapshot captured with `--baseline` is diffed
with the same one: TruthForm refuses to compare under different rules.
Secret values are never stored, so `diff` sees a Secret's keys but not a
change to a value.

Restore needs the Secret's value from somewhere. Here it is read live from
the cluster itself (`--secrets-from-context`), straight from one API to the
other and never written to disk; without it, restore applies everything
else and says which Secret it could not. The same snapshot rebuilds the app
in a new cluster:

```sh
kind create cluster --name tf-new --wait 2m
truthform restore --context kind-tf-new --from snap/ --secrets-from-context kind-tf-try
truthform diff --context kind-tf-new --baseline base/ --from snap/     # no differences

kind delete cluster --name tf-new; kind delete cluster --name tf-try
```

A restore never deletes. On Kubernetes it re-applies what the snapshot
holds, and leaves alone fields that another tool added, which `diff`
still reports. For a cloud platform, start with `truthform permissions`
and `truthform check` in the [user guide](docs/guide.md).

## Documentation

- [User guide](docs/guide.md): every command, what a snapshot holds and
  what it never holds, restore, whole environments, translation, exit
  codes, known limits.
- [Permissions](docs/permissions.md): what to grant on each platform, and
  which grants have been verified against real accounts.
- [AI agents](docs/agents.md): TruthForm over MCP (`truthform mcp`). Agents
  get capture, diff and every type's fields; restore is deliberately not a
  tool.
- [Architecture](docs/architecture.md): how each platform adapter works,
  and the roadmap.
- [Development](docs/development.md): the restore drills and the local dev
  loop.

## Commands

```bash
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

truthform translate --from snap/azure --map map.yaml --out moved/   # offline: an Azure snapshot as AWS or GCP snapshots (beta)
truthform restore --platform aws --region eu-west-1 --profile dr --from moved/aws --dry-run   # what a restore would write; writes nothing

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
- **translate** rewrites an Azure snapshot as snapshots for AWS, GCP or
  the cluster, offline, from a map that says where each service class goes.
  It names every loss and refuses what it cannot carry; nothing gets a
  default. It is a beta: see [To another cloud](docs/guide.md#to-another-cloud-azure-to-aws-or-gcp).
- **restore --dry-run** (AWS, GCP, GitHub, Cloudflare) reads the target and
  prints each write a restore would make, with a client that refuses every
  write. Exit `3` when anything would not apply.
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

A capture of four sandboxes (a kind cluster, AWS, Azure, GCP), from one
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
  every client sits behind the guard. That is the build to hand to someone
  else for an assessment.
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

Every adapter passes the same drill: capture, restore into an empty target,
and require `diff` to find nothing. It runs against fakes and real API
servers on every pull request, and against real accounts on demand. See
[docs/development.md](docs/development.md).

## Contributing

Issues and pull requests are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md).
To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Licence

TruthForm is under the [Apache License 2.0](LICENSE).
