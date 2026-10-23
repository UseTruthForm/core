# StackDNA user guide

StackDNA reads the live configuration of a cloud account, a Kubernetes
cluster or a SaaS organisation into a **snapshot**: plain YAML files you
can review, commit and diff. From a snapshot it can **diff** what is
running against what was captured, and **restore** what is missing, into
the same place or another account, subscription, project or region.

It is one binary with nothing to install, and it keeps no state: the
platform itself is the source of truth.

## Install

Download the archive for your platform from the release, check it against
`SHA256SUMS`, and put `stackdna` (or `stackdna.exe`) on your `PATH`:

```sh
sha256sum -c SHA256SUMS --ignore-missing
tar -xzf stackdna_0.1.0_linux_amd64.tar.gz
./stackdna_0.1.0_linux_amd64/stackdna version
```

There are two editions for every platform:

| Edition | Can | Use it for |
|---|---|---|
| full | capture, diff, restore | your own environments |
| capture-only | capture, diff | handing to a client for an assessment: it has no restore, and every request it makes goes through the read-only guard, so it cannot change anything it reaches |

`stackdna version` says which edition and build you have.

## Permissions

Give a capture a read-only role, and a restore a write role, separately.
[permissions.md](permissions.md) lists the exact roles per platform, and
which have been verified.

## Capture

```sh
stackdna capture --platform aws   --region us-east-2 --profile prod --out snap/aws
stackdna capture --platform azure --subscription <id>              --out snap/azure
stackdna capture --platform gcp   --project my-project             --out snap/gcp
stackdna capture --context prod-cluster                            --out snap/k8s
GITHUB_TOKEN=... stackdna capture --platform github --account my-org --out snap/github
```

A snapshot directory holds `objects/` (one YAML file per resource),
`schemas/` (the field list of every type, so schema changes show up),
`coverage.yaml` (what was read, what was skipped and why) and
`snapshot.yaml` (with a digest: two captures of an unchanged system have
the same one). **REPORT.md** beside it says, in plain words, what was
captured, what was not and why, and what a restore will need.

What a snapshot does not hold, by design:

- **data**: S3 objects, blobs, database rows, queue messages, volume
  contents;
- **secret values**: passwords, keys, a webhook's secret. They are named
  in the snapshot and given at restore with `--values`;
- **what the platform made itself**: default VPCs and their subnets,
  built-in roles, AWS-managed policies. Use `--baseline` with a capture of
  a fresh account to skip anything identical to it.

Limit a capture with `--types 'AWS::EC2::*,AWS::IAM::Role'`. A full AWS
region (about 1,500 types) takes around five minutes.

## Diff

```sh
stackdna diff --platform aws --region us-east-2 --from snap/aws
```

It lists what was added, removed or changed, field by field, and exits 2
when there are differences, so it can gate a pipeline or raise an alert.

## Restore

```sh
stackdna restore --platform aws --region us-east-2 --from snap/aws --values secrets.yaml
```

- **By default a restore only creates what is missing.** Something already
  there and identical counts as applied; something there but different is
  reported, with the fields that differ, and left alone.
- **`--update`** also brings differing resources in line with the
  snapshot. It never replaces a resource: a change the platform can only
  make by deleting and re-creating (an AWS create-only property) is
  refused and named.
- **References are remapped.** A subnet's VPC, a role's ARN, a principal
  ID: the snapshot holds references, not the source's IDs, and a restore
  resolves each to what the target created.
- **Into another region (AWS):** zones are paired by zone ID (printed);
  `--zone-map use2-az1=use1-az4` overrides a pair.
- **Several at once (AWS, Azure, GCP):** resources that do not depend on
  each other are created together (`--parallel`, 8 by default).
- **Secrets** come from a YAML file given with `--values`, keyed by
  resource. A restore says which secrets it was not given.

## A whole environment

List every system in one file and capture or diff them together:

```yaml
name: prod
targets:
  - {name: cluster, platform: kubernetes, context: prod}
  - {name: aws,     platform: aws, region: us-east-2, profile: prod}
  - {name: azure,   platform: azure, subscription: <id>}
```

```sh
stackdna capture --config prod.yaml --out snap/
stackdna diff    --config prod.yaml --from snap/
```

One target that cannot be reached is recorded as failed without stopping
the others. Restore stays per target, on purpose.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success: the capture is complete, the restore fully applied, or no differences |
| 1 | Error: bad flags, cannot connect, cannot read a snapshot |
| 2 | Differences found (diff, compare) |
| 3 | Incomplete: the snapshot was written but some types could not be read, or a restore applied only some resources |

## For AI agents (MCP)

`stackdna mcp` serves StackDNA's knowledge over the Model Context
Protocol. For every field of a resource type it says whether the field is
required, set by the platform, write-only, secret or fixed at creation,
with the platform's documentation link. It can also capture, diff and
read reports. No tool can restore. Add it to a client as:

```json
{"mcpServers": {"stackdna": {"command": "stackdna", "args": ["mcp"]}}}
```

## Known limits

- S3 bucket names are global: a bucket cannot be restored under the same
  name while the original exists, or in another region shortly after it
  was deleted.
- Data is never captured (see above).
- GitHub's environment wait timer and a few similar fields are accepted on
  write but never read back; a snapshot names them (`stackdna.org/unreadable`)
  and a restore says it could not carry them.
- Proven against real systems so far: AWS (17 resources across 14 types,
  restore, update, another region), Azure, Google Cloud, Kubernetes and
  GitHub capture. Cloudflare and Google Compute are proven against
  simulated APIs only.
