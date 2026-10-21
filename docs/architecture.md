# Architecture

## The idea

Infrastructure-as-code goes from code to cloud and keeps a state file that
records what it believes it created. That state drifts, gets corrupted and has
to be locked, imported and migrated. StackDNA goes the other way. It reads what
is actually running and writes a snapshot that can recreate it. The live system
is the source of truth, so nothing has to be kept in sync.

## Why not Pulumi or Terraform

The first sketch built on an earlier Pulumi project, which deploys
resources from any Pulumi provider out of one YAML file. We dropped that for
two reasons:

- **Dependencies.** Every Pulumi provider is a large plugin plus a language SDK.
  The platforms already expose uniform inventory APIs (Kubernetes discovery,
  AWS Cloud Control, Azure Resource Manager, GCP Cloud Asset Inventory), and a
  single Go binary can call them directly.
- **It didn't run.** On its own Kubernetes example (2026-10-21), pulumi-universal's
  `main.py` read every top-level config key as a provider, tried to pip-install
  packages such as `pulumi-labels`, and exited before creating anything. It also
  skips unknown resource types with only a warning, and a restore engine can't
  be allowed to do that.

## Pipeline

```
live system ──discover──▶ list every type ──policy──▶ normalise ──▶ snapshot/
                                              │                       │
                                       skip + reason            restore / diff
                                       (coverage.yaml)
```

1. **Discover.** Ask the platform what types exist. Kubernetes discovery returns
   every served type, including CRDs. A partial failure (one aggregated API down)
   puts that group into coverage as not captured, rather than failing the whole
   capture or silently leaving the group out.
2. **Policy.** For each object, decide whether recreating the system needs it.
   Each skip records a reason:
   - **Excluded types:** derived types, machine types or one-off types (events,
     endpoints, leases, nodes, CSRs).
   - **Owned objects:** anything a controller owns (ReplicaSets, Pods,
     ControllerRevisions) is recreated by that controller.
   - **Platform objects:** the system namespaces and objects the cluster creates
     itself, such as bootstrap RBAC, default service accounts and the root CA
     ConfigMap.
   - **Distribution baseline:** objects identical to a capture of a fresh cluster
     of the same distribution. A list of platform names is never complete, but a
     baseline is.
3. **Normalise.** Strip what the server generated, so the snapshot holds only
   configuration and the same live state always captures the same.
4. **Snapshot.** Each object goes to
   `objects/<group>/<version>/<kind>/<namespace|_cluster>/<name>.yaml`, with
   path segments escaped so they are safe on Windows. Alongside them go
   `coverage.yaml` and `snapshot.yaml`, which holds the format, platform,
   policy, object count and a digest over every file. Reading verifies the
   digest, so a hand-edited or half-copied snapshot is refused. A capture always
   rebuilds the objects folder, so deleted objects can't come back.
5. **Restore.** Server-side apply as the `stackdna` field manager, in phases:
   CRDs, then namespaces, then everything else, then admission webhooks.
   Every object ends up applied or reported as not applied, with the reason.
   Restore never deletes anything.
6. **Diff.** Capture the target under the same policy and compare. The policy
   (including the baseline digest) is recorded in the snapshot, so a diff can't
   accidentally compare two different rule sets.

## Schema reflection: fields are never hard-coded

This is the one thing other IaC tools struggle with. A provider release
freezes each API's fields, and keeping up means shipping releases forever.
StackDNA's rule is that no adapter may contain a field list:

- **Values** come from the live API as-is (the Kubernetes dynamic client).
- **Shape** comes from the schema the API publishes (Kubernetes OpenAPI v3).
  Each captured type's schema is flattened to field paths and fingerprinted
  into the snapshot.
- **Change** is what `schema-diff` reports between two snapshots. It is
  derived, not maintained.
- **Restore** validates strictly, so a field the target doesn't serve is an
  error, never a silent drop.

Every adapter follows the same rule, using the platform's own published
schema: CloudFormation registry schemas for AWS Cloud Control (done; see
below), the Azure REST API specs (`readOnly`), GCP discovery documents (output-only
fields), and vendor OpenAPI specs for SaaS. A refreshed schema arrives as a
schema-diff, not as a code change.

## Secrets

Values never enter a snapshot. A Secret is captured with its key names and
empty values, plus the annotation `stackdna.org/withheld-keys`. Restore refuses
those secrets unless it has a source for the values. Today that source is a
live cluster (`--secrets-from-context`), for migrations and drills. A vault
source comes next.

## AWS: Cloud Control, driven by the registry

`internal/awscc` has no code for any AWS type. Cloud Control is one generic
CRUD API across the CloudFormation registry, and each type's registry schema
says everything the adapter needs:

| Schema says | StackDNA does |
|---|---|
| `primaryIdentifier` | How to read it, and whether the user chose the ID (`BucketName`) or AWS generated it (`VpcId`) |
| `readOnlyProperties` | Moves those values out of `spec` into `status`. They are never sent back, and they are the targets of references |
| `writeOnlyProperties` | Drops them (AWS never returns them anyway), annotates the object with `stackdna.org/write-only`, and requires them at restore when they are also `required` |
| `handlers.list.handlerSchema.required` | Builds a list plan. An enum property (WAFv2 `Scope`) is listed once per value. Any other property comes from one parent type found by name, such as `RestApiId` from `AWS::ApiGateway::RestApi` |
| `insertionOrder: false` | Sorts the array canonically (tags, CIDR lists), so captures are deterministic |

Pointers are applied in full, including nested ones and `*` across arrays
(`/properties/Code/ZipFile`, `/properties/LifecycleConfiguration/Rules/*/Transition`).

**Coverage.** `stackdna aws-coverage` measures this from the public bundle,
using the adapter's own rules. The bundle had 1,854 types on 2026-10-21:

- 1,607 (87%) are capturable and creatable:
  - 1,286 are listed directly;
  - 12 are listed once per enum value;
  - 309 are listed per parent.
- 247 are not capturable, and each is named in `coverage.yaml`:
  - 60 have a parent the schemas don't identify (for example, QuickSight
    needs the account ID, and Organizations OUs nest under roots);
  - 78 have no list or read handler;
  - 109 are legacy CloudFormation-only types.

**Logical names.** Generated IDs differ in every account, so an object is
named the way a person named it:

1. its user-chosen identifier;
2. otherwise its `Name` tag;
3. otherwise a `Name` or `<Type>Name` property;
4. otherwise a hash of its spec after its references are tokenized (`h-…`).

Because the names are the same in every account, a snapshot from one account
diffs cleanly against another account. Naming walks the reference graph,
because a hash taken before the references were tokenized would contain the
source account's IDs.

**References.** A read-only identifying value that appears in another
resource's spec is replaced with a token that restore resolves to the value
the target account generated:

```yaml
Role: "{{stackdna|AWS::IAM::Role|shop-lambda|Arn}}"
```

These values count as identifying: the resource's identifier, `*Id`, `*Arn`
and `*Url` properties, and ARNs. IDs must match exactly. ARNs and URLs also
match inside larger strings, such as policy documents and environment
variables. A status word such as `available` is never a reference.

**Restore** first reads the target with the same naming rules, then creates
what is missing, in reference order:

- An object that already exists and is identical is reported as applied.
  This makes a second restore a no-op.
- An object that exists but differs is reported as not applied, with the
  differing fields. StackDNA doesn't update or delete anything.
- A token can resolve to a resource that wasn't in the snapshot but exists in
  the target. The target's default VPC is one example.
- Write-only values come from `--values <file>` and go only to AWS.

**Skipped by default, each with a reason:**

- resources tagged `aws:cloudformation:stack-name`, because the stack
  recreates them;
- resources carrying any other `aws:` tag;
- service-linked roles;
- anything identical to an account baseline (`--baseline`, a capture of a
  fresh account), such as the default VPC.

**Proof today: a fake that refuses what AWS refuses.** The drill
(`internal/awscc/drill_test.go`) runs `drilltest.Run` between two in-memory
accounts that share one ID space. A create that carries another account's
ID fails, as `InvalidVpcID.NotFound` would. Without that refusal, a restore
that never remapped anything would pass. Mutation checks confirm that
disabling tokenization, set sorting or the managed-resource skip each fails
the suite.

**Not yet verified against AWS.** `sdk.go` compiles against aws-sdk-go-v2,
but it has never called AWS. The first sandbox recording session is meant to
find what the fake can't know:

- types that reject their own read output on create (for example, a subnet
  returning both `AvailabilityZone` and `AvailabilityZoneId`);
- list parameters that a schema leaves out;
- whether API Gateway lists the root resource;
- throttling across about 1,300 list calls.

**Known limits:**

- S3 bucket names are global, so a cross-account restore of a user-named
  bucket fails while the source bucket exists.
- Account IDs in references to resources outside the snapshot stay literal.
- StackDNA never updates an existing resource.
- Data is never captured: S3 objects, queue messages and table rows.

## Roadmap

| Step | What |
|---|---|
| Next | Vault and file sources for secret values; PersistentVolume handling (claims are captured, but volume **data** is not, and the snapshot must say so); `--json` output |
| AWS | One recording session against a sandbox account, which turns `sdk.go` from unverified into verified, keeps the session as replay fixtures, and fixes what it finds; account-ID tokens; Secrets Manager values read live from a source account, as `--secrets-from-context` does for Kubernetes |
| Platforms | Azure via Resource Graph plus ARM `GET`/`PUT` per resource ID; GCP via Cloud Asset Inventory |
| SaaS | GitHub, Cloudflare, Okta, Datadog and similar, through their REST APIs, each with an explicit schema of configured fields versus computed fields |
| Agents | A small MCP server (`discover`, `diff`, `snapshot`, `explain`), read-only against live systems by default. Agents watch for drift and open PRs; CI regenerates snapshots deterministically, so a PR shows only real change |
| Proof | Scheduled restore drills per platform: restore into a sandbox and require an empty diff |

## Prior art to compare against

Not yet researched in depth. Before the first cloud adapter, compare what
Terraformer, Former2, aztfexport, Terracognita, `pulumi import`/`convert`,
`gcloud resource-config bulk-export`, Firefly and ControlMonkey each do, and
where they stop. The likely differences to test, rather than assume: one
snapshot format across cloud **and** SaaS; no state files; deterministic CI
updates; secrets kept out by construction; and restores proven by drill.
