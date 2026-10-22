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

**Proof against real AWS: `scripts/drill-aws.sh`.** This is the disaster
case, run in one region:

1. seed an app with the plain AWS CLI;
2. capture it twice, requiring identical digests;
3. delete the app;
4. restore from the snapshot;
5. require an empty diff;
6. delete everything again, then require that the region diffs clean against
   its pre-drill baseline, so a leaked resource fails the run.

It uses free-tier resources only (VPC, subnet, SQS, SSM Standard parameter,
API Gateway REST API and resource) and takes about 6 minutes. It passed in
us-east-2 on 2026-10-21 with 6 of 6 resources restored under new IDs.

The first runs found four things the fake had not modelled. Each one is now
pinned in the fake tests:

- **API Gateway lists each REST API's root resource**, which AWS creates
  along with the API. Capture now skips any resource whose generated ID
  another resource reports as a read-only property (here the API's
  `RootResourceId`), and routes references through that parent. The same
  rule covers a VPC's default security group and network ACL.
- **A subnet reads back both `AvailabilityZone` and `AvailabilityZoneId`,
  but a create with both is refused.** The schema doesn't declare this. The
  zone name is an account-relative alias, so it moves to `status` and the
  spec keeps the ID. This is the only type-specific entry (`aliases` in
  `capture.go`), and it names the failure that found it.
- **List APIs are eventually consistent.** A capture taken seconds after a
  create missed an SQS queue, so the two captures differed. The drill now
  waits until Cloud Control lists what it created. A real capture can
  likewise miss anything created in the last minute or so.
- **SQS holds a deleted queue's name for 60 seconds.** A restore right after
  a deletion fails with `QueueDeletedRecently`.

**Full-registry capture against real AWS.** It runs read-only across all
1,498 types in us-east-2: 4m52s at 8 calls in flight, nothing lost to
throttling, and two consecutive runs byte-identical. Getting there took
six runs. Each one found something that only a real account shows:

| Run | Time | What went wrong, and the fix |
|---|---|---|
| Serial | 32 min | Writing failed on one AWS SSM document containing a character YAML refuses (DEL, C1 controls), so nothing was saved. Such characters are now escaped, and PyYAML reads them back exactly. |
| 8 in flight | 7 min | 188 types lost to "retry quota exceeded", the SDK's client retry budget. Also, 2,391 "resources" were captured, about 2,300 of them AWS's own: managed IAM policies, public SSM documents, RAM permissions, default parameter groups. |
| Adaptive retry | 52 min | Adaptive mode slows the whole client when any one service throttles. |
| Standard retry | 40 min | Long SDK retries held the in-flight slots while sleeping. 34 reads that always fail with HTTP 500 (CodePipeline's built-in action types) stalled everything for 21 minutes. |
| Retry outside the slot | 4m52s | The SDK retries briefly. The inventory retries throttling with the slot released, and work is interleaved across services. |

**AWS-owned resources are skipped by rule, not by a list.** There are
three rules:

- an ARN in AWS's namespace (`arn:aws:iam::aws:…`, or an empty account
  with a region set);
- an ARN naming a different account (AWS's patch baselines belong to
  `733109147000`, and a resource can also be shared in from elsewhere);
- a name prefix AWS reserves (SSM `aws*`, KMS `alias/aws/`, and others).

Only a resource's own read-only ARN counts. A customer role that points
at an AWS-managed policy stays the customer's. In the sandbox this
reduced 2,391 "resources" to 86, and skipped 2,958 with reasons.

**Every type that isn't captured is in one of five groups:**

- AWS-owned;
- not set up in this account (53 types, such as Audit Manager and
  Control Tower);
- needing list input that its schema doesn't declare (63 types, such as
  lifecycle hooks, which need an Auto Scaling group). These are real gaps,
  and the summary says so;
- permission denials;
- AWS's own handler errors.

Only the last two count as incomplete: 23 types, plus 41 AWS built-ins
whose read handlers fail.

**Still unverified against AWS:**

- restore beyond the 6 types the drill used (the full capture proves
  reading, not recreating);
- IAM (the sandbox user can list roles but not read them);
- cross-account restore;
- the Lambda and Secrets Manager write-only paths, which are proven only in
  the fake.

Cross-region restore also needs a zone mapping. Zone IDs are region-specific,
so a subnet captured in one region can't be created in another as it stands.

**Known limits:**

- Cross-region restore of subnets needs a zone mapping (see above).

- S3 bucket names are global, so a cross-account restore of a user-named
  bucket fails while the source bucket exists.
- Account IDs in references to resources outside the snapshot stay literal.
- StackDNA never updates an existing resource.
- Data is never captured: S3 objects, queue messages and table rows.

## Azure: Resource Manager, driven by Azure's published definitions

`internal/azarm` follows the same rule as AWS: there is no code for any Azure
type.

| Source | What it gives |
|---|---|
| **bicep-types-az**, generated by Azure from the REST API specs; Bicep's own type data | Every property's flags: required, read-only, write-only. Its string type is marked `sensitive` for secrets. A VM's `adminPassword` is *sensitive*, not write-only, so both count as secrets. Also every field path, for `schema-diff`. |
| **Provider registrations** (`GET /subscriptions/{id}/providers/{namespace}`), live | The API versions each type offers in *this* subscription. Capture uses the newest stable version that also has a definition. If none has one, the type is reported as incomplete, never skipped silently. |
| `GET /subscriptions/{id}/resources` and `/resourcegroups` | What exists. |
| `GET`/`PUT` per resource ID | Read and recreate. `PUT` waits for long-running operations through the Azure SDK's poller. |

**Why ARM's own list and not Resource Graph,** which the roadmap had
planned: Resource Graph is an indexed copy that can lag behind changes. The
AWS drill showed what an eventually consistent list does to a capture taken
straight after a change: the two captures differed. Resource Graph can come
back if subscription-wide listing proves too slow.

**References are simpler than on AWS.** People choose Azure resource names,
so a resource ID changes between subscriptions only in its subscription.
Capture turns the subscription and tenant IDs into tokens wherever they
appear, **including map keys**. A site's `identity.userAssignedIdentities`
is keyed by the identity's full resource ID; a value-only rewrite would
have pointed a restored site at the source subscription. The fake refuses
other subscriptions' IDs in keys too.

**Restore** puts resource groups first, then parents before children, then
each resource after the resources its IDs point at. It checks the target
first: an identical resource is reported as present, a different one is
reported and left unmodified. Secrets come from `--values` (keyed
`Kind/resourceGroup/name`). A secret whose parent object exists in the
spec, such as `osProfile.adminPassword`, is reported as "not supplied" when
missing, because a VM restored without its password is configured but
unusable.

**Skipped by default:** resources with `managedBy` set (an AKS cluster's
node resource group and its contents), and anything identical to a
subscription baseline (`NetworkWatcherRG`).

**Proven against a fake only, so far.** The drill runs between two fake
subscriptions in different tenants, using the trimmed real definitions in
`testdata/azure/types`. Those are regenerated from Azure's repository with
`STACKDNA_REGEN_AZURE_FIXTURES=1 go test -run Regenerate ./internal/azarm/`.
It covers a resource group, NSG, VNet with a subnet referencing the NSG,
managed identity, storage account, App Service plan and site, and a VM. The
drill passes. Mutation checks confirm that dropping subscription tokens,
key rewriting or dependency order each fails it.

**Proof against real Azure: `scripts/drill-azure.sh`.** It's the same
disaster case as on AWS: seed with the `az` CLI, capture twice, delete the
resource group, restore, require an empty diff, clean up, then require the
subscription to match its baseline. It uses free resources only (resource
group, NSG, VNet with a subnet referencing the NSG, managed identity). It
passed on 2026-10-21 in a personal sandbox subscription: 4 of 4 restored,
empty diff, subscription clean afterwards. A full read-only capture of the
same subscription took 13s.

The first runs found three things the fake had not shown:

- **The SDK rejects `v0` as a client version;** it wants full semver.
- **Managed identities answer `PUT` synchronously** (200 or 201 with no
  operation header), and the SDK's poller refused that response as an
  "invalid polling URL". Only asynchronous answers go to the poller now.
  Synchronous ones are read until `provisioningState` is final.
- **Definitions lag the API.** A subnet returns `resourceGuid`, which the
  `2026-03-01` definition doesn't declare, so a restored VNet showed it as
  drift. `provisioningState` and `resourceGuid` are set by the server under
  ARM's resource-provider contract, so they're treated as read-only even
  when undeclared. Every other undeclared field is still kept.

A web app was meant to test, against real Azure, a map keyed by resource
ID (`identity.userAssignedIdentities`). The subscription's Free (F1) App
Service quota is 0, so for now only the fake covers that case.

**Known limits:**

- Only tracked resources are listed. Proxy resources that the subscription
  list doesn't return (role assignments, diagnostic settings, most
  children) are not captured unless their parent's body includes them, as
  a VNet's includes its subnets.
- Data is never captured.
- Restore never modifies an existing resource.

## Roadmap

| Step | What |
|---|---|
| Next | Vault and file sources for secret values; PersistentVolume handling (claims are captured, but volume **data** is not, and the snapshot must say so); `--json` output |
| AWS | A full-registry read-only capture of the sandbox, to see which types fail to list and how throttling behaves; the drill extended to IAM and Lambda once the sandbox user can read roles; replay fixtures recorded from real responses; a zone mapping for cross-region restore; account-ID tokens; Secrets Manager values read live from a source account, as `--secrets-from-context` does for Kubernetes |
| Azure | A real-subscription drill (free tier); proxy resources (role assignments, diagnostic settings) through their parents' list endpoints; principal IDs as references, so role assignments can be remapped |
| Platforms | GCP via Cloud Asset Inventory |
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
