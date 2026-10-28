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

## The read-only guarantee

`internal/readonly` is an `http.RoundTripper` that every platform's client
goes through:

- AWS, through the SDK's HTTP client option;
- Azure, through the ARM client's transport;
- GCP, beneath the OAuth transport;
- Kubernetes, through client-go's transport wrapper.

It allows only these requests:

- `GET` and `HEAD`;
- credential exchanges: AWS STS and SSO, Azure and Google token endpoints,
  and the EC2 metadata token;
- AWS JSON-RPC calls whose `X-Amz-Target` names a read
  (`CloudApiService.ListResources`, `GetResource`, ...). Cloud Control
  sends every call as `POST /`.

Anything else is refused before it is sent. Capture, diff and reading
secrets from a source cluster always run behind it; restore does not,
except in the capture-only build.

Proof:

- Each real client was driven against a local server: reads arrived,
  writes never did.
- The Kubernetes drill captures its source through a guarded client, then
  attempts a guarded restore. Every object is refused, and the target is
  unchanged.
- Read-only captures of the AWS, Azure, GCP and Kubernetes sandboxes ran
  through the guard with no refusals.
- Mutation checks: an allow-all guard, or an unguarded Kubernetes client,
  fails the tests.

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

It uses resources that cost nothing while empty, chosen for the
references between them:

- a VPC, subnet and security group with an ingress rule (the group's rules
  are also listed as `SecurityGroupIngress`/`Egress` resources of their own);
- two SQS queues, one the other's dead-letter queue, whose ARN sits inside
  the `RedrivePolicy` JSON string;
- an SNS topic, and a DISABLED EventBridge rule that targets it by ARN;
- an SSM Standard parameter, an API Gateway REST API and resource, a log
  group, an ECR repository and an S3 bucket.

It passed in us-east-2 on 2026-10-22: 17 of 17 resources across 14 types
restored under new IDs, an empty diff, and the region back to its
baseline. The whole drill takes about 14 minutes; the restore takes 135s.

**Restores run in parallel along the dependency graph.** Each resource
starts as soon as everything its references name is done, up to
`--parallel` at once (8 by default); results keep the dependency order, so
reports and diffs do not change. One at a time, the restore took 4m33s,
mostly waiting on Cloud Control's own handlers (about 60s for each SQS
queue and for the EventBridge rule) for resources that did not depend on
each other. In parallel it is bounded by the longest chain (the
dead-letter queue, then the queue that uses it: about 130s). Measured on
the real drills, each run back to back on the same day:

| Drill | One at a time | In parallel |
|---|---|---|
| AWS, 17 resources | 4m33s | 135s |
| Azure, 7 resources (one long chain: group, NSG, VNet; identity, role assignments; the lock last) | 23s | 19s |
| GCP, 2 independent resources | 10s | 4s |

The gain grows with breadth: a real account is wide and shallow, so
hundreds of resources take about as long as their longest chain rather
than their sum. A create refused for throttling before AWS accepted it is
retried with backoff (the account's rate is shared now); one accepted and
then failed inside its handler is reported, not repeated, since it may
have done part of its work. GitHub and Cloudflare restores still run one
at a time.

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

Broadening the drill (2026-10-22) found eight more:

| Symptom | Cause, and the fix |
|---|---|
| SNS create failed: "Unknown attribute ArchivePolicy" | A standard topic reads back `ArchivePolicy: {}`. An empty object means unset, so it is not kept. |
| The VPC's `Name` tag became a reference to the ECR repository of the same name | A chosen name (one the user picked, the same in every account) inside a tag is a label. It no longer becomes a reference; a generated ID in a tag still does. |
| The drill VPC's default security group was captured, and its restore collided with the one AWS makes | The group reports its own ID as `GroupId`, which hid the VPC's `DefaultSecurityGroup` claim. A resource's own ID no longer counts. |
| The default group's rules "depend on" the group, which is never restored | `DefaultSecurityGroup` isn't an `*Id` name, so it wasn't a reference source. An AWS-created child's ID now refers through the parent property that reports it. |
| One rule create spun for 257s, then "InternalFailure Resource Handler Internal Failure" | A rule reads back `GroupId` and `GroupName`, and `SourceSecurityGroupId` and `SourceSecurityGroupName`; sent both, the handler fails. A second `aliases` entry, confirmed by a probe that sent each form alone. |
| `SourceSecurityGroupOwnerId: "999988887777"` in the spec | The capturing account's ID is now a token wherever it is structural (a whole value, or an ARN's account segment) and resolves to the target's account. Prose is left alone. |
| Cloud Control reported a bucket created, then "Bucket not found" on the next read | Eventual consistency after a delete and re-create. A read that follows a successful create is retried for up to two minutes. |
| The restore note said a group's ingress rules were write-only | Only `SecurityGroupIngress[].SourceSecurityGroupName` is. Notes and annotations now name exact field paths. |

A create can also make other resources as a side effect: a group's inline
rules are listed again as rule resources, and a VPC brings a default group
with rules. When a create is refused, restore rereads the target, and an
object now present and identical counts as applied. In probes Cloud Control
adopted such duplicates without complaint; the fake refuses them, which is
the stricter case.

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

- restore beyond the 17 types the drill uses (the full capture proves
  reading, not recreating);
- IAM beyond a role and a customer managed policy (the drill restores
  those since 2026-10-24);
- cross-account restore;
- the Secrets Manager write-only path, which is proven only in the fake
  (Lambda's, the function's code given with `--values`, passed the real
  drill on 2026-10-26).

**Restoring into another region.** A snapshot records its region
(`serverVersion: cloudcontrol/us-east-2`). Restored or diffed in another
region, it is retargeted first:

- Zones are paired one to one in zone-ID order (use2-az1 to use1-az1, and
  so on), which keeps resources that were in different zones in different
  zones. `--zone-map use2-az1=use1-az4` overrides a pairing. The pairing is
  printed, because it decides where subnets land. Zone names alone would
  not do: in the sandbox account us-east-1c is use1-az4.
- The region is replaced where it is structural: a whole value, or an
  ARN's region segment, also inside a JSON string. Prose is left alone.
- A zone with no counterpart (a six-zone region into a three-zone one)
  refuses the whole restore before anything is sent, naming what uses it.
- Both regions' baselines go in the capture policy
  (`--baseline base-us-east-2,base-us-east-1`), so each region's default VPC
  and subnets are skipped.

Each region's zones come from one EC2 `DescribeAvailabilityZones` call,
signed with the SDK's own signer and sent as a GET, so it passes the
read-only guard and needs no EC2 SDK module. Only the `aws` partition's
endpoint is known.

`TARGET_REGION=us-east-1 scripts/drill-aws.sh` seeds and captures in
us-east-2, deletes the app there, restores into us-east-1, diffs, runs the
update phase there and cleans both regions. It passed on 2026-10-22: 16 of
16 resources across 13 types, an empty diff, and both regions back to
their baselines. Its first run found a nil HTTP client in the zone lookup
(a panic: without the read-only guard the SDK config carries no client).
The fake cannot catch that; a probe through and without the guard now
lists both regions' zones.

**Known limits:**

- S3 bucket names are global. A cross-account restore of a user-named
  bucket fails while the source bucket exists, and a cross-region one fails
  while S3 still holds a name just deleted ("A conflicting conditional
  operation is currently in progress"; Cloud Control took 3m15s to say so).
  In a real region loss the name stays taken, so a bucket restored
  elsewhere needs another name. The cross-region drill leaves the bucket
  out for this reason.
- An existing resource is updated only with `--update` (see "Restore into
  a target that already has things").
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
  when undeclared. Every other undeclared field is still kept, except an
  empty object: it holds no settings, and Azure returns some only
  sometimes (a Service Bus rule's `sqlFilter.parameters`), which made two
  captures of an unchanged subscription differ.
- **Observations are not status.** `status` keeps the read-only values a
  reference can point at: IDs, GUIDs, host names. Times, counters and
  flags (`accessedAt`, `earliestRestoreDate`, message counts) change on
  their own, so they are left out, and an unchanged subscription captures
  to the same digest.

A web app was meant to test, against real Azure, a map keyed by resource
ID (`identity.userAssignedIdentities`). The subscription's Free (F1) App
Service quota is 0, so for now only the fake covers that case.

**What the resource list doesn't return is discovered too:**

- **Extension resources** are listed across the subscription: role
  assignments, custom role definitions, locks and policy assignments.
  Diagnostic settings are listed on the subscription and on every tracked
  resource. Assignments inherited from a management group are recorded as
  "assigned above this subscription" and not restored. Built-in roles are
  counted, not listed.
- **Children** are found generically. The provider registration lists each
  type's child types (`storageAccounts/blobServices`, ...), and ARM lists
  any child collection at `{parentId}/{child}`, to a depth of three. A child
  the parent manages inline (a VNet's `subnets`) is skipped, and so is a
  type no one can write (`writableScopes: 0`, such as an NSG's
  `defaultSecurityRules`, which Azure defines).
- **IDs:** every object keeps its tokenized ID. An extension resource's
  scope can't be rebuilt from kind and name, and restore `PUT`s to it,
  after its scope exists. A resource reachable two ways (tracked, and its
  parent's child) is captured once.
- **Principal references.** Restoring a managed identity creates a new
  principal. A read-only GUID of a captured resource (its `principalId`)
  that appears in another spec becomes a reference, resolved from the
  target. A role assignment therefore follows the restored identity,
  instead of granting access to an object ID that no longer exists. This
  needed one more fix: a whole read-only `properties` object (an
  identity's) used to be dropped without keeping its values.

The real drill covers this: a Reader assignment for the identity, and a
lock on the group. The restored assignment named the restored identity's
new principal, checked with `az`.

**Known limits:**

- Role assignments across tenants: a principal from another tenant does
  not exist in the target, and the assignment fails with
  `PrincipalNotFound`.
- Custom role definition IDs are unique per tenant. Restoring one into
  another subscription of the same tenant conflicts while the source's
  exists.
- Data is never captured.
- An existing resource is modified only with `--update`.

## GCP: Cloud Asset Inventory, driven by Discovery documents

`internal/gcp` follows the same rule: there is no code for any Google type.

| Source | What it gives |
|---|---|
| **Cloud Asset Inventory** (`assets.list`, content `RESOURCE`) | What exists. For each resource it also names the Discovery document, version and schema. |
| **Discovery documents**, live and cached for a day | Output-only fields, from the `readOnly` flag or the "Output only" wording Google's guidelines require. The `get` and `create` methods for each collection, chosen by matching the name pattern. Whether a create takes the resource itself (`LogMetric`) or a request that wraps it (IAM's `CreateServiceAccountRequest`, which holds `serviceAccount` and `accountId`). Also every field path, for `schema-diff`. |
| `GET` by URL, then `POST` to the create method | Each resource is read fresh, because Cloud Asset Inventory's copy can lag. Restore uses `POST` and waits for long-running operations. |

**Rules taken from Google's API guidelines, not from any one type:**

- `createTime`, `updateTime`, `deleteTime`, `uid` and `etag` are output-only
  on every resource (AIP-148), flagged or not.
- An ID made of digits or a UUID was assigned by the server; user-chosen
  IDs follow `[a-z][a-z0-9-]*`. Such resources (Monitoring notification
  channels) get a logical name from their `displayName`.
- References to server-assigned names become tokens, named relative to
  the project. Every name nested under a server-named resource (an alert
  policy's conditions) is dropped as server-assigned.
- IDs starting with `_` are reserved by the service (Logging's `_Default`),
  and service accounts outside the project's own domain belong to Google.
  Both are skipped.

One fact is specific to one type, with the reason in the code: IAM names a
service account by its email but creates it from the email's local part.

**Proven against a fake only, so far.** The drill runs between two fake
projects, using trimmed real documents (`testdata/gcp/discovery`). It covers
a service account, custom role, log metric, notification channel, and an
alert policy that references the channel by its server-assigned name.
Mutation checks confirm that dropping project tokens, reference tokens,
nested-name removal or the Google-owned skip each fails it.

**Proof against a real project: `scripts/drill-gcp.sh`.** It's the same
disaster case. It passed in a personal sandbox project, with billing
disabled, on 2026-10-21. Both resources were restored: a service account,
and an email notification channel whose ID the server assigns. The diff was
empty and the project was clean afterwards. A read-only capture of the
project takes about 2s.

Cloud Asset Inventory lags changes by a minute or so, so the drill retries
reads after each change and logs how long they took to settle.

The real project found five things the fake had not shown. Each is now
pinned in the fake tests:

- **Cloud Asset Inventory names service accounts by numeric `uniqueId`,**
  while IAM names them by email. Taken from the inventory, every service
  account looked server-named, and Google's default accounts passed the
  domain check. The resource's own `name` from `GET` is now canonical.
- **Schema names differ between the inventory and the document.** The
  inventory calls a Service Usage service `Service`; the document calls
  the schema `GoogleApiServiceusageV1Service`. Matching falls back to the
  name pattern alone.
- **"Must not specify service_account.name":** when a create takes the ID
  separately (AIP-133), the name is identity, not input, and is no longer
  sent.
- **Monitoring's audit records (`MutationRecord`) are server-written** but
  flagged nowhere. They are treated as output-only by type.
- **The project, its billing link and enabled APIs are listed as
  resources.** They are captured as project-level and never restored. A
  restore runs into an existing project and must never link billing or
  enable APIs, because both can spend money.

**Not in the real drill, and why:**

- Log metrics: creating one needs billing (`BILLING_DISABLED`).
- Custom roles: a deleted role's ID can't be reused for 37 days, so
  delete-then-restore in one project can't succeed. Restoring them needs
  `undelete`, which isn't implemented.
- Alert policies: Cloud Monitoring charges for alerting conditions.

All three are covered by the fake.

**Compute-style APIs.** Compute names each path segment
(`projects/{project}/regions/{region}/subnetworks/{subnetwork}`) where
other documents take one `{+name}`. Names are matched against the whole
template, each parameter by its own pattern, and URLs are filled segment
by segment: a get takes the item's name, an insert its parent, and the
template supplies the collection word. Compute answers every write with
its own operation (`kind: compute#operation`, `status: DONE`, no `done`
field, no name under `operations/`), which is polled through its
`selfLink` before the resource its `targetLink` names is read; missed, a
restore would have recorded `operation-1730...` as the new resource's
name. A fake drill restores a network, a regional subnetwork and a
firewall that names the network by URL.

Two bugs that were not Compute's alone:

- A create's `requestId` (AIP-155, an idempotency UUID that Compute and
  many AIP APIs take) was read as the new resource's ID, as `secretId` is,
  so the name would have gone into the token and out of the body.
- Creation order followed only the tokens for server-assigned names. A
  user-named resource referenced by its name (a firewall's network,
  `.../global/networks/shop-net`) could be created first: Firewall sorts
  before Network. Order now follows those names too, and the fake refuses
  a reference to a resource it serves but does not hold, as Google does.

**Known limits:**

- A project ID written into free text, such as a log filter
  (`resource.labels.project_id="..."`), is not tokenized. Only names, emails
  and exact values are.
- Compute is driven through the fake only: Compute needs billing, which
  the sandbox project does not have. Real Compute may hold fields the fake
  cannot show to be server-set: Compute's own description does not flag
  `Subnetwork.fingerprint` (a hash of the resource) output only, so it is
  captured, and against a real project it would likely read as drift.
- Data is never captured.

## SaaS: GitHub and Cloudflare, driven by their OpenAPI descriptions

`internal/saas` is one engine for any provider with an OpenAPI
description. Each provider has a descriptor, which is data. It names the
API root, the envelope and paging conventions, and its configuration
collections (path templates, how their parameters bind, which fields name
an item). An OpenAPI description says how to call an endpoint but not which
ones hold configuration rather than activity, so that part is declared.
Everything else comes from the description:

- **What is kept is what the writes accept.** That is the union of the
  create and update request schemas, with `allOf`, `oneOf` and `anyOf`
  merged. A Cloudflare DNS record is one of a dozen record types. GitHub
  flags 0 of the 105 fields of a repository read-only, so flags can't be
  relied on. A field only the response has (`stargazers_count`,
  `created_at`) is server-computed by definition.
- **Masked values** (GitHub answers a webhook secret as `********`) are
  never kept. They are annotated, supplied at restore with `--values`, and
  named in the result when missing.
- **The account is tokenized only where it is structural**: an exact value,
  or a path or URL segment. The StackDNA organisation's repository
  describes itself as "StackDNA core: ...", and replacing the name in prose
  would rewrite the description in every target.
- **A feature the plan lacks is not a failure.** Each provider lists its own
  refusal messages ("Upgrade to GitHub Pro"), and those collections are
  recorded as not available.
- Restore creates parents first, applies an update for settings the create
  doesn't take, and recognises existing items by name. With `--update` it
  brings differing items in line (see below).

| | Proof |
|---|---|
| GitHub: repositories, labels, webhooks, rulesets | A fake drill. Plus a real read-only capture of the StackDNA organisation: 2 repositories, 19 labels, rulesets correctly "not available on this plan", complete |
| Cloudflare: zones, DNS records | A fake drill only; no API token on the dev machine |
| GitHub, derived (Actions settings, variables, secrets, environments, org issue fields, code-security configurations, ...) | A derived drill. Plus a real capture of StackDNA: 36 items across 18 collections; 10 organisation collections need an org-admin token |

**GitHub's collections are derived, not listed.** The description tags
every operation with a category. The descriptor names the configuration
categories and the activity subcategories to leave out. A list `GET`
(bare, or wrapped as `{total_count, variables: [...]}`) paired with its
create (`POST` to it, or `PUT` to its item path) is a collection, and
`GET` plus `PUT` on one path is a singleton setting. Over the full
description that gives 37 collections; new API areas arrive with the
description. Items named only by a server ID, or keyed by another
resource's ID, are not portable and are left out.

Secrets are captured as names only. A restore names the required inputs
no read returns (`encrypted_value`, `key_id`) unless they are supplied.
GitHub answers 404 both for "not enabled" and for "not visible to this
token", and the report says exactly that.

The fakes serve both providers over HTTP, from the descriptor and the
description: they route by the spec's templates, refuse unknown body
fields, add server-computed fields, mask secrets, page in twos, wrap
Cloudflare's envelope, and refuse references to another account. Mutation
checks: keeping every field, skipping tokenization, keeping masked
secrets, reading one page only, and tokenizing inside prose each fail the
tests.

## Restore into a target that already has things

By default a restore only creates what is missing. Something already
present and identical counts as applied; something present but different
is reported, with the fields that differ, and left alone (exit 3). An
update changes a resource that something may depend on as it is, so it
is a choice: `restore --update` brings differing resources in line. Each
platform uses its own update path, derived from the same schemas that
drive capture:

| Platform | How | Refused, by design |
|---|---|---|
| AWS | Cloud Control `UpdateResource` with a JSON Patch, one operation per top-level property: add, replace, or remove what the snapshot doesn't have | A change to a property the schema marks `createOnlyProperties`: AWS would replace the resource, deleting what depends on it. The result names the fields. |
| Azure | A PUT of the snapshot's body; ARM updates in place and never re-creates | A resource with secret fields Azure never returns (a VM's admin password) unless they are supplied with `--values`, since a PUT without them would send the resource without its credential |
| GCP | The collection's `patch` method from its Discovery document, else `update`; the body is what the method takes (the resource, or a request holding it), and the `updateMask` names exactly the fields that differ, removed ones included | |
| GitHub, Cloudflare | The collection's update operation from the OpenAPI description, else the PUT that creates it (an environment, a variable) | Masked secrets (a webhook's), unless supplied |
| Kubernetes | Server-side apply, which always updates | |

A setting with no list (GitHub Actions permissions) is applied without
`--update` only when the same restore created its parent; on an existing
repository it needs `--update` like anything else.

On Azure, a dependency that is present but different no longer blocks
what depends on it: a web app and a role assignment had been reported "not
restored" because the identity they name differed only in a tag.

**Fields a read never returns.** Restoring into a drifted GitHub
repository found that an environment's `wait_timer` had never been
captured. GitHub accepts it on write and returns it only reshaped inside
`protection_rules`, so capture, which keeps what writes accept and reads
return, dropped it without a word, and the earlier drill passed because
both sides lacked it. Each object now carries a
`stackdna.org/unreadable` annotation naming such fields (state both the
create and the update accept, absent from the read's response schema), and
a restore says it could not carry them. In the real StackDNA organisation
it names one: a code-security configuration's `code_security` and
`secret_protection`.

## Agents: the MCP server

`stackdna mcp` serves StackDNA to an agent over the Model Context Protocol
(JSON-RPC on stdin and stdout; no MCP dependency in the binary). An agent
building on a platform needs to know what a resource takes before it
writes one. StackDNA already reads that from each platform's published
schemas to capture and restore, so it says it:

| Tool | What it does |
|---|---|
| `platforms` | What StackDNA covers on each platform, and each platform's own MCP server |
| `list_types` | Resource types from the published schemas (AWS registry, Azure definitions, a GCP API's Discovery document, a SaaS description) |
| `describe_type` | Every field of a type: required, read-only (set by the platform), write-only, secret, create-only (changing it replaces the resource), with the platform's documentation links |
| `capture`, `diff` | Read a live target into a snapshot, or compare one with it |
| `report` | A snapshot's REPORT.md |

**Every tool is read-only, and there is no restore tool.** Describing
reads public schemas; capture and diff run through the read-only guard as
always. Restoring creates and changes live resources, and stays a command
a person runs with the snapshot in front of them. Capture and diff run
this binary as a separate process, so their progress output never reaches
stdout, which is the protocol. An agent's arguments cannot change what
runs: the command is the tool's, unknown keys are dropped, and each value
is one `--name=value` argument (a region of `us-east-2 --update` failed
as a host name in the real probe, as it should).

Verified against real systems through the protocol: `describe_type` for
`AWS::SQS::Queue` (FifoQueue and QueueName create-only, Arn and QueueUrl
read-only), `Microsoft.Compute/virtualMachines` (159 fields to depth 3,
`properties.osProfile.adminPassword` secret), IAM service accounts, and
GitHub environments; a capture of the StackDNA organisation (36 items,
honestly incomplete for want of `admin:org`), a diff of it (no
differences), its report, and an AWS capture. The first real describe
showed an environment's `name` as read-only; it names the item in the
PUT path, and is now shown as such.

Documentation links come from the schemas where they carry them (GitHub's
`externalDocs` per operation, a Discovery document's `documentationLink`)
and otherwise follow each platform's reference layout, checked to
resolve: AWS's CloudFormation template reference
(`aws-resource-sqs-queue.html`; only 19 of 1,498 schemas name a page
themselves) and Azure's template reference
(`/azure/templates/microsoft.compute/<version>/virtualmachines`).

**Companion servers.** StackDNA says what exists and what each field
means; each platform's own MCP server acts on it. As listed by the
providers on 2026-10-22:

- AWS: the remote AWS MCP Server (in preview), the AWS IaC MCP Server and
  the AWS Documentation MCP Server, in
  [awslabs/mcp](https://github.com/awslabs/mcp). The Cloud Control API MCP
  Server there is deprecated in favour of the IaC server.
- Azure: the Azure MCP Server, in [microsoft/mcp](https://github.com/microsoft/mcp).
- Google Cloud: Google-managed remote servers (Compute Engine, GKE, Cloud
  Run, Cloud Storage, Resource Manager) and the gcloud MCP server, listed
  in [google/mcp](https://github.com/google/mcp), whose README notes it is
  not an officially supported Google product.
- GitHub: [github/github-mcp-server](https://github.com/github/github-mcp-server),
  with a `--read-only` mode; remote at `https://api.githubcopilot.com/mcp/`.
- Cloudflare: the Cloudflare API MCP Server at `https://mcp.cloudflare.com/mcp`
  ([cloudflare/mcp-server-cloudflare](https://github.com/cloudflare/mcp-server-cloudflare)).

A client runs it like any stdio server:

```json
{"mcpServers": {"stackdna": {"command": "stackdna", "args": ["mcp"]}}}
```

## Roadmap

| Step | What |
|---|---|
| Next | Vault and file sources for secret values; PersistentVolume handling (claims are captured, but volume **data** is not, and the snapshot must say so) |
| AWS | The drill extended to IAM and Lambda (the sandbox user may now write roles named `stackdna-drill*`); a restore into a second account, and the onboarding role trusted from another account, once that account is activated; replay fixtures recorded from real responses; Secrets Manager values read live from a source account, as `--secrets-from-context` does for Kubernetes |
| Azure | Mapping principals across tenants; data-plane configuration (Key Vault secrets' metadata, storage CORS) where ARM exposes it |
| GCP | A real Compute drill (needs billing); project IDs in free text; `undelete` for soft-deleted resources (custom roles) |
| SaaS | GitHub, Cloudflare, Okta, Datadog and similar, through their REST APIs, each with an explicit schema of configured fields versus computed fields |
| Agents | Drift watching that opens PRs: CI regenerates snapshots deterministically, so a PR shows only real change. MCP resources for snapshots, so an agent can read one without a tool call |
| Proof | Scheduled restore drills per platform: restore into a sandbox and require an empty diff |

## Prior art to compare against

Not yet researched in depth. Before the first cloud adapter, compare what
Terraformer, Former2, aztfexport, Terracognita, `pulumi import`/`convert`,
`gcloud resource-config bulk-export`, Firefly and ControlMonkey each do, and
where they stop. The likely differences to test, rather than assume: one
snapshot format across cloud **and** SaaS; no state files; deterministic CI
updates; secrets kept out by construction; and restores proven by drill.
