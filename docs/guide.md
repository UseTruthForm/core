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

`stackdna permissions --platform <p>` writes the grant as a template for
the platform's own tool and prints every command to deploy, verify and
remove it, with your values filled in; it grants nothing itself.
`stackdna check` then says who StackDNA runs as, what that identity holds
beyond what it needs, and what it can read, type by type: a type refused
for want of permission shows as **denied**, never as empty. A type the
platform throttled until the retries ran out shows as **throttled**: that
is not a permission, and the same capture run later, or with a lower
`--parallel`, reads it. It exits 3 when anything is denied, throttled or
failed.

### Signing in to Cloudflare

No token to make: `stackdna login cloudflare` opens Cloudflare's sign-in
in a browser, you approve StackDNA, and the sign-in is kept in the OS
keychain (Secret Service, macOS Keychain, Windows Credential Manager) and
refreshed as it expires. It asks for zone read and DNS record read and
edit, nothing else. Capture, diff and restore then use it.

- `CLOUDFLARE_API_TOKEN`, when set, comes first, for CI and machines with
  no browser; a run says which one it used.
- Without a keychain (a bare server), login says so and stores nothing;
  set the token instead. No file is written in its place.
- `stackdna logout cloudflare` forgets the sign-in on this machine; revoke
  StackDNA in the Cloudflare dashboard to end the grant itself.
- A capture-only build signs in too: its read-only guard lets
  Cloudflare's token endpoint through and nothing else on that host.

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
- **secret values**: passwords, keys, a webhook's secret, and a webhook
  URL that is itself a credential (Slack, Discord, Teams, a `?token=` or
  `user:pass@` URL; such a hook is named by its host and a hash). They are
  named in the snapshot and given at restore with `--values`. A
  credential set as plain configuration in Kubernetes is withheld the
  same way: a value named like one (`*_PASSWORD`, `PGPASSWORD`,
  `*_TOKEN`, `*_SECRET`, `API_KEY`, `*_KEY`, `*_DSN`) in any `env` list
  (pod templates, Argo and Tekton steps, a HelmRelease's `values`) or as
  a ConfigMap key, and any such value that is a URL with a password in it.
  It is named in the snapshot and listed in REPORT.md as a finding: move it
  into a Secret. A restore reads it from the source with
  `--secrets-from-context`. Not caught: a credential passed as a command
  argument, inside a config file a ConfigMap holds, or in Helm values
  outside an `env` list. Because both sides are withheld, a diff does not
  show a rotated credential, and a snapshot taken before StackDNA withheld
  these values still holds them in its git history;
- **what the platform made itself**: default VPCs and their subnets,
  built-in roles, AWS-managed policies. Use `--baseline` with a capture of
  a fresh account to skip anything identical to it;
- **what is only taken to be AKS's**: on Kubernetes, a cluster-scoped object
  that Eno (the tool AKS manages some of its own objects with) applied or
  labelled, and that also has an `aks-managed-` name, a `kubernetes.azure.com`
  group or a `kubernetes.azure.com/*` key. A person's object could carry the
  same marks, so `REPORT.md` names each one under "Taken as the platform's", and
  `--capture-platform` keeps them;
- **a moment's state**: Cloudflare TXT records at `_acme-challenge.*`,
  which cert-manager and other ACME clients add to prove a domain and
  remove minutes later. Captured, a snapshot taken during a certificate
  renewal would differ from one taken after, and a restore would put back
  a stale challenge. A CNAME at `_acme-challenge` (a lasting delegation
  of the challenge to another zone) is captured.

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
  reported, with the fields that differ, and left alone. The exception is a
  child Azure made with a parent this run created, such as a storage account's
  `blobServices/default`: no one else's change can be in it, so it is set from
  the snapshot and reported as updated.
- **A resource that did not provision is not restored (Azure).** One Azure says
  has failed or is still in progress is reported, even if its configuration
  matches. `diff` lists one that failed, or a peering that is not connected, as
  `not working` and exits 2.
- **A lock is held back if anything else was not applied (Azure),** so it cannot
  block the re-run.
- **`--types` limits a restore (Azure),** so a run can be staged:
  `--types 'Microsoft.Network/*'`. A child goes with its parent's type, resource
  groups always come, and a pattern that matches nothing is refused. What a selected
  resource needs and was not selected must already be there. A child Azure already
  made in an earlier stage needs `--update`, as does one after a first run that
  failed part way. Check what a pattern covers before relying on it to hold back
  cost. A lock waits for a run that covers everything. Other platforms refuse
  `--types` on a restore.
- **Azure resource providers** are registered as a restore needs them, which takes
  `*/register/action` (Contributor and Owner have it). It can take minutes, and
  a resource that outlasts the wait reports the failure and is applied by a re-run.
- **`--update`** also brings differing resources in line with the
  snapshot. It never replaces a resource: a change the platform can only
  make by deleting and re-creating (an AWS create-only property) is
  refused and named.
- **References are remapped.** A subnet's VPC, a role's ARN, a principal
  ID: the snapshot holds references, not the source's IDs, and a restore
  resolves each to what the target created.
- **Into another subscription while the source exists (Azure):** many
  Azure names are unique across all of Azure (storage accounts, key
  vaults, container registries, SQL servers, Service Bus namespaces), so
  the restore would fail on them. `--rename names.yaml` gives them new
  names, one `Type/name: newname` per line
  (`Microsoft.Storage/storageAccounts/shopassets01: shopassets02`). A
  child follows its parent, or is renamed on its own by its full name
  (`Microsoft.Sql/servers/databases/srv/db: db2`); an entry applies in
  every resource group that has the resource. Every reference to a
  renamed resource follows: other resources' IDs, a role assignment or
  lock on it, a diagnostic setting that writes to it. Resource groups and
  extension resources cannot be renamed, and two resources given one name
  are refused. Text that only mentions the old
  name (a host name in an app setting) is not changed; each object holding
  some is listed so it can be checked. Write `--values` with the
  snapshot's names, and give `diff` the same file. Key vaults keep their name
  after deletion, and purge protection makes that last for the whole retention
  period and cannot be undone, so use a fresh name for each attempt.
- **Into another subscription in the source's tenant (Azure):** a role assignment's
  name is unique across a tenant, so pass `--new-role-assignment-ids` to `restore`
  and to `diff` of that target. A custom role is unique there too. A restore will
  not take over one that exists for other subscriptions: add the target to its
  `assignableScopes`, and run the restore again, which then takes the role as it is
  and will not change it, even with `--update`. A `diff` shows its wider scopes.
- **Workload identity (Azure):** a federated credential naming a cluster in the
  snapshot follows it, and trusts the restored cluster's issuer. One naming a
  cluster that is not in the snapshot keeps its issuer.
- **Into another region (AWS):** zones are paired by zone ID (printed);
  `--zone-map use2-az1=use1-az4` overrides a pair.
- **Several at once (AWS, Azure, GCP):** resources that do not depend on
  each other are created together (`--parallel`, 8 by default).
- **Secrets** come from a YAML file given with `--values`, keyed by
  resource. A restore says which secrets it was not given. The same file can
  set any other property; a list it sets is replaced whole. Give `diff` the
  same file (Azure), so what it set is compared as it was sent, not shown as
  drift. A key that matches nothing in the snapshot is refused by both.
- **Names held by deleted resources (Azure):** a deleted key vault, Cognitive
  Services account, SQL server, API Management service or App Configuration
  store keeps its name for a time, and Azure refuses a new one by that name. A
  restore and a diff say which of the snapshot's names are held, and how to
  free each (`names_held` in `--json`). A deleted SQL server cannot be purged,
  nor a key vault with purge protection before its date: rename it with
  `--rename`, or wait. Only the target subscription is checked: a key vault,
  API Management service, App Configuration store or Cognitive Services
  account deleted in another subscription holds its name too, and is not seen
  (`only_this_subscription`).
- **What no one changed (Azure):** a diff, and a restore checking what exists,
  do not count Azure's default for a property the snapshot does not set where
  unset behaves as that default (Key Vault's `enabledFor*`, Service Bus's
  `dnsNamePolicy`), a pool's node count its autoscaler sets, or an auditing
  setting's details when it is off on both sides. What a restore sends is
  unchanged. Other defaults Azure gives a restored copy (an AKS cluster's
  node OS upgrade channel, for one) are differences, and shown.
- **VM sizes (Azure):** a restore and a diff warn of a size the target
  subscription cannot have in that region or in the zones asked for, which
  Azure would refuse, and say what they could not check and how many they
  did (`vm_sizes` in `--json`). Give another size with `--values`: for a
  cluster, its whole `agentPoolProfiles`.
- **What Azure makes itself (Azure):** a registry's replication in its own
  region is not captured; a restore of an older snapshot says NOT SENT for it.
  A workspace's AzureDiagnostics table is captured with its retention, plan
  and custom (`_CF`) columns, and not sent until Azure has made it, when a
  diagnostic setting first sends data. The restore says NOT SENT. If a person
  set something on it, the restore is not complete (`pending` in `--json`,
  exit 3) and keeps it when run again with `--update`; a retention inherited
  from the workspace is left to the workspace. One with only the workspace's
  defaults does not hold the restore up.

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

A relative path in the file (`baseline`, a Kubernetes target's
`kubeconfig`) is relative to the file itself, so the command works from any
folder. One target that cannot be reached is recorded as failed without
stopping the others. Restore stays per target, on purpose. An AWS, Azure or Google
Cloud target the platform throttles can take `parallel: 4` (calls in
flight at once; 8 by default), as `--parallel` does for one target.

## Throttling

Every platform limits how fast it is read, and StackDNA waits as each one
asks. A read that stays throttled is reported as **throttled**, never as
empty or denied: capture again later.

- **Azure:** the SDK honours a `Retry-After` of up to 2 minutes, and a
  read still throttled after that is read again after at least 1 and then
  2 minutes, or the longer `Retry-After` Azure gave (up to 5). A lower
  `--parallel` (which `check` takes too) eases a throttled subscription.
- **Google Cloud:** a 429, and Compute's 403 `rateLimitExceeded`, are
  sent again after 1, 2, 4… seconds plus up to a second of jitter, at most
  64 seconds a wait and 8 tries in all, as Google asks. A 503 is sent
  again only for a read. A quota spent for the day is not retried: it is
  reported as a failure, since running again soon will not help.
- **GitHub and Cloudflare:** read one request at a time. A rate-limited
  read waits for `retry-after`, or for the reset the limit headers give,
  or at least a minute, and is sent again. Once a response says the
  budget is spent, nothing more is sent until it refills, so Cloudflare
  never locks the account out for its 5 minutes. A wait past 15 minutes
  (GitHub's hourly limit, shared with every other tool using the token)
  is not sat out: the read is reported as throttled, with when the limit
  resets.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success: the capture is complete, the restore fully applied, or no differences |
| 1 | Error: bad flags, cannot connect, cannot read a snapshot |
| 2 | Differences found (diff, compare) |
| 3 | Incomplete: the snapshot was written but some types could not be read, or a restore applied only some resources |

## Machine-readable output

Add `--json` to `capture`, `diff`, `restore` or `compare` (an environment
`--config` too). Stdout is then one JSON document, named by its `schema`
field (`stackdna.org/output/v1`), and everything meant for a person goes
to stderr. The exit code is the same as without it. A capture's document
says whether it is `complete` and lists its `gaps`, and under `throttled`
the gaps a later capture can close as it is; a diff's lists each
change with its `kind` (missing, extra, changed, not working) and `fields`; a
restore's lists each resource with `ok` and `detail`. A diff against one
target and a restore list under `left_out` the objects `--leave-out` held
back, so a clean diff says what it did not compare (`compare` has no
`--leave-out`, and its list is empty). On Azure, both also list under
`access_elsewhere` each action a restore needs outside its target, with the
resource it is needed on (an event hub rule's keys for a diagnostic setting
that sends there), as the report does.

```sh
stackdna diff --platform aws --region us-east-2 --from snap/aws --json | jq '.differences'
```

## As a graph (Azure)

`stackdna graph --from <snapshot>` writes an Azure snapshot as resources
and the relationships between them, as JSON, for a tool that maps an
estate (an asset inventory, a security graph) rather than recreating it.
It reads only the snapshot: no login, no request. Since the snapshot holds
no secret values, neither does its graph.

```sh
stackdna graph --from snap/azure --out graph.json
stackdna graph --from snap/azure --subscription <id> --tenant <id> --out graph.json
```

- **Nodes** are resources: `id` (the resource ID), `type`, `name`,
  `group`, `location`, `tags`, and the `properties` the projection
  chooses, keyed by their path (`properties.publicNetworkAccess`). A path
  through a list (`properties.securityRules[]`) gives a list, with a null
  for an element without the field, so two fields of one list line up. A
  reference token in a property is replaced by the value it stands for (a
  role assignment's `principalId` is the identity's GUID). A node that is
  `external` is something the snapshot refers to but doesn't hold, such as
  another subscription's network or a built-in role definition: only its
  ID, type and name are known. The captured subscription itself is a node
  (`Microsoft.Resources/subscriptions`, not external) when something is
  attached to it. A node with `managedBy` is something capture left out
  because that resource manages it, such as the load balancers and public
  IPs in an AKS cluster's node group: it exists, and only its ID, type and
  name are known. It was not read, so it says nothing about its address or
  rules, and a public IP there may only be the cluster's way out.
  `--capture-managed` reads them. In a snapshot from an earlier release, the
  manager is taken to be in the captured subscription.
- **Edges** run from the resource holding a relationship to the one it
  names. Each has a `kind`:
  - `references`: a field names it; `path` says which. IDs are found in
    any case, several joined in one string, inside a URL or template, as
    map keys (`identity.userAssignedIdentities{}`) and in tag keys, at
    tenant level too (a built-in role or policy definition). A reference
    to who created or changed something is not a relationship.
  - `child-of`: a child resource of its parent.
  - `extension-of`: a role assignment, lock, policy assignment or
    diagnostic setting on the resource, resource group or subscription it
    is attached to.
  - `depends-on`: a resource that cannot exist until another does, because
    it is in the group an AKS cluster creates.
  - `managed-by`: a resource capture left out, to the one that manages it
    (where the graph has that one: a type the projection leaves out has no
    node).

  A reference to a part that ARM keeps inside a resource (a subnet, a
  load balancer's backend pool, a security group's rule) goes to that
  resource, and `subresource` names the part (`subnets/app`).
- **The projection** (`--types`) chooses each type's properties. The
  built-in `security` projection covers network exposure, identity and
  access, encryption, public access, private endpoints and diagnostics,
  and leaves out types with no security signal, such as Log Analytics
  tables, Service Bus topics and scale-set instances. `none` gives every
  resource without properties. A file in the same format as the built-in
  one (`internal/azarm/graph_security.yaml`) gives your own.
- **IDs** keep the `{{stackdna|subscription}}` placeholder unless
  `--subscription` gives the real one, and `--tenant` does the same for the
  tenant. Another subscription that a resource refers to (a peered network)
  keeps its real ID either way, since the snapshot holds it as it is.

The output is deterministic: the same snapshot gives the same graph from
any binary of one release, whichever its edition or OS. `generator` names
the version and commit that wrote it, so another build (a new release, a
local `go build`, a tree with uncommitted changes) can change the file even
where the nodes and edges have not changed. To compare graphs across builds,
compare `nodes` and `edges`.

## For AI agents (MCP)

`stackdna mcp` serves StackDNA's knowledge over the Model Context
Protocol. For every field of a resource type it says whether the field is
required, set by the platform, write-only, secret or fixed at creation,
with the platform's documentation link. It can also capture, diff and
read reports, say what access to grant (`permissions`) and check what a
grant can read (`check_access`). No tool can restore and none grants
anything. An agent setting up someone's access should follow
[agents.md](agents.md). Add it to a client as:

```json
{"mcpServers": {"stackdna": {"command": "stackdna", "args": ["mcp"]}}}
```

## Known limits

- A Log Analytics workspace's data sources can only be listed one kind at
  a time. StackDNA lists every kind Azure's definition names; a data
  source of a kind it does not name is not found. The change-tracking
  default registry keys Azure makes up on every read are counted in
  coverage, not captured.
- A VNet peering to a network in another subscription keeps that network's ID,
  so a restore connects the target to it if the identity may. Check any before
  restoring. Private endpoint connections come with their endpoints, and a target
  in another tenant may need them approved.
- An attached data disk is skipped with its VM and does not come back. `REPORT.md`
  lists each under "Check before relying on a restore".
- A snapshot's IDs and display names do not name the Azure subscription or tenant,
  but the title of its `REPORT.md` does, to say whose report it is. So does a
  resource's own name if it holds one, such as `DefaultWorkspace-<id>-EUS`, and a
  restore creates it under that name. Another subscription a resource refers to
  keeps its real ID.
- S3 bucket names are global: a bucket cannot be restored under the same
  name while the original exists, or in another region shortly after it
  was deleted.
- Data is never captured (see above).
- GitHub's environment wait timer and a few similar fields are accepted on
  write but never read back; a snapshot names them (`stackdna.org/unreadable`)
  and a restore says it could not carry them.
- Proven against real systems so far: AWS (21 resources across 17 types,
  IAM and Lambda included; restore, update, another region), Azure, Google Cloud, Kubernetes and
  GitHub capture. Cloudflare and Google Compute are proven against
  simulated APIs only.
