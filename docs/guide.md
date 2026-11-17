# TruthForm user guide

TruthForm reads the live configuration of a cloud account, a Kubernetes
cluster or a SaaS organisation into a **snapshot**: plain YAML files you
can review, commit and diff. From a snapshot it can **diff** what is
running against what was captured, and **restore** what is missing, into
the same place or another account, subscription, project or region.

It is one binary with nothing to install, and it keeps no state: the
platform itself is the source of truth.

## Install

Download the archive for your platform from the release, check it against
`SHA256SUMS`, and put `truthform` (or `truthform.exe`) on your `PATH`:

```sh
sha256sum -c SHA256SUMS --ignore-missing
tar -xzf truthform_0.1.0_linux_amd64.tar.gz
./truthform_0.1.0_linux_amd64/truthform version
```

There are two editions for every platform:

| Edition | Can | Use it for |
|---|---|---|
| full | capture, diff, restore | your own environments |
| capture-only | capture, diff | handing to a client for an assessment: it has no restore, and every request it makes goes through the read-only guard, so it cannot change anything it reaches |

`truthform version` says which edition and build you have.

## Permissions

Give a capture a read-only role, and a restore a write role, separately.
[permissions.md](permissions.md) lists the exact roles per platform, and
which have been verified.

`truthform permissions --platform <p>` writes the grant as a template for
the platform's own tool and prints every command to deploy, verify and
remove it, with your values filled in; it grants nothing itself.
`truthform check` then says who TruthForm runs as, what that identity holds
beyond what it needs, and what it can read, type by type: a type refused
for want of permission shows as **denied**, never as empty. A type the
platform throttled until the retries ran out shows as **throttled**: that
is not a permission, and the same capture run later, or with a lower
`--parallel`, reads it. It exits 3 when anything is denied, throttled or
failed.

### Signing in to Cloudflare

No token to make: `truthform login cloudflare` opens Cloudflare's sign-in
in a browser, you approve TruthForm, and the sign-in is kept in the OS
keychain (Secret Service, macOS Keychain, Windows Credential Manager) and
refreshed as it expires. It asks for zone read and DNS read, plus DNS
write in the full edition only: the capture-only edition's sign-in grants
no write at all. Capture, diff and restore then use it; a restore needs a
sign-in made with the full edition.

- `CLOUDFLARE_API_TOKEN`, when set, comes first, for CI and machines with
  no browser; a run says which one it used.
- Without a keychain (a bare server), login says so and stores nothing;
  set the token instead. No file is written in its place.
- `truthform logout cloudflare` forgets the sign-in on this machine; revoke
  TruthForm in the Cloudflare dashboard to end the grant itself.
- A capture-only build signs in too: its read-only guard lets
  Cloudflare's token endpoint through and nothing else on that host.
- `TRUTHFORM_CLOUDFLARE_CLIENT_ID` signs in as another registered OAuth
  client, such as your organisation's own, in place of TruthForm's.

## Capture

```sh
truthform capture --platform aws   --region us-east-2 --profile prod --out snap/aws
truthform capture --platform azure --subscription <id>              --out snap/azure
truthform capture --platform gcp   --project my-project             --out snap/gcp
truthform capture --context prod-cluster                            --out snap/k8s
GITHUB_TOKEN=... truthform capture --platform github --account my-org --out snap/github
```

A snapshot directory holds `objects/` (one YAML file per resource),
`schemas/` (the field list of every type, so schema changes show up),
`coverage.yaml` (what was read, what was skipped and why) and
`snapshot.yaml` (with a digest: two captures of an unchanged system have
the same one, unless Azure returned a name in another case; see
[Names in another case](#names-in-another-case-azure)). **REPORT.md** beside it says, in plain words, what was
captured, what was not and why, and what a restore will need.

What a GitOps source renders (a Flux HelmRelease or Kustomization, an Argo
CD application, a Crossplane composite) is left to its source: restoring
the source recreates it, and `--capture-rendered` keeps it anyway. Where
GitOps starts is captured, since nothing else recreates it: the Flux
Kustomization that applies itself (the one `flux bootstrap` makes) with
the repository object it reads from, and an Argo CD application that
manages itself. That is the repository, branch and path the cluster was
built from. The credential to read it is a Secret, named and never held.
A credential written into one (a token in the repository's URL, a
password in an Argo CD application's Helm values) is withheld like any
other, and supplied at a restore from the secret sources file. One of these
in a system namespace is left out with the namespace, unless
`--include-system` is given.

What a snapshot does not hold, by design:

- **data**: S3 objects, blobs, database rows, queue messages, volume
  contents;
- **secret values**: passwords, keys, a webhook's secret, and a webhook
  URL that is itself a credential (Slack, Discord, Teams, a `?token=` or
  `user:pass@` URL; such a hook is named by its host and a hash). They are
  named in the snapshot and given at restore with `--values`. A
  credential set as plain configuration in Kubernetes is withheld the
  same way, by its name or by its shape.

  By its name, one rule everywhere: in any `env` list (pod templates,
  Argo and Tekton steps, a chart's values), as a ConfigMap's key (`data`
  and `binaryData`), and in what a GitOps source installs with. That is
  a Flux HelmRelease's `values` and a Kustomization's
  `postBuild.substitute`; an Argo CD application's or application set's
  `valuesObject`, parameters, generator elements and inputs; an Argo
  workflow's parameters. A name says a credential when one of its words
  is `pass`, `pwd`, `pw`, `key`, `cred`, `auth`, `dsn`, `sas`, `jwt`,
  `salt`, `signature` or `license`, or when `password`, `passcode`,
  `token`, `secret` or `credential` is anywhere in it: `DB_PASSWORD`,
  `apiToken`, `client-secret`, `jwtKey`. In a chart's values, so does
  everything under `password:`, `tokens:`, `apiKey:` and their like,
  however deep.

  Kept, under any such name:

  - what names a thing: `secretName`, `existingSecret` and
    `apiKeyExistingSecret`, `envFromSecret`, `pullSecret`, the `name` and
    `key` of a reference, a `key` beside a `name` or a `path`, a list of
    Secrets' names under `secrets:`, a public key;
  - a setting about a credential, by how the name ends:
    `PASSWORD_MIN_LENGTH`, `TOKEN_TTL`, `tokenExpiration`, `tokenUrl`,
    `KEY_PREFIX`, `passwordPolicy`, and a value that is a file's path
    (`/var/run/secrets/key.json`);
  - a chart or a component whose name says a credential
    (`sealed-secrets`, `external-secrets`): a map with an `image`, a
    `tag`, a `fullnameOverride`, `replicas`, `resources` or the like in
    it is settings, and each is read by its own name;
  - what says where a pod runs and how it is labelled (`tolerations`,
    `affinity`, `nodeSelector`, labels and annotations);
  - a boolean, a number of six digits or fewer where it is written as a
    number, and a value that only points at another (`${VAR}`,
    `{{ .Values.x }}`).

  By its shape, whatever it is called: a private key, a URL that signs in
  (with a password, with a token as its name, or with one asked as
  `?token=`, `?api_key=`, `?sig=` and their like; a chat webhook's
  address is one too), an `Authorization` header or its value, a
  connection string with `Password=` or `password=` in it, a token that
  says what it is (GitHub's, GitLab's, Slack's, an AWS key ID, a JWT),
  and a long run of mixed letters and digits with nothing to read in it.
  A short name with no password in a URL is an account (`ssh://git@host`)
  and is kept; where an address is all a field holds (`url`, `repoURL`,
  `endpoint`, `repo`, `address`, `uri`, `dsn`), any name in it is
  withheld unless it is over SSH.

  Text is withheld whole when a credential is in it: an application's
  `values`, `templatePatch` and `elementsYaml`, a `patch`, and any value
  of several lines in a chart's values. It is read as the YAML or JSON
  it is. Text that is no document (a script, a properties or env file)
  is read line by line, for `NAME=value` and `name: value`. Text that
  should be a document and cannot be read as one, a template with
  `{{ if }}` in it most often, or that sets a key twice, is withheld
  whole whatever is in it: where a value is in it cannot be told.

  This withholds more than credentials, on purpose: what is withheld
  costs a line in the secret sources file, and a credential kept is one
  in a snapshot. Each is named in the snapshot and listed in REPORT.md as
  a finding: move it into a Secret. A restore reads it from the source
  with `--secrets-from-context`, or from the secret sources file's
  `settings` with `--secrets-from`.

  **Not caught.** No rule reads every credential under every name. These
  stay in a snapshot, and a planted set of them is counted by a test so
  that the list can only get shorter:

  - a name that does not say it is one, with a value of no shape:
    `foo: hunter2`, and names such as `pin`, `seed`, `cookie`, `session`,
    `login`, `webhook`;
  - a key of lower-case letters and digits only (a hex key, a UUID), or
    shorter than 32 characters, under such a name;
  - a number of six digits or fewer, and `true` or `false`, under any
    name;
  - `credentials: {name: admin, key: ...}`: a `key` beside a `name` is
    read as the name of a key;
  - a config file a ConfigMap holds (`application.properties`,
    `redis.conf`): a ConfigMap's value is read for its shape, not as a
    file. In a chart's values, a file with no `name=value` or
    `name: value` in it (`requirepass ...`);
  - a command's argument (`--password=...`), and an annotation;
  - a field of a custom resource that is none of the above
    (`spec.adminPassword` of a database operator's object), unless its
    shape says so and it is called `url`, `address`, `uri`, `dsn` or the
    like;
  - in a URL: a password with a space in it, one with a slash in it
    before a host with no dot and no port, and `?key=` or `?code=`;
  - text on one line: a value such as `extra: "DB_PASSWORD=hunter2"` or
    `javaOpts: "-Ddb.password=hunter2"` under a name that says nothing
    (only a value of several lines is read line by line);
  - in a document as text, a credential in a comment
    (`# password: hunter2`), and a template with a default written into
    it where the document still reads as YAML
    (`password: {{ .Values.pw | default "hunter2" }}`, unquoted: YAML
    reads the braces as a map and sees no value).

  Because both sides are withheld, a diff does not show a rotated
  credential, and a snapshot taken before TruthForm withheld these values
  still holds them in its git history. A snapshot taken by an earlier
  version restores as it did: the places it names are found by the names
  it gave them;
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
truthform diff --platform aws --region us-east-2 --from snap/aws
```

It lists what was added, removed or changed, field by field, and exits 2
when there are differences, so it can gate a pipeline or raise an alert.

### Names in another case (Azure)

Azure's resource types, resource groups and names ignore case, and Azure
does not always return one in the same case: a Log Analytics table has come
back as `ACSCallAutomationStreamingUsage` on one day and
`AcsCallAutomationStreamingUsage` on the next. For Azure, TruthForm takes
them as one object:

- **A snapshot** stores the object in the same file whatever the case (its
  path is in lower case), and the file keeps the case Azure returned. Two
  spellings of one object in a capture are an error.
- **`diff`, `compare` and an environment's diff** match it in any case, and
  a type, group, name or ID that differs only in case is not a difference.
- **`restore`** finds it in the target in any case (Azure's own reads ignore
  case), and does not create it beside the one there.
- **`--values`** keys match it in any case. Two keys for one object are
  refused.

The digest is of the files as written, so on a day Azure returns a name in
another case it differs although `compare` finds nothing: compare by
content, not by digest. Kubernetes and Google Cloud names are case-sensitive
and are matched as they are; so are AWS's, where some services ignore case
and others do not.

## Restore

```sh
truthform restore --platform aws --region us-east-2 --from snap/aws --values secrets.yaml
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
- **A DNS record whose content changed (Cloudflare):** a record is named by
  its type, name and content, so `www` pointing at a new address is, by
  name, a different record. For an A, AAAA or CNAME record a restore takes
  it for the same record changed when the target holds exactly one record
  of that type at that name which the snapshot does not have, and exactly
  one of the snapshot's is missing there. It is reported with the content
  the target holds and left alone; `--update` changes it where it is. It is
  not created beside the old one, which would make DNS answer with both.
  With any other count (two the snapshot does not have, say) which replaces
  which is not known: nothing of that type is written at that name, and
  the restore says to delete what should go. Either way the restore is
  then incomplete (exit 3). Content that differs only by case (a CNAME's
  host, an IPv6 address) is the same record. A TXT, MX or other record is created
  beside whatever is there, since such a name holds unrelated values, and
  the restore names what it is beside. A CNAME beside a record of another
  type is left to Cloudflare, which refuses it.
- **`--dry-run` (GitHub, Cloudflare)** reads the target and prints each
  write the restore would make (`would create`, `would update`), and makes
  none: its client refuses every write.

### A second environment's DNS in the same zone (Cloudflare)

```sh
truthform restore --platform cloudflare --account <id> --from snap/cloudflare \
  --subdomain test.example.com --address 192.0.2.1=198.51.100.7 \
  --target app.example.net=app-test.example.net --dry-run
```

`--subdomain` restores one zone's records a level down, beside the
originals: `example.com` becomes `test.example.com`, `www.example.com`
becomes `www.test.example.com`, and a CNAME to a name in the zone follows.

- **Only names under the subdomain are written.** The zone is used as it is
  and never created or changed; other zones in the snapshot are left out.
- **Each record it writes carries the comment `truthform: test.example.com`.**
  Only a record with that comment is TruthForm's to change, with `--update`.
- **It reads the zone first and stops before writing anything** when:
  - a record it did not make is at a name it would write;
  - a record an earlier run made is at a name it would write, with other
    content (a wrong `--address` the first time), so DNS would answer
    with both: delete it first;
  - the subdomain is delegated or a zone of its own;
  - a record would still point at the source. Name each target with
    `--address <source-ip>=<target-ip>` for an A or AAAA record and
    `--target <source-host>=<target-host>` for a CNAME to a host outside
    the zone (an app service, a load balancer). The same host twice keeps
    it.
- The record comment it adds has to fit in the 100 characters Cloudflare's
  free plan takes, so a subdomain name longer than 89 characters is refused.
- **Mail, delegations and ACME records stay out:** MX, SPF, DKIM, DMARC,
  MTA-STS and autodiscovery records, NS records, `_acme-challenge`.
- **It warns of a wildcard above the subdomain** (`*.example.com`). Today it
  answers for `test.example.com` and every name below it. Once any of those
  names exists, it no longer does, and a name there the restore does not
  create stops resolving.
- **It also warns of** a CNAME moved onto a name it leaves out (it would
  answer with nothing), and an SRV, HTTPS or SVCB record, whose target is
  copied as it is.
- **A record made by an earlier run that the snapshot no longer has** is
  reported and left in place; nothing is deleted.
- `diff --subdomain test.example.com` (with the same `--address` and `--target`) compares
  the records under the subdomain with the snapshot as the restore put it.

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
truthform capture --config prod.yaml --out snap/
truthform diff    --config prod.yaml --from snap/
```

A relative path in the file (`baseline`, a Kubernetes target's
`kubeconfig`) is relative to the file itself, so the command works from any
folder. One target that cannot be reached is recorded as failed without
stopping the others. Restore stays per target, on purpose. An AWS, Azure or Google
Cloud target the platform throttles can take `parallel: 4` (calls in
flight at once; 8 by default), as `--parallel` does for one target.

## Throttling

Every platform limits how fast it is read, and TruthForm waits as each one
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
| 2 | Differences found (diff, compare), a secret sources file that does not cover its snapshot (plan secrets --check), or a scope whose hold would bring objects it does not know how to hold, or that brings an admission webhook failing closed whose Service will not answer, or that holds something and brings, not held, a GitOps source that applies into a namespace it narrows or a Flux object that acts outside the cluster (plan scope --check) |
| 3 | Incomplete: the snapshot was written but some types could not be read, a restore applied only some resources, or a restore under a hold brought objects not held |

## Machine-readable output

Add `--json` to `capture`, `diff`, `restore`, `compare` or `plan` (an
environment `--config` too). Stdout is then one JSON document, named by its `schema`
field (`truthform.org/output/v1`), and everything meant for a person goes
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
truthform diff --platform aws --region us-east-2 --from snap/aws --json | jq '.differences'
```

## Before a rebuild (Kubernetes)

A snapshot recreates what it holds. A cluster rebuilt from one also needs
what the snapshot does not hold, and `truthform plan rebuild` lists that,
in the order to act on it:

```sh
truthform plan rebuild --from snap/cluster                 # Markdown, to stdout
truthform plan rebuild --from snap/cluster --out PLAN.md
truthform plan rebuild --from snap/cluster --json | jq '.plan.secretsByHand[].name'
```

A snapshot whose capture could not read everything gives a plan that
says so first and lists what was not read (`.gaps` with `--json`): a step
that lists nothing is then no proof there is nothing.

It reads the snapshot and nothing else: no login, no request, and it runs
in the capture-only build. The same snapshot gives the same plan, so it
can be kept beside the snapshot and compared like one. With `--json` the
document goes to stdout; `--out` is for the Markdown.

1. **Install first.** What the capture left to a GitOps source (a Flux
   HelmRelease or Kustomization, an Argo CD application, a Crossplane
   composite), with how many objects each makes. Sources the snapshot
   holds, and those they apply, are named apart: they are applied again
   once the GitOps tool's own controllers are installed and the snapshot
   is restored. The rest are to install by hand; one that makes objects
   only in system namespaces is marked, as the cluster's platform may
   install it itself. The plan names the Flux repository objects the
   snapshot holds, or says that where the sources are read from is not in
   it.
2. **APIs to have served.** Types the snapshot has objects of and no
   CustomResourceDefinition for, by API group. The restore refuses those
   objects until something serves the type, usually an operator that
   step 1 installs.
3. **Secrets to supply by hand.** A snapshot never holds a secret's value.
   These are the Secrets no store in the snapshot supplies: each one's
   keys, what in the snapshot names it, and what the Secret says of
   itself (a registry login, a Helm release's, the key a Flux
   Kustomization decrypts with). Named apart, and not for a person to
   supply: what something in the cluster makes again by itself
   (cert-manager's certificates and ACME accounts, the Azure Files
   driver's copy of a storage key, KEDA's own certificates); a service
   account's token is left out. Secrets kept encrypted are named with the
   key that opens them (Sealed Secrets, SOPS read by a Flux
   Kustomization): that key is the one thing only a copy kept outside the
   cluster brings back. A tool the plan does not know is listed here, by
   hand, never as something that looks after itself.
4. **Secrets a store supplies.** The store items read by the 1Password
   operator, External Secrets, the Vault Secrets Operator, the Secrets
   Store CSI driver and akv2k8s, most-used first. A Secret the 1Password
   operator marked as its own counts too when the object that asked for
   it is a GitOps source's and not in the snapshot. The restore recreates those objects and the operator makes the
   Secrets, once the store is reachable from the rebuilt cluster. An item
   holds the settings of the cluster it was written for: one that feeds
   many Secrets is where to look for the addresses and keys that must
   differ in a rebuild.
5. **Restore.**
6. **Names to point at the rebuilt cluster.** The hosts the snapshot's
   routes answer to: Ingress rules, Gateway listeners and routes, Traefik
   `Host()` matches.

What it cannot see:

- **Who uses a Secret**, when the user is something step 1 installs (an
  operator's own credential usually is), or an object with no namespace
  that names the Secret without one (a `ClusterIssuer`).
- **Which namespaces a `ClusterExternalSecret` reaches.** Its Secrets are
  listed as `*/name`, and a Secret of that name in any namespace is taken
  as supplied.
- **A secret store of another kind.** Its Secrets are listed under step 3.
- **Hosts matched by pattern** (`HostRegexp`).
- **Data**: databases, volumes and queues are outside a snapshot.

### Where the secrets are read from

Step 3's Secrets are the ones a person has to keep a copy of. A secret
sources file says where each copy is, so that a rebuild reads the values
itself. It holds references and never a value, and can be kept in a
repository beside the pipeline that uses it.

```sh
truthform plan secrets --from snap/cluster --out secrets.yaml      # a file to fill in; never written over one
truthform plan secrets --from snap/cluster --check secrets.yaml    # does every Secret to supply have a source?
truthform plan secrets --from snap/cluster --check secrets.yaml --resolve   # and does each source answer?
truthform restore --context new --from snap/cluster --secrets-from secrets.yaml
```

```yaml
secrets:
  - secret: flux-system/flux-system
    from:
      username: env:GIT_USER
      password: op://Break Glass/flux git/password
  - secret: keda/bus
    from:
      connection: "exec:az servicebus namespace authorization-rule keys list -g rg --namespace-name bus -n send --query primaryConnectionString -o tsv"
  - secret: tools/licence
    leave: the vendor's operator makes it when it starts
```

| Reference | Read from |
|---|---|
| `op://<vault>/<item>/[<section>/]<field>` | 1Password, with the `op` CLI; each part is letters, digits, spaces, dots, dashes and underscores (give anything else by its ID) |
| `azurekv://<vault>/<secret>[/<version>]` | Azure Key Vault, with the `az` CLI; each part is letters, digits and dashes |
| `env:<NAME>` | an environment variable |
| `file:<path>` | a file's whole content, byte for byte; a relative path is from where the command runs. On Windows write the path with forward slashes or in single quotes (`'file:C:\keys\db.txt'`): in double quotes YAML reads a backslash as an escape, so the file is refused as not YAML, or (`"file:C:\tmp\new.txt"`, where `\t` and `\n` are a tab and a newline) is read without complaint as another path, which fails only when the value is read |
| `exec:<command>` | what a command prints, less its last line end; only with `--allow-exec` |
| `empty:` | the empty value, for a key that holds nothing |

A read that gives nothing is refused, so that a sign-in that lapsed does
not restore an empty password: a key that is meant to be empty says so
with `empty:`. A read is given two minutes, and what it started is ended
with it.

`exec:` is for whatever has no reference of its own: another vault's CLI,
or a value read from the cloud the cluster is rebuilt in (a storage key, a
connection string), which is then the new resource's and not a copy of
the old one's. It runs a command from the file with the access of whoever
runs the restore, so it is refused without `--allow-exec`: give that flag
only for a file you would run as a script.

`leave:` is for a Secret the plan lists by hand that something does make:
the restore does not write it, and the check does not ask for a source.

An entry may also give values to a Secret the plan does not ask for (to
bring a certificate with you, where cert-manager would issue a new one).
Any entry with `from:` gives every key the Secret has and no other: a
restore takes one Secret's values from one place.

`--check` exits 2 when a rebuild would lack something: a Secret to supply
with no entry, a key with no reference, a key the Secret does not have.
Run after each capture, it says so the day someone adds a Secret by hand.
It also exits 2 for a snapshot whose capture did not read Secrets (a
Secret to supply may be among them), and notes any other type it could
not read; with `--json`, `.gaps` lists what the capture failed to read
and `.secrets.problems` says which of it bears on Secrets.
It reads only the snapshot and the file. `--resolve` also reads every
value from its source and prints none of them: it proves the sign-ins and
the items are there before the day they are needed.

A restore with `--secrets-from` checks the file the same way and reads
every value **before it writes anything** to the cluster; a source that
does not answer stops it there. It then leaves out the Secrets that are
not a restore's to write (those a store, a controller or a SealedSecret
makes, by the plan, and the file's `leave:` entries) and says which. A
value is read, sent to the cluster, and written nowhere else. No message
repeats one, nor an `exec:` command, nor text in the file that is not
what a sources file holds. With `--secrets-from-context` as well, a
Secret the file does not name is read from that cluster.

A credential that was set as plain configuration (a variable in a
workload, a URL that signs in) is withheld from the snapshot like a
Secret's value, and a restore refuses the object until it is supplied.
The file supplies those too, under `settings`: the object, and a
reference for each place a value was withheld at.

```yaml
settings:
  - object: "apps/v1|Deployment|shop|api"
    from:
      "spec.template.spec.containers[api].env[DB_PASSWORD]": "op://Break Glass/shop db/password"
```

A place that held a number has `#number` at its end, and what is
supplied for it has to be one. A place with `=` before it is written so
where a key with a dot in it sits beside the same keys nested: copy it
as `plan secrets --out` wrote it. The mark is followed only where a
capture writes it; added by hand anywhere else, the restore refuses it.
For such an object two things change with this version, both refused
aloud and never filled wrongly: a snapshot of it taken now is not
restored by an earlier version, and a sources file written against an
earlier snapshot of it no longer fits one taken now (write its key again
from `plan secrets --out`). A ConfigMap's `binaryData` key is
supplied as it is stored, in base64. A document withheld whole (see what
is withheld, above) is one place, and the reference gives all of it: a
`file:` reference suits it.

`plan secrets --out` writes an entry for every such object, and
`--check` wants a reference for each place, as it does for a Secret's
keys (`.secrets.settings` counts the objects with `--json`). So what was
withheld does not need the cluster it came from to be restored. A
setting is text: a reference that reads something else is refused, and
so is `empty:`, since nothing empty is ever withheld. With
`--secrets-from-context` as well, an object the file does not name is
read from that cluster; one it names is filled from the file alone, and
has to have a reference for every place.
The better fix stays the one the capture's report gives: move each into
a Secret. An object a GitOps source applies is not in the snapshot, and
needs nothing here: the source holds its values.

The file to fill in is written from what the cluster's objects say, and
only as comments and names: read it before you fill it in, as you would
any file a tool wrote for you to run.

### The secrets a secret store starts from

A cluster that reads its Secrets from a store still starts from a
credential for that store, and the plan lists it by hand. How much work
that is depends on the store:

- **A cloud vault read with the cluster's own identity** (workload
  identity): there is no such Secret. Restoring the cloud snapshot brings
  the identity and its grants back; what ties the identity to the cluster
  (a federated credential) names the cluster's issuer, which a new
  cluster changes, and the Azure restore points it at the new one.
- **Sealed Secrets, SOPS**: the key is the Secret, and a copy of it is the
  entry in the sources file. SOPS with a key held by a cloud key service
  has no such Secret: the cluster's identity needs that key's use.
- **1Password Connect**: the credentials file and the access token are
  issued by 1Password and not by the cluster, so the ones an environment
  was given still work after it is rebuilt, unless the token was made to
  expire: keep them, and name them in the sources file. A new environment needs its own, made by a person
  signed in. `examples/bootstrap/1password-connect.sh` does that in one
  command: it makes the server and a read-only token for the vaults you
  name, keeps both as one item in another vault, reads them back, and
  prints their references (and, given the Secrets' names, the
  sources-file entries). It prints neither value, and `--dry-run` makes
  nothing. It removes only a server 1Password said this run made, and
  says what it made and left if it is stopped; killed outright
  (`kill -9`, or the machine losing power) it cannot, and its temporary
  directory (under `$TMPDIR`, or `/tmp`) then still holds the
  credentials file and the token. It knows its own server by the id
  1Password prints when it makes one; the first real run is what shows
  that it does, and if it does not the script stops with the server made
  and says so. **It has been run with `--dry-run`
  against a real account and has not yet made a server on one**: run it
  with `--dry-run` first, and read what it says it made.

### A part of the snapshot

A restore need not bring everything. A drill wants the platform, the core
of an application and a few of its many workloads, and a scope file says
which, in terms the cluster already has:

```sh
truthform plan scope --from snap/cluster --out scope.yaml     # brings everything; never written over one
truthform plan scope --from snap/cluster --check scope.yaml   # what it brings, and what it leaves out
truthform restore --context test --from snap/cluster --scope scope.yaml
truthform diff    --context test --from snap/cluster --scope scope.yaml
truthform plan rebuild --from snap/cluster --scope scope.yaml # the plan of the part
truthform plan secrets --from snap/cluster --scope scope.yaml --out secrets.yaml
```

```yaml
narrow:
  - namespaces: ["team-*"]          # names, or patterns as a shell has them
    releases: [a-search, b-search]  # Helm releases, in any of those namespaces
    objects: [ConfigMap/shared]     # what no release made, as Kind/name
  - namespaces: [batch]
    labels: {tier: drill}
```

A scope **narrows the namespaces it names, and leaves the rest of the
snapshot as it is**. So a file written for a drill does not have to know
the whole cluster, and a namespace added later that a pattern fits is
left out until someone chooses from it. A pattern has `*` for any run of
characters, `?` for one, `[a-c]` for one of a set, and a backslash before
one of those to mean the character itself.

A release belongs to the namespace Helm installed it in. In a narrowed
namespace:

- a **release** chosen comes whole, wherever what it made is (a
  ClusterRole, an object in another namespace): it is known by what Helm
  writes on what it makes. An object chosen by a **label** brings the
  rest of its release. Its namespace comes with it. An object with no
  namespace that names its release by label alone does not say which
  namespace the release is in: it goes with the releases of that name,
  and is left out only when all of them are (one brought while another
  release of the name is left out is named in the run);
- a **Secret** an object of the snapshot makes (from a store, from an
  ExternalSecret or a SealedSecret, a certificate's) goes where that
  object goes;
- **what no release of a narrowed namespace made** (shared
  configuration, a Secret made by hand, a workload applied by hand, a
  GitOps source's own object) is **left out unless an entry names it**
  under `objects`, as `Kind/name`, or it carries an entry's labels.
  Either part may be a pattern (`ConfigMap/*`, `"*/*"` for all of them),
  and `Kind.group` tells two APIs' kinds of one name apart. Restore and
  diff list those brought and those left out. A Secret an object makes
  is not named here: it goes with its maker;
- the Namespace itself comes when anything of it is brought. A namespace
  from which nothing is chosen is left out whole, with what the capture
  left there to a GitOps source, which the plan then does not ask for;
- **a scope cannot stop a GitOps source that is brought** from making
  what it makes: if the snapshot's root Kustomization applies a
  HelmRelease in a namespace the scope narrows, left out whole or not,
  the release is installed once the source runs. The run says so by name
  (`scope.stillMade` with `--json`), and the plan goes on listing it:
  leave the source out with `--leave-out`, or have it apply less. Where
  the scope holds anything, such a source refuses the restore unless it
  is held or accepted (see the hold, below);
- **a webhook that is brought and calls a Service that will not answer**
  is named (`scope.webhooksWithoutService` with `--json`): an admission
  webhook with no namespace of its own is brought with everything else,
  and while nothing answers at its Service the API server refuses every
  write it is asked about (unless its `failurePolicy` is `Ignore`). The same is
  said of a CustomResourceDefinition whose conversion webhook calls such
  a Service (a `v1` definition; the long-removed `v1beta1` form is not
  read), and of an APIService served by one: its API is then not there,
  and what lists every API, a namespace's deletion for one, waits on
  it. A Service the capture left to a GitOps source counts as there
  only when that source is brought. What a webhook matches is not read,
  so one that matches nothing is named too. Bring what makes the Service, or leave the webhook out with
  `--leave-out`.

Both notes are in the rebuild plan as well, under "A part only", so that
whoever reads the plan sees them without the command's output.

**A restore is refused, with nothing written, for an admission webhook
that fails closed and whose Service will not answer** (a
`ValidatingWebhookConfiguration` or `MutatingWebhookConfiguration` hook
whose `failurePolicy` is `Fail`, the default in `v1`). Webhooks are
applied last, so the first restore would go through; from then on the
API server refuses every write such a webhook is asked about: a second
run, a resume after a failure, an update, and whatever is done in that
cluster next.

This is asked of every Kubernetes restore, with a scope or with none,
and of any Service, wherever it is. It is one question, "is it there
once the restore has run?", asked of the Service and then of whatever
is said to make it, as far up as that goes:

- an object the restore brings is there. A Service that is brought
  answers unless every workload of the snapshot that its selector picks
  is held by the scope (`hold: true`), left out of it, or taken out with
  `--leave-out`; a Job is not counted, and where the snapshot has no
  such workload (an operator makes the pods) the Service is taken to
  answer;
- an object of the snapshot that this restore takes out (the scope,
  `--leave-out`) is not there;
- what the capture left to something else is there if that is: the
  object that owns it, the Flux HelmRelease or Kustomization or Argo CD
  application that makes it, the Crossplane composite that composes it,
  each asked the same question in turn (an owner a HelmRelease renders,
  which a Kustomization applies, is there if the Kustomization is). One
  of these that is brought and held makes nothing, and what it would
  have made is not there;
- what the capture left as the platform's or the cluster's own (a
  system namespace, the cloud's objects) is there;
- what is in no snapshot and left to nothing is not there.

A source is asked like any other object: an Argo CD Application that an
ApplicationSet generates is there if the ApplicationSet is. **Where the
source is in another cluster** (a hub that runs Argo CD for its spokes),
the spoke's snapshot has what the source labelled and not the source:
nothing in it makes those Services, and a spoke's webhooks that fail
closed are refused until their configurations are accepted under
`withoutService`. That is every spoke of such a fleet: accept them
once, in the scope file the fleet shares.

**How far the refusal reaches.** It refuses for a Service that is gone,
and, for one that is brought, in a namespace whose pods all come from
Deployments, StatefulSets, DaemonSets, Jobs, CronJobs or bare Pods that
are in the snapshot. Where a workload of the namespace is rendered by a
GitOps source, or an operator's custom resource owns workloads there, a
Service gets the `unseen` note once its own workloads are held or taken
out, and no refusal: a namespace GitOps manages nearly always gets the
note. That follows from the capture not holding what a source renders,
and it is said, never passed in silence.

**There are three answers, and only one refuses.** The Service will
answer, and nothing is said. It will not, and the restore is refused.
Or the snapshot does not say, and that is said as a NOTE, apart, and
refuses nothing: a snapshot taken before this version lists what an
object owns by namespace and without the names, so whether a webhook's
Service is one of them is not in it. A capture taken now lists the
Services by name (`names` on the skip, in `coverage.yaml`), and the
GitOps sources an object owns likewise, and settles it, and beside each name its selector (`selectors`), so that what
answers behind a Service the snapshot does not hold is looked for as it
is behind one it does: among the workloads of the snapshot that the
selector picks. Where pods will run in that namespace that the
snapshot cannot show the labels of (the capture left them, or what
makes them, to an owner, a GitOps source or the platform that will be
there), they may be what answers: that is said as a NOTE (`why:
unseen`), and nothing is refused for it. A chart's own Deployment is not
such a case: its ReplicaSets and pods are its own, and its labels are
in the snapshot. Pods and the rest are still listed once per owner:
their names are the cluster's. A selector is labels and their values,
which pick pods, and holds no credential.

Writing the names changes one file of a snapshot, `coverage.yaml`, and
only for a cluster where an object owns a Service or a GitOps source
(an ApplicationSet's Applications): its digest then differs from one
taken before, though nothing in the cluster changed.
**A pipeline that pins a digest, or compares one capture's with the
last, sees that once, at the first capture with this version.** A diff or a compare reads objects, and
shows no difference for it; an earlier version reads such a snapshot as
it reads any other, and a snapshot taken before is read by this one.

`plan scope --check` exits 2 for one that refuses, so it is found before
the restore; with no scope, `plan rebuild` lists it, on stderr and in
the plan ("Webhooks with nothing to answer them";
`webhooksWithoutService` with `--json`), and exits as it always does.
`plan rebuild`, `plan scope --check` and `diff` take `--leave-out` as a
restore does, and say what the restore would. A restore with no scope that ran before this
version can be refused now. A diff still runs, and says it as a NOTE. With `--json` each webhook listed under
`scope.webhooksWithoutService` says `why` (`notBrought`, `held`,
`leftOut`, or `unknown` and `unseen` where the snapshot does not say)
and whether it `blocks`, and a refused restore's document lists them as
`webhooksWithoutService`. Bring what answers at the Service, leave the
webhook out with `--leave-out`, or, knowing what it will refuse, accept
it in a scope file, which may hold nothing else (such a file narrows
nothing and leaves nothing out, Jobs included):

```yaml
withoutService:
  - ValidatingWebhookConfiguration/policy
```

That accepts the configuration: every hook of it, those added to it
later too. The name begins with what it is and a pattern may follow
(`policy-*`); one that begins with a pattern would accept any
configuration that comes later, and is refused. A
name that accepts nothing is an error, so a line for a webhook that
`--leave-out` also removes has to go. A hook with `failurePolicy:
Ignore`, a conversion webhook and an APIService are noted and do not
refuse a restore: none of them refuses a write of anything but its own
kind, and a restore goes on with an APIService unavailable.

Two entries that fit one namespace choose from it together. A release or
a label is looked for in the namespaces of its own entry: one that fits
nothing there is refused, as a pattern that fits no namespace is, and as
a mistyped `--leave-out` is.

**Jobs are left out** whenever a scope is given, in every namespace and
whether or not they had finished (a snapshot does not say), those of a
release that is brought among them: a Job restored runs again. A CronJob
is not a Job: it comes with its release and keeps its schedule. `jobs: true` in the
file brings them.

**`hold: true` on an entry brings what it chooses with nothing
running.** A drill beside the source restores workloads that, started
with the source's settings, would do the source's work a second time:
take its messages, call what it calls. Held, they are there to be read,
compared and started one at a time:

```yaml
narrow:
  - namespaces: [shop]
    releases: [api]            # runs
  - namespaces: [team-*]
    releases: [search, billing]
    hold: true                 # restored, not running
```

| Object | Held as |
|---|---|
| `Deployment`, `StatefulSet`, `ReplicaSet`, `ReplicationController` | zero replicas |
| another API's object with `spec.replicas` (an Argo `Rollout`, a Prometheus operator's `Alertmanager`, a `KafkaConnect`) | zero replicas |
| `DaemonSet` | a node selector no node has (`truthform.org/held`) |
| `CronJob`, and a `Job` brought with `jobs: true` | suspended |
| a Flux object (`HelmRelease`, `Kustomization`, a source), an Argo `CronWorkflow`, and another API's object with `spec.suspend` (a `ScheduledSparkApplication`) | `spec.suspend: true` |
| Argo CD `Application` | `spec.syncPolicy.automated` taken out |
| Argo CD `ApplicationSet` | `spec.template.spec.syncPolicy.automated` taken out, so what it makes does not sync by itself; refused, by name, where a `templatePatch` or a generator's own template could put it back, or a `RollingSync` strategy syncs what it makes from its controller |
| KEDA `ScaledObject` | `autoscaling.keda.sh/paused-replicas: "0"` |
| KEDA `ScaledJob` | `autoscaling.keda.sh/paused: "true"` |
| `HorizontalPodAutoscaler` | as it is: it stops while what it scales is at zero |
| what Kubernetes itself serves and runs nothing (`ConfigMap`, `Service`, `Ingress`, RBAC), and APIs known to run nothing and reach nothing outside (an `ExternalSecret`, a `OnePasswordItem`, Traefik and Istio routes) | as it is |

A hold is of what its entry chooses: the releases it names, the objects
it names, what carries its labels. Hold wins: what two entries choose is
held if either holds. A KEDA `ScaledObject` brought without a hold is
paused all the same when what it scales is held: it would start it from
zero.

**What a hold cannot stop is refused**, with nothing restored, by name:
a `Pod`, an Argo `Workflow`, a Tekton `PipelineRun` or `TaskRun` (each
runs as soon as it is there), and another API's workload with a pod
template that does not count its pods.

**What a hold does not know is named.** An object of another API with no
`spec.replicas` and no `spec.suspend` is brought as it is, and the run
lists it in a NOTE (`scope.broughtNotHeld` with `--json`). Some run
nothing; some have a controller that runs something for them (a database
operator's cluster, with its count under another name; a
`SparkApplication`, whose group ends in `k8s.io` and is not Kubernetes'
own); some act outside the cluster (a cert-manager `Certificate` asks an
authority for a certificate for the source's host names, a `PushSecret`
writes to a store, an external-dns `DNSEndpoint` writes DNS). The run
then says "stopped", not "nothing running", and does not end 0:
`plan scope --check` exits 2, and a restore applies what it was given
and exits 3, so a pipeline can tell a hold that holds from one that let
something through. Run `plan scope --check` before a restore: it writes
nothing. A diff's exit code still says only whether there are
differences.

Read the NOTE, or `scope.broughtNotHeld`, and for each object either
leave it out with `--leave-out`, or, having looked at it, name it under
`asTheyAre` on the entry that holds it:

```yaml
narrow:
  - namespaces: [shop]
    releases: [shop]
    hold: true
    asTheyAre:                 # looked at: brought as they are, not held
      - Certificate/shop-tls
      - KafkaTopic/*
```

Each is `Kind/name` as under `objects` (`Kind.group` where two APIs
share a kind). The name may be a pattern; the kind may not, so that a
line takes in one kind and no more. `Certificate/*` also takes in any
`Certificate` a later snapshot has, so name what was looked at as
narrowly as it was looked at. An entry names objects in its own
namespaces and what its releases made in another, or with no namespace
(one tied to a release by a label alone is held, and named, with any
release of that name that is held, and the entry that holds such a
release names it; where another release of the name is brought running,
the run says the object may be that one's). A scope that brought such an
object with a pod template and no count now refuses it, as a hold
refuses any workload it cannot stop.
What is named there is still listed (`scope.broughtAsTheyAre`),
and the run ends 0 when nothing else is left not held. A name that fits
no object the hold would have named is an error, as is `asTheyAre` on an
entry without `hold: true`: it does not hold anything, and does not
excuse a `Pod` or anything else a hold refuses.

Restore and diff list what is held and how, with the count it had
(`scope.held` with `--json`: "zero replicas (it had 3)"); a diff given
the same file expects it held. **Restoring again with the hold taken out
of the file starts it**, and that is how one is released: there is no
other command.

**A GitOps source brought without a hold refuses the restore**, with
nothing written and before anything is connected to, when the scope holds
anything and the source applies into a namespace the scope narrows. A
drill target that syncs the source's Git path starts what the scope held
back, and anything in it that reaches outside the cluster (image
automation, notifications) acts for real. A root Kustomization that
`flux bootstrap` made, or an Argo CD application that manages itself, is
in the snapshot, in a namespace a drill's scope seldom names, and so is
brought as it is unless something says otherwise.

What a source applies into is what the capture left to it, followed as
the webhook check follows it: from what is in a narrowed namespace to the
source or owner the capture left it to, and on through what that one was
left to, until it reaches an object the restore brings. A Kustomization
that applies a HelmRelease that renders into `store` applies into
`store`; an Application that an ApplicationSet generates is not in the
snapshot (the capture leaves it to the ApplicationSet), so the
ApplicationSet is what applies, and what is refused or held. Argo CD 2
tracks what it manages by `app.kubernetes.io/instance` unless told
otherwise (the application's name, or `namespace_name` for one outside
Argo CD's own namespace), and the capture takes such an object as one of
its own: in a narrowed namespace, that label naming an Application that
is brought counts as that Application applying there. **The label is
shared with ordinary Helm charts**, which set it to their release's
name. An object Helm installed (`meta.helm.sh/release-name`) is not read
this way; one a chart made that was applied some other way, beside an
Application of the release's name, is, and the restore is then refused
wrongly. The refusal says so; hold the Application or accept it. An
Argo CD set to track by an annotation alone, or by another label, leaves
nothing of this to read, and a restore is not refused for it: the
refusal says so.

**Flux's objects that act outside** are refused under a hold wherever
they are, as a source is: an `ImageUpdateAutomation` (it commits and
pushes to Git), an `ImageRepository` (it scans a registry with its
credentials), a notification `Provider` and `Alert` (they send), and a
`Receiver` (it takes webhooks from outside, and has the sources it names
reconcile when one comes: the outside then decides when they sync).
**Flux's sources that fetch count too**: a `GitRepository`,
`HelmRepository`, `OCIRepository` and `Bucket` reach a real Git host,
registry or bucket with the source's credentials, every interval. The
`GitRepository` a held root reads is held with it only if the entry
brings it too, as the example below does. An `ImagePolicy` only chooses
a tag from what an `ImageRepository` found, and is not refused.

**Argo CD's repository Secrets are not refused**
(`argocd.argoproj.io/secret-type: repository` or `repo-creds`). Such a
Secret fetches nothing: it holds the credentials Argo CD's repo server
uses, and Argo CD reads the repository of every Application it has, to
compare it, whether its automated sync is on or off, and reads a public
repository with no Secret at all. Refusing the Secret would neither stop
that reading nor find all of it. A hold of the Applications stops what
they apply, not that Argo CD reads: hold Argo CD's own workloads, or
leave them out, where it must not.

Where such an object is in the snapshot (made by hand), it is refused
itself. Where a GitOps source's Git path applies it, the capture leaves
it to that source and it is not in the snapshot: the source makes it
again once it runs, so **the source is refused for it, wherever either
is**, in a namespace the scope narrows or not, and the refusal names the
object and what it does (`appliesOutside` with `--json`). That is the
usual `flux bootstrap` with image automation: the root applies the
`ImageUpdateAutomation` from Git. Taking the root out with
`--leave-out`, or holding it, takes what it applies with it; what is in
the snapshot by hand stays, and is refused. Naming such an object under
`sourcesRunning` is an error that names the source that applies it:
accept or hold that.

**What an operator's resource makes is not followed.** Flux, Argo CD
and Helm set no owner on what they apply; a third-party operator does.
An operator's custom resource that owns an `ImageUpdateAutomation`,
`Provider`, `Alert` or `Receiver` (a tenant resource whose operator
makes one for it) is brought as it is under a hold, its operator makes
the object again, and **the restore is not refused for it**: leave the
resource out. A hold does not stop it: one with no `spec.replicas` or
`spec.suspend` is brought as it is and only named, and setting either
says nothing of what its operator makes for it.

Not refused:

- a source that applies only into namespaces the scope does not narrow,
  and applies nothing that acts outside;
- one already stopped: a Flux object with `spec.suspend: true`, an Argo
  CD application with no automated sync (or `automated.enabled:
  false`), an ApplicationSet whose template has none and that has no
  `templatePatch`, no generator template and no `RollingSync` strategy;
- anything, in a scope that holds nothing (the NOTE above,
  `scope.stillMade`, still names what a source makes).

`plan scope --check` names each in a NOTE, with the namespaces it
applies into or what it does outside (`scope.sourcesNotHeld` with
`--json`, each with `blocks`, `accepted`, `reaches` for one that acts
outside, and `appliesOutside` for a source that applies one), and exits
2 while one is left. A refused restore exits 1, says every cause at once (webhooks and these together), and its document
lists them as `sourcesNotHeld` (and `webhooksWithoutService`), with
`complete: false`. Either hold it, with an entry that brings its object
under a hold (a Flux object is suspended, an Argo CD application's
automated sync taken out, an ApplicationSet's taken out of its
template):

```yaml
  - namespaces: [flux-system]
    hold: true
    objects: [Kustomization/flux-system, GitRepository/flux-system]
```

or leave it out with `--leave-out`, or, having read what it does, accept
it by name:

```yaml
sourcesRunning:
  - Kustomization/flux-system/flux-system
  - GitRepository/flux-system/flux-system   # what the root reads
```

An ApplicationSet with a `templatePatch` or a generator's own template
cannot be held by its template, since either can give what it makes a
sync policy back; nor can one with `strategy: {type: RollingSync}`,
whose controller turns the automated sync of what it makes off and syncs
them itself, step by step (from Argo CD's documentation of progressive
syncs; `AllAtOnce`, the default and the only other type, leaves syncing
to each Application). A hold refuses such a set, by name, as it refuses
a `Pod`, and it is not taken as already stopped. Leave it out, or accept
it.

Each is `Kind/namespace/name` of the object, with no pattern: it is let
run by someone who has read what it does, and a pattern would let one
run that came later. One that is accepted is still listed (`accepted:
true`), and the run ends 0 when nothing else is left. A name that
accepts nothing is an error: one that is held, stopped, left out, or
applies nowhere the scope narrows, and any in a scope that holds
nothing (a file with `sourcesRunning` and nothing to narrow says that
too).

What to know before relying on a hold:

- it is of the objects in the snapshot. What a GitOps source or an
  operator makes from its own object once it runs is not held; a held
  Flux or Argo CD source makes nothing until it is released, and then
  makes all of it;
- a GitOps source that is brought without a hold and applies a held
  object puts it back as the source has it. Where it applies into a
  namespace the scope narrows, the restore is refused for it (below);
  where it applies only into namespaces the scope does not narrow, it
  is not, and a held object it applies there is put back all the same:
  hold the source too, or leave it out;
- a `CronJob` released may run at once what it missed while suspended,
  unless it sets `startingDeadlineSeconds`;
- KEDA before 2.13 does not read `autoscaling.keda.sh/paused` on a
  `ScaledJob`: leave it out there;
- with no pod made, a held workload does not show that its image can be
  pulled.

`plan scope --out` writes a file that lists every namespace a release
was installed in, each release with what it is made of, and each object
there that no release made: as written it brings everything but Jobs, and you delete what a drill is not to
bring. Restore and diff say on stderr what the scope left out (`scope`
with `--json`), and the plans given the file are of the part it brings:
the secrets to supply and the store items are those of what was chosen.

What a GitOps source renders is not in the snapshot, so a scope does not
choose from it: in a namespace that is brought, the source decides.
`--leave-out` is applied first (its entries name objects of the snapshot
as it is), then the scope, then `--rename`. Nothing checks that what is
brought does not need something left out.

### Into another environment

A snapshot restored beside its source (a drill, or one environment rebuilt
as another) needs two things changed, and nothing else.

```sh
truthform restore --context test --from snap/cluster \
  --leave-out leave.yaml --rename stores.yaml --secrets-from secrets.yaml
truthform diff    --context test --from snap/cluster --leave-out leave.yaml --rename stores.yaml
```

`--leave-out` is a list of objects the restore does not write and the diff
does not expect: `Kind/namespace/name`, or `Kind/name` for an object with
no namespace. `Kind.group` tells two APIs' kinds of one name apart, and
`*` is any kind, namespace or name (quote an entry that starts with one:
YAML reads a bare `*` as something else). The first to leave out is
where GitOps starts: restored as it is, the new cluster would sync the
path the source syncs.

```yaml
- Kustomization/flux-system/flux-system
- GitRepository/flux-system/flux-system
- "*/legacy/*"
```

The diff then does not report those as missing. If the target has an
object of the same name of its own (its own GitOps root), the diff lists
it as `extra`, as it does anything the snapshot does not hold.

`--rename` says where Secrets are read from instead: the start of a store
reference, and what replaces it. The longest start that fits a reference
is the one applied. Only fields that name a store or an item in it
change; the same text anywhere else is left alone:

| Object | What changes |
|---|---|
| `OnePasswordItem`; any object's `operator.1password.io/item-path` annotation | the item path |
| `ExternalSecret`, `ClusterExternalSecret` | `remoteRef.key`, `extract.key`, `find.path` |
| `PushSecret` | `remoteRef.remoteKey` (unchanged, it writes to the source's store) |
| `SecretStore`, `ClusterSecretStore` | Azure Key Vault's URL; Vault's server, path and namespace; the GCP project; 1Password's Connect host or SDK vault |
| Vault Secrets Operator | a secret's mount, path and namespace; `VaultConnection`'s address; `VaultAuth`'s mount and namespace |
| Secrets Store CSI `SecretProviderClass` | `keyvaultName`, `vaultAddress` |
| akv2k8s `AzureKeyVaultSecret` | the vault's and the object's name |

Which store object an `ExternalSecret` reads through (`secretStoreRef`)
is not changed: that object is restored under its own name, and which
vault it is is its own field, above.

The rename lists on stderr, and gives under `store_references` with
`--json`, what it did to every use of a store it knows:

| | |
|---|---|
| changed | a reference that points elsewhere now |
| kept | one a start names and replaces by itself: said to be the same in both environments |
| unnamed | one that says **which store** (a vault's address, a 1Password item's path), or what a `PushSecret` or `ClusterPushSecret` writes to, and that no start fits: it is the source's still |
| items unchanged | one that names an item in a store and that no start fits: the same name, read from whichever store its store object says |
| unreached | an object that uses a store in a way a rename cannot change: a CSI class's `objects` document, a 1Password store's `vaults`, a provider it has no field for, an `ExternalSecret` that finds by a pattern of names or by tags or reads from a generator, a pod that asks the Vault agent by annotation, an HCP Vault Secrets object, Vault Secrets Operator objects that read through no `VaultConnection` of the snapshot, a `PushSecret` that writes by `dataTo` or to a destination with no key |

**A restore is refused, with nothing written, while anything is unnamed
or unreached**: what reads or writes through it would use the source's
store. A `PushSecret` writes, so the item it writes to needs a start of
its own, whatever its store is. Give each a start, replaced by itself if
it is meant to be the same (a start replaced by itself is a whole
reference, or a path that ends with a slash: not `https://`, which is
every URL); leave the object out; or pass
`--keep-source-stores` to restore all the same; it then says how many of
them a `PushSecret` writes to, which the new cluster would write, and
delete where it is told to. The refused restore's
`--json` document carries the same lists. A diff writes nothing, and
only lists them.

The rename says on stderr which kinds of object it looked at
(`kinds_read` with `--json`). The list is of what it knows, and is not
proof that nothing else reads the source: a store's address in a workload's own configuration, a
plugin's environment, or an operator not in the table above is not seen.
A start is a plain prefix with no sense of where a name ends
(`kv-dev` also fits `kv-dev-2`), so write starts long enough to mean one
thing, and a start given twice is refused.

```yaml
vaults/apps/items/: vaults/apps-test/items/
https://kv-dev.vault.azure.net: https://kv-test.vault.azure.net
```

**Images.** The starts are tried on image references too: every
container, init container and image volume of a pod spec, wherever it is
(a Deployment, a CronJob, a KEDA `ScaledJob`, another API's workload),
an Argo workflow template's `container` and `script`, and a Tekton
task's `steps`, `sidecars` and `stepTemplate`. Not an Argo template's
own `initContainers`.
There are two ways to rebuild, and the rename file is the difference:

- **The registry the source pulls from is still there** (the quick way,
  and what a disaster usually allows): name no start for it. The rebuilt
  cluster has to be allowed to pull from it, and nothing else changes.
- **A registry of its own** (a rebuild that takes nothing of the source
  for granted): put the images there, built again or copied, and give
  the old registry a start.

```yaml
registry.example.io/shop/: drill.example.io/shop/
```

A start is read against the reference as it is written: `nginx:1.27`
does not start with `docker.io/`. It has to end where a part of the
reference does: `registry.example.io` starts `registry.example.io/app`
and not `registry.example.io.other.com/app`, nor
`registry.example.io:5000/app`, which is another registry;
`registry.example.io/team` does not start
`registry.example.io/team-b/app`. An image pinned by digest and built
again has another digest: copy such an image, or change the reference.
A start that fits both a store reference and an image changes both, so
write a registry's start with its host. The rename lists every image it
changed, and counts by registry those no start fits, which are pulled
from where the source pulls them (`store_references.images` with
`--json`: `changed`, `kept`, `left`). An image no start fits is never a
reason to refuse: most are meant to stay. `plan rebuild` lists the
registries a snapshot pulls from, and how many images have no digest: a
tag is whatever was pushed to it last, so a rebuild from tags runs what
is there now, which may not be what ran. An image named in a chart's
values or in an operator's own field (`spec.image` of a Prometheus or a
KafkaConnect) is not seen, by the rename or by the plan. Giving `--rename` at all
still means every secret store needs a start (above), so a file written
for images names the stores too, each replaced by itself if it is the
same.

An entry or a start that names nothing in the snapshot is refused, as is
a rename file with nothing in it, with nothing restored: a mistyped one would otherwise restore what it was
written to hold back, or leave the new environment reading the old one's
secrets. Leaving out is not checked against what stays: an object left in
that needs one left out fails, or waits, in the cluster.

## As a graph (Azure)

`truthform graph --from <snapshot>` writes an Azure snapshot as resources
and the relationships between them, as JSON, for a tool that maps an
estate (an asset inventory, a security graph) rather than recreating it.
It reads only the snapshot: no login, no request. Since the snapshot holds
no secret values, neither does its graph.

```sh
truthform graph --from snap/azure --out graph.json
truthform graph --from snap/azure --subscription <id> --tenant <id> --out graph.json
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
- **IDs** keep the `{{truthform|subscription}}` placeholder unless
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

`truthform mcp` serves TruthForm's knowledge over the Model Context
Protocol. For every field of a resource type it says whether the field is
required, set by the platform, write-only, secret or fixed at creation,
with the platform's documentation link. It can also capture, diff and
read reports, say what access to grant (`permissions`) and check what a
grant can read (`check_access`). No tool can restore and none grants
anything. An agent setting up someone's access should follow
[agents.md](agents.md). Add it to a client as:

```json
{"mcpServers": {"truthform": {"command": "truthform", "args": ["mcp"]}}}
```

## Snapshots from before the rename

TruthForm was called StackDNA up to v0.1.0-beta.20. A snapshot written then
is format 1 (`format: 1` in its `snapshot.yaml`); this build writes format 2.

- **Azure, Kubernetes, GitHub and Cloudflare:** a format 1 snapshot is read
  as it is by `diff`, `compare`, `restore`, `graph`, `report` and
  `schema-diff`. What TruthForm itself wrote under the old name is read
  under the new one; what the captured system called by the old name (a
  label, a tag, a CRD's group) is left as captured. Its digest differs from
  a new capture's, because the files on disk differ.
- **AWS and Google Cloud:** a format 1 snapshot is refused. A resource with
  no name of its own is named from a hash of its contents, and that name
  changed with the rename. Capture the source again, or use the build that
  wrote the snapshot.
- **A build from before the rename refuses a format 2 snapshot.**
- **A Cloudflare sign-in** made before the rename is not used. Sign in
  again; the old one is removed from the keychain when you do, or on
  `logout`.
- **A DNS record a subdomain restore wrote before the rename** is still
  TruthForm's, and compares as unchanged. Its comment keeps the old name
  until `--update` changes something else in the record.
- **What `permissions` generates** is now named `truthform-...`. Roles and
  files made from an earlier build keep working; remove them with the
  commands that build printed if you deploy the new ones.
- **`--json` output** is now `"schema": "truthform.org/output/v1"`, and a
  `graph` is `"format": 2`. Without `--subscription` and `--tenant` its
  IDs hold placeholders, which were renamed, so they do not match the IDs
  in a graph from an earlier build.
- **Environment variables** that began `STACKDNA_` now begin `TRUTHFORM_`.
  `STACKDNA_CLOUDFLARE_CLIENT_ID` set without the new name is refused by
  `login` and by a run that would use a stored sign-in, with a message
  naming both. A run that uses an API token, or has no sign-in stored, is
  not affected.
- **Kubernetes:** restore applies as the field manager `truthform`. A field
  an earlier build applied, and the snapshot no longer has, stays on the
  object under the old manager.

## Azure snapshots from an earlier build

An Azure snapshot written by this build stores its objects under paths in
lower case (see [Names in another case](#names-in-another-case-azure)). An
earlier one is read as it is. Captured again, its files move to the new
paths with the same contents, so its digest changes once.

Kept in git:

- **On Linux,** git records every Azure object file as renamed.
- **On Windows and macOS** (`core.ignorecase`, git's default there), git
  keeps each path in the case it was first committed in, with the new
  contents. This build reads such a snapshot, a clone of it included: where
  a path differs only in case from the one it writes, the digest is checked
  as if it were that one. A build from before this one refuses it as
  changed after capture. To have git record the new paths, in the working
  copy the capture was written to:

  ```sh
  git rm -r -q --cached <snapshot-dir> && git add <snapshot-dir>
  ```

## Known limits

- Azure objects whose names differ only in case are taken as one: capture
  keeps one of them, and compare, diff and `--values` match either. Azure
  Resource Manager names ignore case, and so far no captured type has been
  seen to keep two apart; if one does (Cosmos DB database and container
  names are case-sensitive), only one of them is in the snapshot. An ID
  inside a property that differs only in case is still reported as changed.
- A Log Analytics workspace's data sources can only be listed one kind at
  a time. TruthForm lists every kind Azure's definition names; a data
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
  write but never read back; a snapshot names them (`truthform.org/unreadable`)
  and a restore says it could not carry them.
- Proven against real systems so far: AWS (21 resources across 17 types,
  IAM and Lambda included; restore, update, another region), Azure, Google Cloud, Kubernetes and
  GitHub capture. Cloudflare and Google Compute are proven against
  simulated APIs only.
