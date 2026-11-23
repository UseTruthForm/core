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

A snapshot can be kept in git. Its `.gitattributes` (`* -text`) tells git
to leave its files as they were written: Git for Windows otherwise checks
text files out with Windows line endings (`core.autocrlf=true`, its
default). A snapshot whose files have Windows line endings anyway (one
from an earlier build, cloned on Windows) is still read, because TruthForm
never writes a carriage return and reads CRLF back as the LF it wrote; a
build from before this one refuses it as changed after capture. Neither
file is part of the digest.

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
`compare` does the same between two snapshots, and a diff of an environment
(`--config`) for each target.

### An object one side left out

An object one side has and the other left out on purpose is still `missing`
or `extra`, and still counts: nothing here changes what a diff reports or
the exit code. Its line says why the other side left it out, from that
side's own record:

```text
missing  v1|ConfigMap|shop|cfg (left out on the other side: identical to the distribution baseline; a new cluster provides it)
```

A note is given only where a skip names that object and no other: on
Kubernetes by type, namespace and name; Helm history, listed once per
release as `sh.helm.release.v1.<release>.v*`, stands for that release's
`.v<N>` Secrets only (it records the release, not which revisions, and its
note says so), and a Secret of Helm's type that Helm did not name as
its own is listed by its own name and stands for itself (a snapshot under
Kubernetes capture rules before 2 wrote the two alike, so its Helm history
skips give no note); on GCP by the name the snapshot keys; on Azure from
snapshots that record Azure capture rules 1, which name a skip by its group
and the name the snapshot keys (an extension by its path below the group).
An Azure snapshot without rules named an extension by its group and last
name alone, the same as another of that name, so it gives no notes. AWS and
the SaaS platforms give none: their skips name a resource by its identifier,
which another's name in the snapshot may be.

The reason explains the difference; it never makes it safe. Something left
out on one side was not compared, and may have been edited: given a GitOps
tool's labels, an owner reference, or a root status it did not have, or
changed to or from a baseline. Look at the object itself.

Every Kubernetes and Azure snapshot records the version of the capture
rules it was taken under (`rules` in `snapshot.yaml`, outside the digest). A snapshot
without one counts as 0: every build up to and including beta.23 wrote it so.
Kubernetes version 1 captures a self-applying GitOps root, and the source a
self-applying Kustomization reads from, which builds before beta.23 left
out; version 2 lists Helm history families apart from Secrets listed by name.
Where the side that left an object out has no rules and gave a GitOps
source's reason, the line adds that this may be why:

```text
extra    kustomize.toolkit.fluxcd.io/v1|Kustomization|gitops|root (left out on the other side: applied by Flux Kustomization gitops/root; restoring it recreates this; a snapshot from a build before beta.23 left out a self-applying GitOps root and the source it reads from, so this may be one)
```

A snapshot under rules newer than the build reading it is refused, naming
the version: read it with a newer TruthForm.

The digest detects accidents, not tampering: it is a plain SHA-256 of the
files, and anyone who can write a snapshot can write its digest. Keep
snapshots where only the pipeline that captures them can write.

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
- **VPC Network Peering (GCP):** a peering is not a resource but an entry
  in each network's `peerings`, which a capture keeps in the network's spec
  (its `state` goes to the status). A restore creates the networks, then
  adds each entry with `networks.addPeering`, one at a time; the peering is
  `ACTIVE` once both networks have theirs. With `--update` an entry that
  differs is changed with `networks.updatePeering` and a missing one added.
  An entry only the target has is reported and left: a restore removes
  nothing.
- **Outside the project (GCP):** a VPC Service Controls perimeter belongs
  to an access policy, and no project's inventory lists it. A restore looks
  for it by its own name, creates it under the policy when it is not there,
  and with `--update` patches one that differs. One it cannot read is not
  created over. A capture of the project does not hold it.
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
| 3 | Incomplete: the snapshot was written but some types could not be read, a restore applied only some resources, a restore under a hold brought objects not held, or a translation refused something, did not look at a type, left a setting unread, made something less protected, or found a Kubernetes manifest that names an Azure thing with no translation |

## Machine-readable output

Add `--json` to `capture`, `diff`, `restore`, `compare`, `plan` or `translate` (an
environment `--config` too). Stdout is then one JSON document, named by its `schema`
field (`truthform.org/output/v1`), and everything meant for a person goes
to stderr. The exit code is the same as without it. A capture's document
says whether it is `complete` and lists its `gaps`, and under `throttled`
the gaps a later capture can close as it is; a diff's lists each
change with its `kind` (missing, extra, changed, not working) and `fields`,
and, on a missing or extra object the other side left out,
`skippedOtherSide` with its `reason`; a
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

**A `HelmChart` is what pulls a chart.** helm-controller makes one for
each `HelmRelease` with a chart source (`spec.chart`), in the chart
source's namespace, and source-controller pulls with it from the chart
source's repository or registry, with that source's credentials. A
`HelmRelease` with `chartRef` makes no `HelmChart`: helm-controller reads
the artifact of the `OCIRepository` or `HelmChart` it names, which is
refused or held for itself. Brought not held, such a release is still
refused, for what it installs, and its refusal speaks of no `HelmChart`.
**A `HelmRepository` of `type: oci` fetches
nothing**: source-controller makes it static and never reads from it, and
its `HelmChart`s do the pulling. So one that is brought not held is not
refused, and there is nothing to accept under `sourcesRunning`. Held, it
is suspended and listed as held, with a word that this stops nothing:
hold its `HelmChart`s, or the `HelmRelease`s that make them. One the
capture left to a source (applied by a Kustomization) is not in the
snapshot, and its type with it: it counts as one that fetches, and the
source that applies it is refused for it. So:

- the `HelmChart` helm-controller made is skipped by the capture
  (rendered by its `HelmRelease`), and a restore does not bring it: the
  release makes it again once it runs, so **a `HelmRelease` brought not
  held is refused for its chart**, wherever either is, and the refusal
  names both;
- **a held `HelmRelease` makes no chart in a new cluster**:
  helm-controller does not reconcile a suspended release, and it makes
  the chart only when it does. It is not refused;
- a `HelmChart` in the snapshot (made by hand, or captured for another
  reason) pulls for itself, and is refused like the sources above unless
  it is held or accepted;
- **on a cluster that already has the chart** (a restore in place), a
  held release leaves it there, and source-controller goes on pulling
  with it: suspend the chart too.

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

## To another cloud (Azure to AWS or GCP)

`translate` rewrites an Azure snapshot as snapshots for another cloud, offline.
It reads one snapshot and a map, and writes a snapshot per target platform,
which `plan`, `restore` and `diff` take as they are. It makes no request, so
the capture-only build has it too. So far it translates Service Bus,
virtual networks, network security groups wherever they are attached
(subnets, network interfaces, both at once), application security groups,
flow logs, what routes the subnets' traffic (route tables, NAT gateways,
peerings), public and private DNS
zones, storage accounts' blob containers, Key Vault secrets, container
registries, AKS clusters (their configuration: the workloads travel
through the Kubernetes snapshot), the configuration (never the data)
of Azure Database for PostgreSQL flexible servers and Azure SQL servers,
and workload identity (the managed identities a cluster's service accounts
use, with what their data roles let them reach); every other type is
reported as not looked at (design: issue #32).

```sh
truthform translate --from snap/azure --map map.yaml --out moved/
truthform restore --platform aws --region eu-west-1 --from moved/aws
```

With `--kube` and `--gitops` it also lists what the cluster's workloads
name that was renamed: see [Kubernetes workloads and
GitOps](#kubernetes-workloads-and-gitops).

The mapping is fixed. Each Azure service has a few destinations, and the map
is the only per-customer input: which destination each service class goes
to, the region, and names the target does not allow or that would collide.
Nothing the map leaves out gets a default.

```yaml
to: aws                     # or gcp
region: eu-west-1           # aws; gcp where something regional is written (a subnetwork, a bucket)
destinations:
  messaging: sqs-sns        # sqs-sns (aws), pubsub (gcp), or rabbitmq (in the cluster, on either)
  network: vpc              # a VPC (aws) or VPC network (gcp)
  secrets: secret-manager   # Key Vault secrets: Secrets Manager (aws) or Secret Manager (gcp)
  registry: ecr             # ecr (aws) or artifact-registry (gcp)
  storage: buckets          # an S3 bucket (aws) or Cloud Storage bucket (gcp) per blob container
  dns: route53              # route53 (aws) or cloud-dns (gcp)
  databases: rds            # rds (aws) or cloud-sql (gcp)
  clusters: eks             # eks (aws) or gke (gcp), for AKS clusters
  identity: workload        # managed identities of the clusters' service accounts, and their data roles
secrets:                    # gcp: where Secret Manager keeps each secret; it cannot change later
  replication: user-managed # automatic, or user-managed with
  locations: [europe-west1, europe-west4]
network:                    # aws: an Azure subnet spans the region's zones, an AWS one is in one
  zone: eu-west-1a          # every subnet, or
  zones:
    net/core/data: eu-west-1b   # one per subnet, keyed group/network/subnet
  egress:                   # aws: the public subnet a network's NAT gateways sit in
    net/core:               # keyed group/network
      subnet: 10.20.255.0/28    # a free /28 or wider of the network's range
      zone: eu-west-1a          # network.zone when left out
  defaultOutbound: nat      # Azure's default outbound access becomes a NAT (billed); without it, no egress
  nsgs:                     # the network an NSG is written in when nothing in the snapshot uses it
    net/spare-nsg: net/core     # keyed group/nsg: group/network; without it such an NSG is refused
  flowLogs:
    destination: arn:aws:s3:::shop-flow-logs/azure/   # aws: the bucket (and folder) flow logs are delivered to
    everywhere: true            # log every translated network, not only those the source logged (billed)
privateAccess:              # gcp: the service perimeter for Pub/Sub, Secret Manager, Artifact Registry (see Private access)
  accessPolicy: accessPolicies/123456789
  perimeter: shop_prod
  restoreIdentity: serviceAccount:truthform@ops.iam.gserviceaccount.com   # or restoreFromInside: true
sessions: fifo              # how a session queue is carried: fifo, ordering or single-active-consumer
rabbitmq:                   # for messaging: rabbitmq
  namespace: messaging
  replicas: 3
  tlsSecret: broker-tls     # without it the brokers listen in plain text, reported as less protected
clusters:                   # per AKS cluster, keyed group/cluster: what Azure cannot say (the other target's keys are refused)
  rg/shop:
    roleArn: arn:aws:iam::111111111111:role/eks-shop        # eks: identity is not translated,
    nodeRoleArn: arn:aws:iam::111111111111:role/eks-nodes   #   so these name roles that exist
    subnets: [net/core/spare]   # eks: more subnets, when the pools' are all in one zone
    kmsKey: 0b2c3d4e-1111-2222-3333-444455556666           # a KMS key ID or ARN (eks), a Cloud KMS key name (gke)
    serviceAccount: gke-nodes   # gke: the nodes' service account (an ID in the project, or an email)
    podCidr: 10.250.0.0/16      # gke: for Azure CNI without overlay, whose pods had subnet addresses
    pools:
      system:
        instanceType: m7i.xlarge    # eks; VM sizes are not translated
        machineType: n2-standard-4  # gke
        zones: [europe-west1-b, europe-west1-c, europe-west1-d]   # gke
        subnet: net/core/app        # for a pool in the network AKS made itself
prefixes:                   # a prefix for every queue and topic of one Service Bus namespace,
  rg/shop-test: test-       # keyed group/namespace: two namespaces that share names collide
booleans: text              # a boolean application property is sent as the word true or false;
                            # without it a SQL filter that compares one with TRUE or FALSE is refused
names:
  rg/shop/legacy.feed: legacy-feed   # a name SQS does not allow
  rg/shopfiles/$root: shopfiles-root # a bucket name, keyed group/account/container
databases:                  # per server, keyed group/server: what Azure cannot say
  data/shop-pg:
    instanceClass: db.m6g.large      # aws; gcp: tier: db-custom-2-8192. No default, and no SKU translation
    subnets: [net/core/db2]          # more subnets of a translated network; RDS needs two zones
    kmsKey: arn:aws:kms:...          # for a server encrypted with its own key; gcp: a Cloud KMS key name
  data/shop-sql:
    instanceClass: db.m6i.xlarge
    edition: sqlserver-se            # aws: sqlserver-ex, -web, -se or -ee
    licenseModel: license-included   # aws: or bring-your-own-media
    version: 16.00.4185.3.v1         # aws: an RDS engine version; gcp: SQLSERVER_2022_STANDARD
    subnets: [net/core/app, net/core/db2]
    storageGB: 300                   # only when its databases give no maximum size
    acceptTlsFloor: true             # only after checking the target: see below
```

| Service Bus | sqs-sns | pubsub | rabbitmq |
|---|---|---|---|
| Namespace | (none: the account and region) | (none: the project) | `RabbitmqCluster` |
| Queue | SQS queue + dead-letter queue | topic + subscription of its name, + dead-letter topic | quorum `Queue` + dead-letter queue |
| Topic | SNS topic | topic | headers `Exchange` |
| Subscription | SQS queue subscribed with raw delivery, a queue policy for that topic only | subscription | quorum `Queue`, a `Binding` per rule |
| Correlation rule | filter policy on message attributes (`$or` for several) | filter on attributes (`OR` for several) | headers binding |
| SQL rule that compares text for equality (`=`, `IN`, `AND`, `OR`) | the same filter policy: one key with its values, or `$or`. Five keys and 150 alternatives at most | the same filter | a headers binding per alternative |
| SQL rule with `EXISTS(property)` or `NOT EXISTS(property)` | `{"exists": true}` or `{"exists": false}` on the key | `attributes:property`, `NOT attributes:property` | refused: a headers binding matches a value |
| SQL rule that compares a property with `TRUE` or `FALSE` | with `booleans: text` in the map: a match on the word `true` or `false`, which senders then send. Refused without it | the same | the same |
| Any other SQL rule (any other `NOT`, `LIKE`, `IS NULL`, `<>`, an ordering, a number, a system property, a function) | refused, with what was met | refused | refused |
| Rule action | refused | refused | refused |
| Rule set default deny, public access disabled | a policy on every queue and topic denies sending, receiving and publishing to requests that come neither through the namespace's SQS and SNS endpoints nor from the rule set's public ranges (see Private access) | no network setting per topic: the project's service perimeter (`privateAccess` in the map; see Private access), or less protected without one | the brokers' Service answers inside the cluster only |
| Session queue | FIFO (`sessions: fifo`) | ordered delivery (`sessions: ordering`) | single active consumer |
| Shared access keys | refused: identity is a change to the app | refused | refused |

A SQL filter matched a property whatever the case of its name's letters
(`Area`, `area`); no target does. A translated filter names each property
as the subscription's first rule wrote it, and the report lists those
names: senders set the attribute so, or the message is not delivered.

| Network | aws | gcp |
|---|---|---|
| Virtual network | VPC. A range wider than /16 is written as its /16s and a second range as a second block: the VPC is created with one and given the rest (`AWS::EC2::VPCCidrBlock`), the same addresses. Refused where AWS takes no VPC of them (ranges of two private families, more than 50 blocks) | VPC network, custom mode, regional routing, MTU 1500 |
| Subnet | subnet in the map's zone | subnetwork in the map's region |
| NSG on a subnet | a security group per network, holding what the NSG allows with its denies taken out | a firewall rule per NSG rule, same priority, allow or deny, applied by a network tag per NSG |
| NSG on a network interface, alone | a security group of its own, for what takes the machine's place | the same rules under the NSG's tag, which that machine carries |
| NSG on a subnet and another on an interface in it | one security group holding only what both allow; never the two groups side by side, which would add up | one tag of allow rules (priority 1000) for what both allow, and a deny of all other egress (1001); never the two tags side by side |
| Application security group | a security group with no rules (its only egress rule is to 127.0.0.1/32, so it adds nothing), which rules name as source or destination and members carry | a network tag `asg-<name>`: `sourceTags` in ingress rules; an egress allow to a group is not carried over, an egress deny denies the members' subnets whole |
| Rule that applies to a group's members only | written in a security group only those members carry (`<nsg>-as-<group>`) | written under a tag only those members carry (`<nsg>-as-<group>`) |
| Deny that names a group, before an allow of address ranges | the subnets the group's members are in are taken out of the allow whole (stricter) | exact: a deny with `sourceTags` |
| NSG on a subnet whose `privateEndpointNetworkPolicies` lets it filter private endpoints | the interface endpoints' security group lets in HTTPS from what every private endpoint behind them let in | Private Google Access only on the subnetworks all of whose addresses every such endpoint took HTTPS from |
| NSG nothing uses | written in the network the map names (`network.nsgs`), attached to nothing; refused without it | the same |
| Flow log of a virtual network or subnet (or interface: its subnet) | a VPC flow log on the VPC or subnet, to the map's S3 bucket, every minute, in a fixed format | VPC Flow Logs on the subnetworks: every flow, every minute, all metadata, to Cloud Logging |
| Flow log of an NSG (retiring) | a VPC flow log on each VPC the NSG is used in | VPC Flow Logs on those networks' subnetworks |
| Azure's default rules | written as their effect (the network allowed in, all allowed out) | the network's allow at 65000; GCP's own rules match the rest |
| NAT gateway on a subnet | internet gateway, a public subnet from the map (`network.egress.<group/network>`), a NAT gateway there with as many Elastic IPs (8 at most), and a route table per subnet with a route to it | Cloud NAT on a Cloud Router listing those subnetworks, sending from as many reserved addresses, with the same idle timeout |
| Default outbound access (set, or left unset) | no egress, unless the map says `network.defaultOutbound: nat`: then a NAT gateway per network | the same: then a Cloud NAT gateway with Google's addresses |
| Route to a virtual appliance or gateway | no route for those destinations (they go nowhere; the appliance is a machine, and machines are not translated); it comes before a NAT gateway, as on Azure | an egress deny firewall rule for the subnet's range, priority 50, leaving `private.googleapis.com` and `restricted.googleapis.com` open |
| Route that drops (`None`) | no route for those destinations: the internet route is then written range by range around them | an egress deny firewall rule for the subnet's range |
| Route to `Internet`, `VnetLocal` | part of what the subnet reaches as before | the same |
| Route over the network's own range | less protected: a VPC's local route always delivers | the egress deny rule: dropped |
| Route to a service tag | not carried over; less protected where it kept traffic from the internet and the subnet has egress | the same |
| Peering, both networks in the snapshot, connected | one VPC peering connection, a route to the peer in each subnet's route table; `VirtualNetwork` in the NSG rules takes in the peer's ranges | an entry in each network's own `peerings` (a GCP peering is no resource: a restore adds it with `networks.addPeering` once both networks exist), every setting said, subnet routes of any range imported as Azure carried them; the firewall rules take in the peer's ranges |
| Peer ranges a subnet had no peering route to (a route came first, or `disablePeeringRoute`) | no route to them in that subnet's route table | a GCP peering gives every subnet the peer's routes: an egress deny rule, and an ingress deny rule (`<network>-<subnet>-no-peer`) for the answers Azure could not route |
| Peering to a network outside the snapshot, of some subnets, out of sync | refused | refused |
| Peering with access off, one-sided or not connected | nothing written: it carried nothing | the same |
| Forwarded traffic, gateway transit, remote gateways | reported: a peering on the target gives no transit | the same |

| Storage | aws | gcp |
|---|---|---|
| Storage account | no bucket of its own: its settings go into each of its containers' buckets | the same |
| Blob container | S3 bucket `<account>-<container>` (or the map's name), public access blocked, no ACLs | Cloud Storage bucket in the map's region, uniform access, public access prevention enforced |
| Public container, static website (`$web`) | refused: public read is an access grant, which is identity | refused |
| Encryption (Microsoft keys; twice) | SSE-S3; DSSE-KMS with AWS's key | Google's keys (layered by Google) |
| Customer-managed key, a key's encryption scope | the managed keys, reported as less protected | the same |
| HTTPS only, minimum TLS 1.2 or 1.3 | a bucket policy that only denies plain HTTP and older TLS | HTTPS only; no TLS minimum per bucket: less protected |
| Firewall, private endpoints only | the bucket policy also denies object reads, writes, deletes and listings to requests that come neither through the account's S3 interface endpoint nor from the firewall's public ranges. Object names stay listable through AWS's own services (see Private access): less protected unless Azure's trusted services passed the firewall | the bucket's IP filter: the firewall's public ranges, and the VPC networks that had a private endpoint to the account |
| Versioning, soft delete | versioning; soft delete as versioning with noncurrent versions expired (an early permanent delete is reported as less protected) | versioning, soft delete policy (7 to 90 days) |
| Time-based retention, version-level immutability | Object Lock (locked: compliance, unlocked: governance) | retention policy, written unlocked; version-level: less protected |
| Legal hold | less protected: holds are per object | the same |
| Access tier, redundancy | no class per bucket; one region | storage class (Hot, Cool, Cold, Smart as Autoclass); one region |
| Data Lake (hierarchical namespace) | flat namespace | hierarchical namespace |
| CORS | rules, GET PUT HEAD POST DELETE | rules, one header list |
| Lifecycle, inventory, replication, files, queues, tables | not looked at yet (the nearest equivalent named) | the same |
| Local users, account keys, SAS | refused, or listed as a change to the app: identity | the same |

Blobs are never copied: each bucket is written empty, and the report says
so. An account with no blob container writes nothing.

| Databases | rds | cloud-sql |
|---|---|---|
| PostgreSQL flexible server | `AWS::RDS::DBInstance` (postgres, its major version; 13 to 17), a DB subnet group, a security group | Cloud SQL instance (`POSTGRES_<n>`) |
| Azure SQL server | one `AWS::RDS::DBInstance` (the map's edition, license and version) for all its databases | one Cloud SQL instance (the map's `SQLSERVER_<year>_<EDITION>`) |
| Size (SKU) | the map's `instanceClass`; none: refused | the map's `tier` (its edition follows) |
| Storage, autogrow | `AllocatedStorage`; autogrow: `MaxAllocatedStorage` 32 TiB, Azure's ceiling | `dataDiskSizeGb`, `storageAutoResize` |
| SQL database sizes | storage is the sum of their maximum sizes | the same |
| Backup retention | `BackupRetentionPeriod` | daily backups kept as long; point in time 7 days at most (Enterprise) |
| Zone-redundant HA | `MultiAZ` | `availabilityType: REGIONAL` |
| Private (delegated subnet, or the map's subnets) | in the network's subnets, reached from the network on its port, or through the NSG of its subnet | private IP in the VPC network, no public IP; private services access is a requirement |
| Public, firewall rules | `PubliclyAccessible`, a security group allowing exactly those ranges on its port | public IP, the ranges as authorized networks |
| Firewall rule 0.0.0.0 (all Azure services) | not carried over (less than the source) | the same |
| Encrypted connections only | `rds.force_ssl` and the TLS floor in a parameter group | `sslMode: ENCRYPTED_ONLY` |
| Oldest TLS version | PostgreSQL: `ssl_min_protocol_version`; SQL Server: `rds.tls10`/`rds.tls11` disabled. TLS 1.3 only cannot be set (RDS always takes 1.2): less protected unless accepted | PostgreSQL: the `ssl_min_protocol_version` database flag; SQL Server: Cloud SQL has no such setting: less protected unless accepted |
| Engine version | PostgreSQL 14 to 18 under standard support; 11 to 13 run under paid RDS Extended Support (named in the report); older refused | the versions Cloud SQL's own definition lists and does not mark deprecated |
| Server parameters set by a person | the parameter group, where RDS has the parameter | database flags, where Cloud SQL has the flag |
| Customer-managed key | the map's `kmsKey`; without it, less protected | the same |
| Admin login | `MasterUsername`, the password kept by RDS in Secrets Manager | a requirement: create the user, with a password from a secret source |
| Databases | a requirement: create them, then move the data | the same |
| Entra ID admins, Entra-only sign-in | refused: identity (#32) | refused |
| Auditing, threat detection, vulnerability assessment | lost, reported as less protected | the same |
| Elastic pools, replicas, failover groups, backups | refused | refused |

Where the target cannot set the source's oldest TLS version (SQL Server on
Cloud SQL; TLS 1.3 only on RDS for SQL Server), the loss is reported as less
protected and the run fails. Once the target's floor has been checked,
`databases.<group/server>.acceptTlsFloor: true` accepts it: the loss is still
named, and no longer fails the run. RDS's PostgreSQL versions come from AWS's
release calendar; Cloud SQL's are read from its definition each run.

No password and no row of data is carried over. A server Azure kept after
deletion (Azure SQL's soft delete) gets deletion protection on the target,
which is stricter; other servers get none, since Azure's equivalent is a
lock, which is not translated.

| AKS cluster | eks | gke |
|---|---|---|
| Cluster | `AWS::EKS::Cluster` in the pools' translated subnets (two zones at least) | regional `Cluster` in the pools' subnetwork, its pools inline |
| Kubernetes version | `Version` 1.N, no patch; never upgraded, EKS validates it at restore | `initialClusterVersion` 1.N, in no release channel |
| Long-term support | `UpgradePolicy` EXTENDED (STANDARD otherwise) | EXTENDED channel |
| API server, public | public endpoint, `PublicAccessCidrs` the authorized ranges | public endpoint, authorized networks only (not Google's ranges) |
| API server, private | private endpoint only | private endpoint only |
| Pod and service ranges | service range carried; pods take VPC addresses (VPC CNI) | VPC-native: both written as secondary ranges of the subnetwork |
| Network policy | `azure`: the VPC CNI's policy enforcement (`vpc-cni` add-on); Calico, Cilium: less protected (their own kinds are not enforced) | `azure`: Dataplane V2; `calico`: Calico; `cilium`: Dataplane V2, less protected |
| Secrets with a customer key | `EncryptionConfig` with the map's key, else less protected | `databaseEncryption` with the map's key, else less protected |
| Node pool | `AWS::EKS::Nodegroup` per pool: count and autoscaling bounds, disk, labels, taints, spot, Windows AMI | `nodePools[]`: totals across the map's zones, disk, labels, taints, spot, Windows image, max pods, no public address |
| The cluster's and the nodes' own identity, Entra ID sign-in | not translated: roles from the map, access entries on its own | not translated: service account from the map, IAM on its own |
| Workload identity | with `identity: workload`: the EKS Pod Identity agent add-on, and a role per managed identity (see Workload identity) | the project's workload identity pool, the GKE metadata server on every pool, and a service account per managed identity |
| Add-ons, mesh, monitoring | not translated; Azure Policy and Istio are less protected until the target's own is installed | the same |

An AKS pool's VM size has no exact equivalent, so each pool's instance or
machine type is named in the map; a refusal prints the Azure size. A GKE
pool without a service account would run as the Compute Engine default one,
which holds the project's Editor role unless an organization policy
prevents it, so the map names one. Who gets admin on an EKS cluster is not
whoever restores it: access is by access entries alone. Maintenance
windows, managed namespaces and trusted access bindings are refused.

Azure evaluates an NSG's rules by priority, the first match deciding. A
security group only allows, so on AWS each allow is written with every deny
before it taken out, worked out as address ranges, ports and protocols.
What cannot be written exactly is dropped and named: a rule that names a
service tag, a source port, or part of the subnet's addresses. A
translation may let through less than the source, never more.

An NSG can sit on a subnet, on a network interface, or one on each. Azure
then asks both, each a list of its own, and lets a packet through only when
both do: an allow at priority 100 on the interface does not answer a deny
at 200 on the subnet. AWS adds up the security groups on an interface, and
GCP puts every rule that applies to an instance in one list, so neither can
hold the two NSGs side by side. The translation works out what both allow
and writes that once: one security group, or one network tag whose rules
only allow, closed by a deny. An NSG alone on an interface, or on a subnet,
is written by itself as before.

An application security group is a set of interfaces. On AWS it becomes a
security group with no rules that its members carry beside their own, and
that other groups' rules name as their source or destination; on GCP a
network tag. Who is a member is read from the network interfaces, private
endpoints and scale sets in the snapshot. Where a rule would need "the
members of a group, except some addresses" or "these addresses, except the
members of a group", no target can say it: the allow is narrowed (the
subnets the group's members are in are taken out whole) or left out, and
the report says which. An NSG whose interfaces fall into more than 16
different combinations of groups and other NSGs is refused.

Machines are not translated, so nothing attaches what is written for an
interface: the report's `attachments` list says, for every subnet,
interface, scale set and private endpoint an NSG filtered, which security
groups or tags it must carry on the target (all of them, and no other one
translated from an NSG), and whether the translation attached them
(`written`: the interface endpoints that stand for private endpoints) or a
person must (`requirement`). A GKE node pool is given its subnet's tag by
the translation. An EKS managed node group takes a custom
security group only through a launch template, which then replaces the
cluster's own security group instead of adding to it; the translation
writes none, and names the security group the node group's subnet stands
for.

### Evidence for an audit

Each network security group's entry in `translation.yaml` has an `evidence`
list: one row per rule (Azure's six default rules included) for every place
the NSG is written (`where`: a security group, or a network tag).

```yaml
- source: Microsoft.Network/networkSecurityGroups sec/app-nsg
  state: mapped with losses
  evidence:
  - where: AWS::EC2::SecurityGroup app-nsg
    rule: deny-ssh
    priority: 200
    direction: inbound
    access: deny
    status: exact
    enforcedBy:
    - 'AWS::EC2::SecurityGroup app-nsg: security groups only allow, and no rule of it allows what this denies'
```

`status` is one of:

| Status | Meaning |
|---|---|
| `exact` | the target lets through, and keeps out, what the rule did. `enforcedBy` names the target rules: the security group rules that carry an allow, the firewall rule of the same name, or, for a deny where the target only allows, the group none of whose rules allows what it denies |
| `stricter` | the target lets through less than the rule did; `why` says what and for which reason |
| `not carried` | an allow that is not written: nothing it allowed is let through. Never a deny: a deny that cannot be written exactly is widened (`stricter`), and one that cannot be read refuses the NSG |
| `does not apply` | the rule names addresses, or an application security group, that are not in this place: Azure did not apply it there either |

The rows are in a fixed order (place, direction, priority), so two runs
can be compared line by line. The claim behind them, that the target never
lets through what Azure denied, is tested by putting the same packets to
Azure's rules and to each target's rules as that cloud evaluates them.

### Flow logs

Azure's NSG flow logs retire on September 30, 2027, and new ones can no
longer be created; virtual network flow logs replace them. Both are a
`Microsoft.Network/networkWatchers/flowLogs` object, told apart by what
`targetResourceId` names. A virtual network flow log is the fully mapped
case; an NSG flow log is mapped to the networks its NSG is used in, and the
report says it is the retiring kind. The network watcher itself is Azure's
own and is not translated.

| Flow log setting | aws | gcp |
|---|---|---|
| Target: a virtual network | exact: `AWS::EC2::FlowLog` on the VPC (`ResourceType: VPC`) | exact: `logConfig.enable` on every subnetwork of the network |
| Target: a subnet | exact: a flow log on the subnet; none when its VPC is logged already | exact: `logConfig` on that subnetwork |
| Target: a network interface | more is logged: its subnet (the machine is not translated) | the same |
| Target: an NSG (retiring) | more is logged: each VPC the NSG is used in | more is logged: those networks' subnetworks |
| `enabled: false` | exact: nothing is written | exact |
| `storageId` (a storage account; Azure makes the container `insights-logs-flowlogflowevent`) | the map's choice: `network.flowLogs.destination`, an S3 bucket ARN; refused without it. The bucket's policy must let `delivery.logs.amazonaws.com` write (a requirement) | lost: records go to Cloud Logging (`compute.googleapis.com/vpc_flows`); a Logging sink carries them on (a requirement) |
| `retentionPolicy` | lost: the bucket's lifecycle rules expire them (a requirement names the days) | lost: the Cloud Logging bucket's retention (a requirement names the days) |
| Collected every minute | exact: `MaxAggregationInterval: 60` | exact: `aggregationInterval: INTERVAL_1_MIN`, `flowSampling: 1` |
| `format.version` | lost: the record is AWS's, in the format below | lost: the record is GCP's |
| `enabledFilteringCriteria`, `recordTypes` | lost: every flow is recorded (`TrafficType: ALL`), which is more | lost: every flow is recorded; `filterExpr` is not written |
| `flowAnalyticsConfiguration` (traffic analytics) | lost: analysed with AWS's own tools | lost: analysed with GCP's own tools |
| `identity` | lost: delivery is by the bucket's policy | lost: Google writes to Cloud Logging itself |
| No flow log on the source | none, unless `network.flowLogs.everywhere: true` | the same |

On AWS every flow log is written with one format, so that a parser can rely
on the order of its fields (space-separated, one line per record):

```
${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${vpc-id} ${subnet-id} ${instance-id} ${tcp-flags} ${type} ${pkt-srcaddr} ${pkt-dstaddr} ${region} ${az-id} ${flow-direction} ${traffic-path} ${reject-reason} ${encryption-status}
```

The first fourteen are AWS's default record in its order. What a record
holds on each cloud, for a parser that normalises all three:

| Azure virtual network flow log (`flowTuples`, comma-separated, in this order) | AWS (field of the format above) | GCP (`jsonPayload` of a `vpc_flows` entry) |
|---|---|---|
| 1. Time stamp, Unix epoch in milliseconds | `start` and `end`, in seconds: the window the record adds up | `start_time`, `end_time` (RFC 3339) |
| 2. Source IP | `srcaddr`; `pkt-srcaddr` is the packet's own where a NAT or a pod stands between | `connection.src_ip` |
| 3. Destination IP | `dstaddr`; `pkt-dstaddr` | `connection.dest_ip` |
| 4. Source port | `srcport` | `connection.src_port` |
| 5. Destination port | `dstport` | `connection.dest_port` |
| 6. Protocol, IANA number | `protocol`, IANA number | `connection.protocol`, IANA number |
| 7. Direction, `I` or `O` | `flow-direction`, `ingress` or `egress` | `reporter`: `DEST` for inbound, `SRC` for outbound (a flow between two logged machines is reported by both) |
| 8. Flow state: `B` begin, `C` continuing, `E` end, `D` denied | no state. `action` is `ACCEPT` or `REJECT` (Azure's `D` is `REJECT`); `tcp-flags` is the OR of the TCP flags seen in the window (SYN 2, SYN-ACK 18, FIN 1, RST 4), from which begin and end are read for TCP only | no state and no verdict. A packet an ingress rule denied is not recorded at all; one an egress rule denied can be. Denied flows are seen only with firewall rule logging |
| 9. Encryption: `X`, or `NX` with a reason | `encryption-status` | none: Google encrypts traffic between VMs itself and records nothing of it |
| 10. Packets, source to destination | `packets`: one direction per record; the reply is a record of its own with the addresses swapped | `packets_sent`, source to destination only, an estimate when sampled |
| 11. Bytes, source to destination | `bytes` | `bytes_sent`: payload bytes only |
| 12. Packets, destination to source | the reply's own record | the reply's own entry |
| 13. Bytes, destination to source | the reply's own record | the reply's own entry |
| Outside the tuple: the rule that decided (`flowGroups[].rule`), `aclID` | none: `reject-reason` says only why AWS itself rejected | none; firewall rule logging names the rule |
| Outside the tuple: `macAddress`, `targetResourceID` | `interface-id`, `instance-id`, `subnet-id`, `vpc-id` | `src_instance`, `dest_instance`, `src_vpc`, `dest_vpc` (all metadata is on) |
| (none) | `log-status`: `OK`, `NODATA`, `SKIPDATA` | `rtt_msec` for TCP |

An NSG flow log's version 2 tuple differs from the above: seconds, not
milliseconds; `T` or `U` for the protocol; a verdict field (`A` or `D`)
before the state, which is only `B`, `C` or `E`; no encryption field.

Flow logs are billed by volume on both targets, so none is written where
the source had none unless the map asks (`network.flowLogs.everywhere`).

| Key Vault | aws | gcp |
|---|---|---|
| Vault | (none: the account and region) | (none: the project) |
| Secret | Secrets Manager secret `<vault>/<secret>`, no value; content type in its description, tags as tags | Secret Manager secret `<vault>_<secret>`, no version, replicated as `secrets.replication` says; content type as an annotation, tags that fit as labels |
| Firewall default deny, public access disabled | a resource policy on each secret denies writing its value, and reading it, to requests that come neither through the vault's Secrets Manager endpoint nor from the firewall's public ranges. A value stays readable through AWS's own services (see Private access): less protected unless Azure's trusted services passed the firewall | no network setting per secret: the project's service perimeter (`privateAccess`), or less protected without one |
| Soft delete | the recovery window each delete chooses | less protected: a delete is immediate |
| Purge protection | less protected: a delete may skip the window | less protected |
| Disabled secret, `exp`, `nbf` | written with no value; the dates are named (Key Vault only records them) | the same; `expireTime` would delete the secret, so it is not written |
| Access policies | identity, not translated: named, and listed as grants to make | the same |
| Azure RBAC | the secret roles of a workload's managed identity are translated (see Workload identity); every other assignment is refused | the same |
| `accessPolicies` child | refused: identity | refused |
| Key | refused: its material never leaves the vault (make one in AWS KMS) | refused (Cloud KMS) |

A capture never holds a secret's value and a translation writes none. On
AWS the restore takes each from `--values`
(`AWS::SecretsManager::Secret/<vault>/<secret>: {SecretString: ...}`) and
lists those created without one; on GCP add each value as a version after
the restore. A disabled secret is restored without one.

| Container registry | aws | gcp |
|---|---|---|
| Registry | a repository creation template for prefix `<registry>`: ECR makes each repository on its first push, AES-256, mutable tags | an Artifact Registry repository of Docker images in the map's region |
| Images | not copied: copy them; image references are listed with what each becomes (Kubernetes workloads and GitOps), not rewritten | the same |
| Firewall default deny, public access disabled | the template's repository policy denies pulls and pushes to requests that come neither through the registry's ECR endpoints nor from the firewall's public ranges | no network setting per repository: the project's service perimeter (`privateAccess`), or less protected without one |
| Customer-managed key, quarantine | less protected | less protected |
| Anonymous pull | not written: the repositories are private | the same |
| Admin user | not written: named, with who signed in with it | the same |
| Tokens, scope maps, credential sets | refused: identity | refused |
| Geo-replication, retention, content trust, export policy | named: kept in the map's region, untagged images kept, signatures and export settings not carried | the same |
| Tasks, connected registries, transfer pipelines | refused | refused |
| Webhooks, cache rules | not translated yet | not translated yet |

| DNS | route53 | cloud-dns |
|---|---|---|
| Public zone | public hosted zone, tags as hosted zone tags | public managed zone (global), tags that are labels as labels |
| Private zone (or a legacy `zoneType: Private` zone) | private hosted zone associated with the VPC each link's network became | private managed zone visible to the VPC network each link's network became |
| A, AAAA, CAA, CNAME, MX, NS, PTR, SRV, TXT, DS, TLSA, NAPTR record set | record set of its name and type, TTL and records as they are | resource record set of its name and type |
| SOA, the zone's own NS | not written: the target makes them | the same |
| Alias to an Azure resource (`targetResource`) | refused: it must point at that resource's translation | refused |
| Link to a network not in the snapshot, or refused | refused; a zone left with no network is refused | the same |
| Auto-registration of a network's machines | named: Route 53 registers nothing | named: Cloud DNS registers nothing |
| DNSSEC (`dnssecConfigs`) | less protected: Route 53 signs only with a KMS key, and keys are not translated | signed (`dnssecConfig.state: on`) with Cloud DNS's own keys |

A TXT string longer than 255 characters is written as consecutive strings.
Host names in records are written with their final dot. On AWS a hosted
zone and a record set are named as a capture of the account names them (by
their DNS name, then `-2`, `-3` for a name's other record sets), so a second
restore finds them. A translated zone answers nobody on the internet until
the registrar's delegation names the target's name servers: the report
lists that, and the DS record to take out or replace for a signed zone.

Azure's own zones for its services' private endpoints (`privatelink.*`, and
the zones of flexible servers placed in a network) are not copied: they name
Azure's services at Azure's addresses. They need no DNS destination; the
target answers its own services' names privately instead, as below.

| Private access | aws | gcp |
|---|---|---|
| Private endpoint to Service Bus (sqs-sns), Key Vault, a registry, blob or Data Lake storage | an interface VPC endpoint per service and VPC (`sqs`, `sns`, `secretsmanager`, `ecr.api`, `ecr.dkr`, `s3`) in the private endpoints' subnets, private DNS on, HTTPS from the network (or from what the subnet's NSG let in, where it applied to them) | Private Google Access on the network's subnetworks (only those an NSG that applied to the endpoints let in) |
| Private endpoint to PostgreSQL or Azure SQL | nothing: RDS answers in the VPC | nothing: Cloud SQL answers on its private IP |
| Private endpoint to messaging in the cluster (rabbitmq) | nothing: the cluster reaches it | the same |
| Private endpoint to anything else (Azure Files, queues, tables, App Service) | refused | refused |
| `privatelink.*` zones, their records and links | not copied | not copied |

An interface endpoint takes one subnet per availability zone; private
endpoints in one subnet make endpoints in one zone, and the report says so.
On S3 the endpoint answers every lookup in the VPC
(`PrivateDnsOnlyForInboundResolverEndpoint: AllResolvers`), as a private
endpoint did, without a gateway endpoint.

### Workload identity

With `identity: workload`, an app that reached a queue, a blob, a secret or
an image on Azure through its pod's managed identity reaches the translated
one, and nothing else. It is the narrowest part of the translation: a grant
is written only when it is no more than the source's, and in doubt the role
assignment is refused and says why.

| Identity | aws | gcp |
|---|---|---|
| User-assigned identity with a federated credential for a translated cluster's service account | `AWS::IAM::Role`, trusted by EKS Pod Identity for those service accounts only | IAM service account |
| Federated credential (issuer a translated AKS cluster, subject `system:serviceaccount:<namespace>:<name>`) | `AWS::EKS::PodIdentityAssociation` (cluster, namespace, service account, role); the role's trust policy names the same three | `roles/iam.workloadIdentityUser` on the service account for `<project>.svc.id.goog[<namespace>/<name>]` |
| Any other credential (a pipeline's issuer, a cluster that is not translated, a subject that is not one service account, a matching expression) | refused | refused |
| An identity no translated cluster's service account uses (a VM's, an app service's) | refused, with its role assignments | refused |
| Two identities federated to one service account | both credentials refused: a service account takes one role | refused: one annotation |
| The kubelet identity's AcrPull | not written: the nodes run as the map's role; the report asks that it may pull | not written: the report gives the `gcloud` command for the node service account |
| Role assignment of such an identity, one of the roles below | statements in the role's inline policy, each on the ARNs of the objects by name | a binding on each object's own allow policy |
| Scope wider than one object (a namespace, an account, a vault, a resource group, the subscription) | narrowed to the translated objects in it, each by name; named as a loss | the same |
| Control-plane roles (Owner, Contributor, Reader, User Access Administrator), custom roles, any role not below | refused | refused |
| An assignment with a condition, or to a user, a group or a service principal | refused: people and pipelines are the customer's directory | refused |
| A Key Vault role on a vault with access policies; AcrPull or AcrPush on a registry with repository permissions | refused: Azure gave nothing there either | refused |
| Messaging to RabbitMQ | refused: a user's password is a Secret any pod of its namespace can mount, and sending to a queue needs write on the default exchange, which is every queue | refused |

The roles are a fixed table, by role definition ID, from each role's
published actions and data actions:

| Azure role | aws | gcp |
|---|---|---|
| Azure Service Bus Data Sender | `sqs:SendMessage`, `GetQueueAttributes`, `GetQueueUrl` on each queue; `sns:Publish` on each topic | `roles/pubsub.publisher` on each topic |
| Azure Service Bus Data Receiver | `sqs:ReceiveMessage`, `DeleteMessage`, `ChangeMessageVisibility`, `GetQueueAttributes`, `GetQueueUrl` on each queue and subscription queue and its dead-letter queue | `roles/pubsub.subscriber` on each subscription and its dead-letter subscription |
| Azure Service Bus Data Owner | both of the above; managing the namespace is not granted | the same |
| Storage Blob Data Reader | `s3:ListBucket`, `ListBucketVersions` on the bucket; `s3:GetObject`, `GetObjectVersion` on its objects | `roles/storage.objectViewer` on the bucket |
| Storage Blob Data Contributor | the Reader's, and `s3:PutObject`, `AbortMultipartUpload`, `ListMultipartUploadParts`, `DeleteObject` on its objects | `roles/storage.objectUser` on a bucket without versioning; on one that keeps versions `roles/storage.objectViewer` and `roles/storage.objectCreator` (no overwrite, no delete: `objectUser` would also delete versions for good) |
| Storage Blob Data Owner | the Contributor's, and `s3:DeleteObjectVersion` | `roles/storage.objectUser` |
| Key Vault Secrets User | `secretsmanager:GetSecretValue`, `DescribeSecret` on each secret | `roles/secretmanager.secretAccessor` on each secret |
| Key Vault Secrets Officer | the User's, and `secretsmanager:PutSecretValue` | `secretAccessor`, `roles/secretmanager.secretVersionAdder`, `roles/secretmanager.viewer` |
| Key Vault Reader | `secretsmanager:DescribeSecret` | `roles/secretmanager.viewer` |
| AcrPull | `ecr:GetAuthorizationToken` (on `*`: it takes no resource), and `ecr:BatchGetImage`, `GetDownloadUrlForLayer`, `BatchCheckLayerAvailability` on `repository/<registry>/*` | `roles/artifactregistry.reader` on the repository |
| AcrPush | AcrPull's, and `ecr:InitiateLayerUpload`, `UploadLayerPart`, `CompleteLayerUpload`, `PutImage`; not `ecr:CreateRepository` | `roles/artifactregistry.reader` only: `writer` would also delete what is attached to an image |

What a role allowed that has no line here is not granted and is named: a
receiver dead-lettering a message itself, creating and deleting containers
and secrets, a user delegation SAS, and on GCP reading a secret's properties
with Key Vault Secrets User (the role that does also reads who may read it).

On AWS no statement names a wildcard but three: `*` for
`ecr:GetAuthorizationToken`, a translated bucket's objects (`<bucket>/*`),
and the repositories a translated registry's template makes
(`repository/<registry>/*`), which do not exist yet. A service that answers
only on its private path still denies these roles from anywhere else, as it
did on Azure.

EKS Pod Identity is used, not IAM roles for service accounts: a role for the
latter names the cluster's OIDC issuer, which EKS gives only when it makes
the cluster. The service accounts need no annotation; the node role must
allow `eks-auth:AssumeRoleForPodIdentity`; a pod on a Windows node gets no
role. On GKE each service account carries
`iam.gke.io/gcp-service-account: <account>@<project>.iam.gserviceaccount.com`,
which the report lists one by one. A GKE cluster's workload identity pool is
its project's: a service account of the same namespace and name in another
cluster of the project is the same principal. Where the translation writes
two clusters and a credential named one, that is reported as less protected.

On GCP a grant is an object of kind `iam.googleapis.com/Binding`. Restoring
it reads the object's allow policy, adds the member to its role, and writes
the policy back with the etag it was read with; nothing already in the
policy is removed, and a policy that already holds the member is left
alone. A capture does not read allow policies: a capture of the rebuilt
project holds none of these objects, and a diff against the translation
says so.

A service that answered only on its private endpoints (public network access
disabled), or only its firewall's ranges, answers only there on the target:

| Private only | aws | gcp |
|---|---|---|
| Service Bus (sqs-sns, pubsub) | `AWS::SQS::QueueInlinePolicy` on every queue and dead-letter queue (a subscription's holds SNS's delivery too), `AWS::SNS::TopicInlinePolicy` on every topic | the project's service perimeter, where the map names an access policy (`privateAccess`); less protected without |
| Storage | statements in the bucket policy | the bucket's IP filter (`vpcNetworkSources`: each network, with its own address ranges) |
| Key Vault | `AWS::SecretsManager::ResourcePolicy` on every secret | the project's service perimeter, where the map names an access policy (`privateAccess`); less protected without |
| Registry | `RepositoryPolicy` in the repository creation template | the project's service perimeter, where the map names an access policy (`privateAccess`); less protected without |
| A private service with no private endpoint in the snapshot and no public range | less protected: there is no private path to lock it to | the same (a bucket admits no network) |
| PostgreSQL, Azure SQL, AKS | already private: RDS not publicly accessible, the EKS endpoint | Cloud SQL's private IP, GKE's private endpoint |

On AWS the policy only denies, so it grants nobody anything and is not
identity. It denies the service's data actions (sending and receiving
messages, publishing, object reads and writes, a secret's value, image pulls
and pushes) to a request that comes neither through the interface endpoints
written for the service's private endpoints (`aws:SourceVpce`) nor from an
allowed public range (`aws:SourceIp`). Three things pass, on purpose:

- **Management actions.** Reading and changing a queue's, bucket's or
  secret's settings works from anywhere IAM allows, as Azure's management
  plane did with public network access disabled. Denying them would lock out
  the restore, a later capture and the console.
- **AWS's services acting as themselves** (`aws:PrincipalIsAWSService`):
  SNS delivering to a subscription's queue does not come through an endpoint.
  Such a service still needs an allow of its own; the only one written is
  that delivery.
- **Two actions, through AWS's services acting with the caller's
  credentials** (`aws:ViaAWSService`): `s3:ListBucket` and
  `secretsmanager:GetSecretValue`. The bucket's and the secret's own Cloud
  Control handlers call them, never through an endpoint, so a restore could
  not read what it wrote without that. It leaves a bucket's object names
  (through Athena, say) and a secret's value (through a CloudFormation
  reference) reachable from outside the network by a principal IAM allows.
  Where Azure's trusted services passed the source's firewall
  (`bypass: AzureServices`) that is what the source did; otherwise it is
  reported as less protected.

A repository gets the template's policy when its first push makes it; one
made any other way needs the same policy by hand.

On GCP, Pub/Sub, Secret Manager and Artifact Registry have no setting for
where a request comes from. A VPC Service Controls perimeter closes them. It
belongs to an access policy, which is the organization's to create (scoped
to the project or not), so the map names an existing one:

```yaml
privateAccess:              # gcp
  accessPolicy: accessPolicies/123456789   # gcloud access-context-manager policies list
  perimeter: shop_prod      # its ID in the policy: your choice, one per target project
  restoreIdentity: serviceAccount:truthform@ops.iam.gserviceaccount.com   # or user:<email>
  # restoreFromInside: true # instead: restores and captures run from one of the project's networks
```

One perimeter is then written for the target project. It restricts exactly
the services that had a private source, and a restore creates it in the
policy (`accesscontextmanager.servicePerimeters.create`, `get` and `update`
on the policy). What it does that the Azure source did not is reported:

- It restricts a service for the whole project. A namespace, vault or
  registry that answered the internet is closed with the private one of its
  service, and says so. A service with no private source is left out.
- It refuses management calls from outside too, the restore's own. So the
  map must say how restores and captures pass, or it is refused:
  `restoreIdentity` writes an ingress rule for that principal from
  anywhere, `restoreFromInside` writes none. The rule names Pub/Sub's
  management methods alone. Secret Manager takes no method restriction and
  an Artifact Registry create must be polled, so there the principal is
  admitted for the whole API, which stays reported as less protected;
  `restoreFromInside` closes that.
- Every network of the project is inside it. A translated network with no
  private endpoint to the service, and no peering with one that had,
  reaches it: reported as less protected.
- A public range the source's firewall allowed is not admitted (that takes
  an access level): narrower, and named.

A project can be in one perimeter only; where the target already is in
one, the restore is refused, and the services and rule go into that one by
hand. A perimeter takes up to 30 minutes to take effect. A capture of the
project does not hold it (it is the policy's), so a `diff` against the
translation lists it as missing; a restore finds it by its name. Without
`privateAccess` nothing is written, and these services stay reported as
less protected.

Cloud Storage is not put in the perimeter: a bucket's IP filter names the
networks per bucket, where the perimeter would close every bucket of the
project. The filter also covers the bucket's own settings: whoever restores
and captures from outside the admitted networks needs
`storage.buckets.exemptFromIpFilter`.

Every source object ends in one state, and `<out>/translation.yaml` lists
each with its reason and target objects:

- **mapped**, or **mapped with losses**: each setting with no equivalent is
  named with why (SQS keeps a message 14 days at most; Pub/Sub has no
  duplicate detection);
- **refused**: looked at, and there is no equivalent, or carrying it over
  would change what it does in a way nobody chose. A SQL filter that says
  more than equality on text is refused with its subscription, because
  without it the subscription would receive every message;
- **not looked at**: no descriptor for the type yet.

A loss that makes the target less protected than the source is marked
`widens`. Examples: a namespace that answered only private endpoints
becomes Pub/Sub topics on Google's public endpoint, guarded by IAM alone,
where the map names no access policy for a perimeter; a customer-managed
key becomes the platform's.

A setting no rule reads is marked `unread`. Each reader is checked in
the tests against Azure's published definition of its type, so a setting
Azure adds fails there first.

Anything refused, not looked at, widened or unread exits 3. The report also
lists what to do before a restore: the operators to install, the grants
Pub/Sub's service agent needs for dead-lettering, and the move from the
Service Bus SDK.

`--out` must be empty or an earlier translation's; a platform the earlier
one wrote and this one does not is removed.

Known limits:

- A restore of the translated objects works as any restore does, and a
  second one finds what the first made. A diff of the rebuilt target
  against them still shows differences: a capture holds every default the
  target fills in that the translation does not set.
- Each target object is built from, or checked against, the target's own
  published definition (the CloudFormation registry, the Pub/Sub, Compute,
  Cloud Storage, Secret Manager, Artifact Registry, Cloud DNS, Cloud SQL,
  GKE and IAM Discovery documents): downloaded and cached like `aws-coverage`, or read
  from `--schemas` and `--discovery`.
- Public addresses of anything but a NAT gateway, gateways, load balancers
  and firewalls are not translated yet. Machines are not either: what an
  NSG on a network interface comes to is written, and the report says what
  must carry it.
- Who is in an application security group is read from the network
  interfaces, private endpoints and scale sets in the snapshot. A member
  the snapshot does not hold (in a resource group left out of the capture)
  is not known, and a deny of the group does not reach its subnet on AWS.
- On GCP an Azure outbound rule that named a private endpoint's address is
  not carried to Google's API addresses, which Private Google Access
  reaches instead.
- Routing is translated as what each subnet's traffic can do, not object
  for object: Azure's routes are worked out per subnet (longest prefix, a
  route table's before Azure's own), and the target subnet is given the
  same reach or less. Azure's own drop of unused private ranges is not
  written: such an address is on no internet either.
- Outbound addresses change: whoever allows the old ones by address must be
  given the new ones (listed in the report's requirements).

### Kubernetes workloads and GitOps

`translate` does not rewrite a Kubernetes manifest. A cluster's workloads
are applied by Flux from Git; a Kubernetes capture leaves out what Flux
applies and keeps where Flux starts (see [Capture](#capture)), so
restoring that snapshot on the target cluster brings Flux back and Flux
rebuilds the rest. But the manifests in Git still name Azure things, and
that repository is yours to edit. Given the cluster's snapshot, a checkout
of the repository, or both, `translate` lists every place that does, with
what the translation made of the thing named:

```sh
truthform translate --from snap/azure --map map.yaml --out moved/ \
  --kube snap/kubernetes --gitops ~/src/fleet
```

```
Kubernetes workloads (read: a Kubernetes snapshot: 9 object(s), and 11 more the capture left to 6 GitOps source(s); a checkout of the repository: 25 YAML document(s) in 15 file(s), and 2 other text file(s)): 26 reference(s) to change, 17 to check, 14 with no translation; 3 source(s) not available to check.

Names an Azure thing with no translation (applied as it is, it would point at Azure):
  apps/base/shop/deployment.yaml:41 Deployment shop/web, applied by Flux Kustomization flux-system/apps
    spec.template.spec.containers[1].image names partner.azurecr.io/tools/proxy@sha256:0123...; it has no translation: registry partner is not in the Azure snapshot

To change in Git, or in the object where nothing in Git applies it:
  apps/base/shop/deployment.yaml:20 Deployment shop/web, applied by Flux Kustomization flux-system/apps
    spec.template.spec.containers[0].image names shopacr.azurecr.io/shop/web:1.4.2; on the target it is {{truthform|account|self|id}}.dkr.ecr.eu-west-1.amazonaws.com/shopacr/shop/web:1.4.2
    (the account is not known offline: {{truthform|account|self|id}} stands for it, as in the AWS snapshot)
    variable: ${registry_shopacr}
  apps/base/shop/scaling.yaml:10 ScaledObject shop/web-orders, applied by Flux Kustomization flux-system/apps
    spec.triggers[0] names KEDA azure-servicebus trigger on queue orders (namespace shop); on the target it is type: aws-sqs-queue; metadata: queueURL: https://sqs.eu-west-1.amazonaws.com/{{truthform|account|self|id}}/orders, awsRegion: "eu-west-1", queueLength: "20", scaleOnInFlight: "false", activationQueueLength: "2"
    variable: ${servicebus_shop_queue_orders}
```

Each reference ends in one of three states:

| State | Meaning | Exit |
|---|---|---|
| change | the thing has a counterpart on the target, and this is its name | 0 |
| check | the target has a form of its own that a person chooses: the role a service account takes, a storage class, an ingress class | 0 |
| no translation | the Azure thing was refused, not looked at, is not in the Azure snapshot, or is a service nothing here translates | 3 |

A reference with no translation fails the run like a refusal: applied as it
is, the workload would point at Azure. One that only needs editing does
not, and neither does a source that could not be read; that is counted
and named.

What is recognised, and what it is given:

| In a manifest | On AWS | On GCP |
|---|---|---|
| An image, chart or any value under `<registry>.azurecr.io` | `<account>.dkr.ecr.<region>.amazonaws.com/<prefix>/…`, the prefix the registry's repository creation template has | `<region>-docker.pkg.dev/<project>/<repository>/…` |
| A KEDA `azure-servicebus` trigger (a queue, or a topic with its subscription) | `aws-sqs-queue`: `queueURL`, `awsRegion`, `queueLength`, with `scaleOnInFlight: "false"` to count as Service Bus did | `gcp-pubsub`: `subscriptionName`, `mode: SubscriptionSize`, `value` |
| The same, with messaging in the cluster | `rabbitmq`: `queueName`, `mode: QueueLength`, `value`, on either cloud | the same |
| `<namespace>.servicebus.windows.net`, a connection string's `EntityPath` | the queue's URL or the topic's ARN; no host of its own | the subscription's or topic's full name (RabbitMQ: the brokers' Service) |
| A `SecretProviderClass` of provider `azure`, each of its objects | provider `aws`: `objectName`, `objectType: secretsmanager`, and an `objectAlias` that keeps the mounted file's name | provider `gcp`: `resourceName`, and a `path` that keeps it |
| An External Secrets store of a Key Vault (`azurekv`), each `remoteRef.key` read from it; a KEDA `azureKeyVault`; `<vault>.vault.azure.net/secrets/<name>` | the secret's name in Secrets Manager (`<vault>/<secret>`) | its ID in Secret Manager (`<vault>_<secret>`) |
| `<account>.blob.core.windows.net/<container>` (or `.dfs.`) | the container's bucket | the same |
| `<server>.postgres.database.azure.com`, `<server>.database.windows.net` | the endpoint RDS gives the instance: named, and not known until it is created | the address Cloud SQL gives it, or its connection name |
| `azure.workload.identity/client-id` on a service account, `azure.workload.identity/use` on a pod, KEDA's `azure-workload` provider | to check: `eks.amazonaws.com/role-arn`, or an EKS Pod Identity association and no annotation | to check: `iam.gke.io/gcp-service-account`, or roles granted to the Kubernetes service account itself |
| `service.beta.kubernetes.io/azure-load-balancer-internal: "true"` | `service.beta.kubernetes.io/aws-load-balancer-scheme: internal` | `networking.gke.io/load-balancer-type: "Internal"` |
| AKS's storage classes (`managed-csi`, `azurefile-csi`, …), a class of Azure's provisioners | to check: a class of the EBS or EFS CSI driver | to check: a class of the Persistent Disk or Filestore CSI driver |
| Application Gateway's ingress class and `appgw.ingress.kubernetes.io/` annotations, the application routing class, other `azure-` load balancer annotations | to check: the target controller's own | the same |
| Any other host under Azure's domains (`*.windows.net`, `*.azure.com`, …), a KEDA `azure-…` trigger of another type, an object of an `*.azure.com` API group, akv2k8s | no translation | no translation |

A value is never repeated whole: a connection string is named by its
host. The account and the project are not known offline, so the names
carry the tokens the target snapshots use
(`{{truthform|account|self|id}}`, `{{truthform|project}}`). Which role or
service account a workload takes is the identity translation's; here only
the form the target reads is named.

**Where it reads from.** Neither input holds everything, which is why
there are two:

- `--kube`, a Kubernetes snapshot of the source cluster, holds what no
  GitOps source applies and where Flux starts. Those objects are read like
  any manifest, since a restore recreates them from the snapshot as they
  are, pointing at Azure; and the workloads among them are listed by
  namespace as **not in Git**. It does not hold what Flux applies. It names
  it: every Kustomization and HelmRelease the cluster has, and how many
  objects the capture left to each.
- `--gitops`, a local checkout of the repository Flux reads, holds what is
  in them. References are given by file and line. Which Kustomization
  applies a file is worked out as Flux builds it: from the Kustomization's
  `path`, through that directory's `kustomization.yaml` and what it lists,
  or every manifest under the path when it has none. With `--kube` this
  starts from the Kustomizations the snapshot holds, so a repository that
  serves several clusters is read as this cluster reads it, and a
  reference in a file it does not apply is listed and not counted.
  Without, every Kustomization the files define is followed.

Nothing is rendered and no request is made: no `kustomize build`, no `helm
template`, no clone. So the report says, under **Not seen** and in
`translation.yaml` (`gitops.notSeen`, and `gitops.sources` source by
source), what that leaves out:

- a source whose content was in neither input (its path is in another
  repository, or only the snapshot was given): counted in the first line,
  and named;
- a HelmRelease's chart: its `spec.values` are read, not what the chart's
  templates render, the chart's own default values, or `valuesFrom`;
- what a kustomize patch, replacement, name prefix or generator changes,
  resources fetched from a URL, and charts kustomize inflates;
- objects the capture left to a Kustomization that are not in its files
  (generated), each named under its source;
- a value Flux substitutes (`${…}`), seen only where the variable is
  defined in the files; image references Flux image automation has not
  yet committed;
- files that are not YAML as written (a chart's templates), which are
  read line by line for Azure host names only;
- secret values (a connection string in a Secret or in the secret
  store), SOPS-encrypted files, other branches and other repositories,
  what Argo CD or Crossplane apply, and what the applications' own code
  names.

**The variables file.** `moved/gitops-variables.yaml` holds the same names
as a ConfigMap that a Flux Kustomization's `spec.postBuild.substituteFrom`
can read, one key per Azure thing that was translated, whether or not a
reference to it was seen. It is optional, a file to commit and not an
object of any snapshot, and it holds names only, never a secret:

```yaml
data:
  cloud: "aws"
  region: "eu-west-1"
  # on Azure: shopacr.azurecr.io
  registry_shopacr: "{{truthform|account|self|id}}.dkr.ecr.eu-west-1.amazonaws.com/shopacr"
  # on Azure: queue orders in Service Bus namespace shop
  servicebus_shop_queue_orders: "https://sqs.eu-west-1.amazonaws.com/{{truthform|account|self|id}}/orders"
```

A manifest then says `${registry_shopacr}/shop/web:1.4.2`, and one
repository serves both clouds when each cluster has such a ConfigMap with
its own values under the same keys (the comment above each key is its
value on Azure). Before committing it, give it the namespace of the
Kustomization that reads it and put the account or project where its
token stands. Flux then substitutes every `${name}` in what that
Kustomization applies, and an undefined one becomes empty: write
`$${name}` where a script must keep its own, or label the object
`kustomize.toolkit.fluxcd.io/substitute: disabled`. Database addresses
are not in the file: the target makes them up at creation.

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

### Skills for what a translation leaves to people

A [translation to another cloud](#to-another-cloud-azure-to-aws-or-gcp)
names what it does not do. For five of those, TruthForm carries a skill:
instructions an AI agent loads to help a person finish the work. Each
reads its work list from `translation.yaml`, has the agent propose and
check, and leaves whatever writes or grants to the person.

| Skill | For | Checked by |
|---|---|---|
| `translate-move-data` | blobs, images, secret values, databases and volumes, none of which a translation copies | counts, bytes and digests on both sides; a diff showing the copy changed no setting |
| `translate-grant-access` | refused role assignments: people, groups, pipelines, control-plane and custom roles | a capture of the target (AWS); the platform's own read (GCP, whose capture does not read IAM policies yet) |
| `translate-rebuild-machines` | VMs, scale sets and firewall appliances, and attaching the groups or tags the report's `attachments` list for each | a capture: each machine carries exactly what `carries` lists |
| `translate-sql-tls` | a SQL Server minimum TLS version the target cannot match | a measured floor on the target, and an exception on record before the map accepts it |
| `translate-flow-logs` | a parser or detections written for Azure's flow log records | the same test traffic parsed on both clouds |

The folders are in the repository's `skills/`, in the open Agent Skills
layout (`<name>/SKILL.md`), and in the binary:

```sh
truthform skills                       # list them
truthform skills translate-move-data   # print one
truthform skills --out .claude/skills  # write the folders where an agent loads them
```

`--out` writes only what is missing: a `SKILL.md` already there with
other text is left as it is and named, and the command exits 1. Over MCP
the same text comes from `list_skills` and `skill`, so an agent with the
server needs no folders.

A skill cannot make a result true. Each ends with what its checks do not
show (that a secret's value is the right one, that the right person is in
a group, that a rebuilt machine runs what the old one ran), for the person
to own.

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
