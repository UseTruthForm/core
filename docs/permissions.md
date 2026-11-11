# Permissions

What to grant Truthform on each platform. A capture only reads; for it,
grant a read-only role and use the capture-only binary, which cannot send
a write whatever it is given. A restore creates and changes resources, so
it needs write access; grant that separately, for the restore only.

You do not have to build these by hand. `truthform permissions` writes
the grant as a template for the platform's own tool (a CloudFormation
stack, an Azure deployment stack, Terraform, a Kubernetes manifest; for
GitHub and Cloudflare, the exact token settings) and prints every command
to check what is there first, deploy it, verify it and remove it again,
with your values filled in. It grants nothing itself:

```sh
truthform permissions --platform aws --account 111122223333 --principal arn:aws:iam::111122223333:role/ops --source-profile ops
```

Then check what the grant can actually read, type by type, with a
capture that is written nowhere. A type refused for want of permission is
reported as **denied**, never as empty:

```sh
truthform check --platform aws --region us-east-1 --profile truthform-reader
```

Each line says whether it was **verified** (Truthform ran with exactly that
access) or is **expected** (from the platform's documentation and the
calls Truthform makes, not yet run with exactly that access).

## AWS

Truthform reads and writes through Cloud Control, which calls each service
on Truthform's behalf with the caller's own permissions. So a role needs
Cloud Control's actions **and** the read (or write) actions of every
service whose types are captured.

| Use | Grant | Status |
|---|---|---|
| Capture, diff | The managed policy `ReadOnlyAccess`, **plus Truthform's read add-on**. `ReadOnlyAccess` covers most services' `Describe*`/`Get*`/`List*` but not every newer service's. The add-on is the reads the CloudFormation registry's list and read handlers name that `ReadOnlyAccess` (v190) lacks: 527 actions in three customer managed policies. A schema naming an action is not enough to grant it, because some reads return secrets that `ReadOnlyAccess` leaves out on purpose (`ivs:GetStreamKey`, `glue:GetConnection`). Each action must be named as a read; not be named like a secret or data read; not be on a reviewed deny list; not be marked by AWS's Service Reference as data plane or a write (except a short reviewed list of reads AWS files under permissions or tagging); and have no output field that AWS's API models mark sensitive and that is named like a secret (a password, credential, token, key value, URL). Wildcards are expanded to concrete actions. Actions no source could vouch for, and actions `ReadOnlyAccess` leaves out of a service it otherwise covers, are kept but listed in the file for review. Truthform generates it from AWS's public sources only, with no AWS credentials, regenerates it weekly, and reviews each change before it ships; `truthform permissions` puts it in the role. `ReadOnlyAccess` itself also reads data (S3 objects, DynamoDB items). | **Verified** (2026-10-24), same account: the role from `truthform permissions` captured us-east-2 of the sandbox with the same 97 resources as an identity holding `ReadOnlyAccess` and `PowerUserAccess` (no differences), and was refused 2 of 1,161 types, both on purpose: `AWS::Bedrock::Session` (data plane) and `AWS::BedrockAgentCore::PaymentCredentialProvider` (credentials); a capture reports them as refused, not empty. No sampled write was allowed. With `ReadOnlyAccess` alone it was refused 87 types. The add-on is generated from the us-east-1 and us-east-2 registries; the capture proof is us-east-2 only. The sandbox holds few resources, so that count is a floor: about 37 types need a refused action in their *list* handler (`AWS::Glue::Connection`, `AWS::SecretsManager::SecretTargetAttachment`, `AWS::DataZone::Connection` among them), and an account using those services sees them refused too, reported as such. Kept on purpose, as configuration: reads that return contact details within a resource's settings (B2B Data Interchange profiles, Chime app instance users, Oracle Database@AWS contacts, invoice contacts) and Wisdom quick responses; a few outputs are free-form documents the models cannot look inside (Control Tower landing zone manifests and control parameters). A trust from another account is not yet verified. |
| Restore | `cloudformation:CreateResource`, `cloudformation:UpdateResource`, `cloudformation:GetResourceRequestStatus`, plus each service's create and update actions. `PowerUserAccess` covers every service except IAM. | Verified with `PowerUserAccess` for the 15 non-IAM types the drill restores (Lambda since 2026-10-26; creating a function also needs `iam:PassRole` on its role). |
| Restore IAM types | Add IAM write (`iam:CreateRole`, `iam:PutRolePolicy`, `iam:AttachRolePolicy`, `iam:CreatePolicy`, `iam:TagRole`, …) and `iam:PassRole` for anything that takes a role, scoped to the names being restored. | **Verified** (2026-10-24) for a role and a customer managed policy attached to it, with a grant limited to roles and policies named `truthform-drill*`: deleted and restored by the drill with no diff, and brought back from drift by `--update`. A role and its policy name each other, which is a reference cycle: restore creates the policy without its `Roles`, then sets them once the role exists. |

`ViewOnlyAccess` is not enough: it omits many of the `Get*` reads Cloud
Control's handlers make, and those types are reported as failed in
`coverage.yaml`.

## Azure

| Use | Grant | Status |
|---|---|---|
| Capture, diff | The built-in **Reader** role at the subscription. It reads every resource, and the extension resources Truthform captures: role assignments and custom role definitions, locks, policy assignments, diagnostic settings. | **Verified** (2026-10-23): a service principal holding only Reader captured the sandbox subscription to the same digest as its owner. The principal was deleted afterwards. |
| Restore | **Contributor**, plus **User Access Administrator** for role assignments and locks (`Microsoft.Authorization/*/write`, which Contributor does not have). **Owner** covers both. | Verified as Owner. |

## Google Cloud

The Cloud Asset Inventory and Cloud Resource Manager APIs must be enabled
in the project, as must each API whose resources are captured.

| Use | Grant | Status |
|---|---|---|
| Capture, diff | `roles/viewer` **and** `roles/cloudasset.viewer` on the project. | **Verified** (2026-10-23): a service account holding exactly these captured the sandbox project to the same digest as its owner. With `roles/viewer` alone the capture fails loudly: Cloud Asset Inventory answers 403. |
| Restore | `roles/editor`, plus `roles/iam.serviceAccountAdmin` and `roles/iam.roleAdmin` for service accounts and custom roles. | Expected. Restores have run as the project's owner. |

## Kubernetes

| Use | Grant | Status |
|---|---|---|
| Capture, diff | `list` on every resource type, cluster-wide, and nothing else. Not `get`: on `*` it covers subresources too, and `get` on `nodes/proxy` reaches the kubelet API and on `pods/exec` can open a shell. The built-in `view` ClusterRole leaves out Secrets: their values are never captured anyway, but without `list` on them their existence is not either. `list` does return their values to whoever holds the role. | **Verified** on every test run: on a real API server with RBAC, a service account bound by exactly the ClusterRole `truthform permissions` writes captured every type; the cluster refused it `get` on Secrets, `pods/exec`, `nodes/proxy` and `services/proxy`, a service account token and any write; and it was refused (forbidden) again once the grant was deleted. Not yet run on a managed cluster. |
| Restore | `cluster-admin`. A restore recreates Roles and bindings, and Kubernetes lets an identity grant only what it holds, so a narrower role fails on the first Role with a verb it lacks. | Verified with cluster-admin on kind clusters. |

## GitHub

The token comes from `GITHUB_TOKEN`. With a fine-grained token, grant
these, read-only for a capture, read and write for a restore:

- **Organization:** Administration, Custom properties, Webhooks, Secrets,
  Variables, Self-hosted runners (runner groups), Actions policies.
- **Repository (all repositories in scope):** Administration, Actions,
  Environments, Secrets, Variables, Webhooks, Pages, Metadata.

A classic token needs `repo` and `admin:org` (`read:org` is not enough:
GitHub answers the organisation's Actions settings, secrets, variables and
runner groups with "You must be an org admin").

Status: partly verified. A capture with a classic token lacking
`admin:org` read every repository collection and was refused exactly those
ten organisation collections, each naming the fine-grained permission
above; it reported them as failed, not as empty.

## Cloudflare

The token comes from `CLOUDFLARE_API_TOKEN`: **Zone: Read** and
**DNS: Read** for a capture, **Zone: Edit** and **DNS: Edit** for a
restore, scoped to the account. Status: expected; not yet run against
Cloudflare.

## What Truthform does with access it is given

- **Capture and diff never write.** Every client sits behind the read-only
  guard, which refuses any request that is not a read before it leaves
  the machine. The capture-only binary also has no
  restore command.
- **No secret value is written to a snapshot.** Values the platforms mask
  or never return (passwords, keys, a webhook's secret) are named in the
  snapshot and supplied at restore with `--values`, which is read and sent
  to the platform, never written.
- **A refused read is a failure, not an empty result.** A missing
  permission shows in `coverage.yaml` and REPORT.md and makes the capture
  exit 3 (incomplete).
