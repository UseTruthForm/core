# Permissions

What to grant StackDNA on each platform. A capture only reads; for it,
grant a read-only role and use the capture-only binary, which cannot send
a write whatever it is given. A restore creates and changes resources, so
it needs write access; grant that separately, for the restore only.

Each line says whether it was **verified** (StackDNA ran with exactly that
access) or is **expected** (from the platform's documentation and the
calls StackDNA makes, not yet run with exactly that access).

## AWS

StackDNA reads and writes through Cloud Control, which calls each service
on StackDNA's behalf with the caller's own permissions. So a role needs
Cloud Control's actions **and** the read (or write) actions of every
service whose types are captured.

| Use | Grant | Status |
|---|---|---|
| Capture, diff | The managed policy `ReadOnlyAccess`. It includes Cloud Control's reads (`cloudformation:ListResources`, `cloudformation:GetResource`), `sts:GetCallerIdentity`, `ec2:DescribeAvailabilityZones` (for a restore or diff in another region) and every service's `Describe*`/`Get*`/`List*`. | Expected. Captures have run as a user holding `ReadOnlyAccess` and `PowerUserAccess` together; `ReadOnlyAccess` alone has not been isolated. |
| Restore | `cloudformation:CreateResource`, `cloudformation:UpdateResource`, `cloudformation:GetResourceRequestStatus`, plus each service's create and update actions. `PowerUserAccess` covers every service except IAM. | Verified with `PowerUserAccess` for the 14 types the drill restores. |
| Restore IAM types | Add IAM write (`iam:CreateRole`, `iam:PutRolePolicy`, `iam:AttachRolePolicy`, …) and `iam:PassRole` for anything that takes a role. | Not verified: the sandbox has no IAM write. |

`ViewOnlyAccess` is not enough: it omits many of the `Get*` reads Cloud
Control's handlers make, and those types are reported as failed in
`coverage.yaml`.

## Azure

| Use | Grant | Status |
|---|---|---|
| Capture, diff | The built-in **Reader** role at the subscription. It reads every resource, and the extension resources StackDNA captures: role assignments and custom role definitions, locks, policy assignments, diagnostic settings. | **Verified** (2026-10-23): a service principal holding only Reader captured the sandbox subscription to the same digest as its owner. The principal was deleted afterwards. |
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
| Capture, diff | `get`, `list` on every resource type to capture, cluster-wide. The built-in `view` ClusterRole leaves out Secrets: their values are never captured anyway, but without `list` on them their existence is not either. | Expected. |
| Restore | Create and patch (server-side apply) on every type restored. | Verified with cluster-admin on kind clusters. |

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

## What StackDNA does with access it is given

- **Capture and diff never write.** Every client sits behind the read-only
  guard (`internal/readonly`), which refuses any request that is not a
  read before it leaves the machine. The capture-only binary also has no
  restore command.
- **No secret value is written to a snapshot.** Values the platforms mask
  or never return (passwords, keys, a webhook's secret) are named in the
  snapshot and supplied at restore with `--values`, which is read and sent
  to the platform, never written.
- **A refused read is a failure, not an empty result.** A missing
  permission shows in `coverage.yaml` and REPORT.md and makes the capture
  exit 3 (incomplete).
