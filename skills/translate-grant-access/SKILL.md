---
name: translate-grant-access
description: Turn the role assignments a TruthForm cross-cloud translation refused (people, groups, pipelines, Owner and Contributor, custom roles) into proposed least-privilege grants on AWS or GCP for a person to approve. Use when translation.yaml has refused Microsoft.Authorization entries, or someone asks who needs access on the new cloud.
---

# Propose access for what the translation refused

`truthform translate` carries one kind of access: a workload's managed
identity and its built-in data roles. It refuses the rest on purpose,
because a wrong guess there gives someone more than they had. This skill
is for the agent helping a person decide those grants.

## The rules

1. **You do not grant access. The person does.** You propose; they run
   the grant or approve it in their own change process. This holds with
   any tool you have, not only TruthForm's.
2. **Never more than the source gave.** If the nearest role on the target
   allows something the Azure role did not, say what, and propose the
   narrower one or a custom one. In doubt, propose less and name what is
   missing.
3. **Control-plane roles are not copied.** Owner, Contributor and Reader
   managed Azure. Who manages the target is a new decision; ask it as one,
   and do not map Owner to an administrator role because the names match.
4. **A separate, named grant each time.** Never widen a role or policy
   that is already on the target.
5. **People come from the directory.** Propose grants to groups in the
   customer's identity provider (IAM Identity Center permission sets on
   AWS, Google groups on GCP), not to individuals, unless the person asks
   for that.

## Read the work list

In `translation.yaml`:

- every `entries` item whose `source` starts
  `Microsoft.Authorization/roleAssignments` and whose `state` is
  `refused`. Its `reason` says which case it is;
- every refused `Microsoft.Authorization/roleDefinitions` (a custom role);
- under `requirements`, the line starting
  `People, groups and pipelines are not translated`.

Sort the refused assignments by their reason:

| The reason says | What to do |
|---|---|
| assigned to a user or group; people and pipelines | find the group in the directory; propose the target grant for that group |
| an identity of a VM, an app service or a pipeline | ask what runs there now and where it will run; propose a role for that (an instance profile, a pipeline's federated identity), not a key |
| a custom role | read the role's actions from the Azure snapshot; list, per action, the target permission that does the same; propose a custom policy or role of exactly those |
| a condition | the condition is Azure's language. State what it limited (a path prefix, a tag) and propose the target's own form of it (an IAM policy condition, an IAM condition on GCP). If it cannot be said exactly, propose the stricter grant |
| a control-plane role | ask who should manage the target; do not derive it |
| gives nothing there on Azure | nothing to grant; list it as such |

## Propose

One table for the person, one row per grant: who (group or identity),
what they had on Azure (role, scope), what you propose on the target
(role or policy, resource), what the proposal allows that Azure did not
(must be "nothing", or named), and what Azure allowed that it leaves out.
Attach the exact policy document or binding for each row, with every
value filled in: no placeholders.

Then stop. The person approves row by row.

## Check

After the person has granted:

- **AWS:** `truthform capture` of the account, then find each role,
  policy and attachment in the snapshot and compare it with the approved
  row. The capture holds IAM as it is.
- **GCP:** TruthForm's capture does not read IAM policies yet. Check each
  binding with the platform's own read (`gcloud ... get-iam-policy`) and
  say that this check was not TruthForm's.
- Where the platform has one, run its policy simulator for one allowed
  and one denied action per grant.

## What this cannot show

That the right person is in the group, and that a grant is what the
business wants. TruthForm can show a grant exists and what it allows. The
person owns whether it should.
