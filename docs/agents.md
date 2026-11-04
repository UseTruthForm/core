# Setting up StackDNA access: a guide for agents

This is for an AI agent (or a person) helping someone give StackDNA access
to their AWS account, Azure subscription, Google Cloud project, Kubernetes
cluster, GitHub organisation or Cloudflare account. The MCP server
(`stackdna mcp`) points agents here.

It also covers planning a restore, at the end. The person runs the restore;
you prepare it.

The tools do the exact parts: `permissions` says what to grant and gives
every command, and `check_access` shows what a grant actually allows. This
page is the judgement around them. Every rule here comes from a mistake
that was made while setting up StackDNA's own test accounts.

## The rules

1. **You do not grant access. The person does.** No StackDNA tool creates
   a role, attaches a policy, creates an account or issues a token, and you
   should not do it either, with this server or any other. Giving an
   identity permissions is the person's decision. Their security tooling,
   and yours, will usually refuse it anyway: Claude Code's safety check
   blocked exactly this while StackDNA's own drill policy was being
   attached.

2. **Never hand over a command with a placeholder in it.** A pasted
   `--profile <admin-profile>` fails in PowerShell ("The '<' operator is
   reserved for future use") and can do worse elsewhere. `permissions`
   fills in every value or returns an error naming what is missing and how
   to find it. When it does, ask the person for that value; do not invent
   one or put in a stand-in.

3. **Look before granting.** Each plan starts with read-only commands:
   which account the administrator is signed in to, what the principal
   already holds, whether a StackDNA role is already there. Run them, or
   have the person run them, and read the output. On the first real setup
   the user already had an inline policy nobody had mentioned, and the
   account turned out to be the organisation's management account. Both
   changed what was safe to do next.

4. **Add a separately named grant; never edit theirs.** The templates
   create their own role, role assignment, IAM binding or ClusterRole,
   named `stackdna-reader` (capture) or `stackdna-restorer` (restore).
   Never widen a policy the customer already has, even when that looks
   simpler: theirs is theirs to change, and a separate grant can be removed
   on its own.

5. **Capture needs read-only access only.** Recommend the capture grant and
   the capture-only binary together. Offer the restore grant only for a
   restore, and say it should be removed afterwards.

6. **Prefer short-lived identities.** Root users, long-lived access keys,
   service account key files and tokens without an expiry all work, and
   `check_access` warns about each. Say so, and suggest the alternative it
   names (SSO, an assumed role, impersonation, a token with an end date).
   Do not refuse to continue over it: it is the person's call.

7. **Verify with `check_access`, not with the grant's exit code.** A
   CloudFormation stack that deployed or an `az stack` that succeeded says
   the platform accepted the template. It does not say a capture can now
   read everything. `check_access` runs a capture that is written nowhere
   and reports every type as read, empty, **denied** or **failed**, and
   lists as **unsure** the ones recorded as "not found" or "not set up"
   that a missing permission can also produce (GitHub answers 404 for
   both). Denied types are not empty; a missing permission must never be
   reported to the person as "nothing there", and an unsure one is not
   known to be fine. Exit 3 means some types cannot be read.

8. **Say what was changed and how to undo it.** Every plan ends with its
   undo steps. When you finish, tell the person what now exists (the stack,
   the role, the token) and the commands that remove it.

9. **Separate what you verified from what you assumed.** Each plan carries
   a status: verified (StackDNA ran with exactly this grant), partly
   verified or expected. Repeat it; do not upgrade it.

## The sequence

1. Ask which platform, and whether this is for capture or restore.
2. Call `permissions` with what you know. For each value it reports
   missing, ask the person, using the "find it with" hint it gives.
3. Show the person the plan's warnings first, then what is granted and its
   status.
4. Walk through *Before granting*. Stop and ask if anything there is a
   surprise.
5. Have the person write the template files (the plan's first step gives
   the exact `stackdna permissions ... --write` command) and read them.
6. Have the person run the *Grant* steps.
7. Run `check_access` as the new identity. Report its warnings, anything
   not checked, and every denied or failed type.
8. Give the person the *To remove it again* steps to keep.

## What `check_access` cannot see

It says so in its output, under NOT CHECKED. Pass those lines on as they
are. The common ones:

- **AWS:** resource policies (bucket and key policies) and organization
  policies are not part of the policy simulator's answer.
- **Google Cloud:** roles held through groups, folders or the organization.
- **Kubernetes:** the cluster's own view of the identity, because asking
  for it is a create request, which the read-only guard refuses. An
  administrator can ask with `kubectl auth can-i --list --as` and the
  identity's name.
- **GitHub (fine-grained tokens) and Cloudflare:** a token's own
  permissions are not shown to it. The trial capture shows what it can
  read.

## Platform notes

- **AWS.** The role is a CloudFormation stack, so deleting the stack
  removes it. When the person who runs StackDNA is in another account,
  agree an external ID; the plan warns if there is none. If the principal
  given is a role session (what `aws sts get-caller-identity` prints for a
  role), the plan trusts the role itself, and says to give the role's full
  ARN if it has a path.
- **Azure.** The role assignments are a *deployment stack*. Deleting a
  plain deployment leaves its role assignments behind; deleting the stack
  with `--action-on-unmanage deleteAll` removes them.
- **Google Cloud.** The grant is Terraform in its own directory
  (`stackdna-gcp` by default). That directory holds the state `destroy`
  needs: tell the person to keep it. The two APIs it enables stay enabled
  when the grant is removed, on purpose.
- **Kubernetes.** The capture role can read Secret values. StackDNA never
  writes them to a snapshot, but the identity can read them; say so.
- **GitHub.** Use a fine-grained token. A classic token cannot read an
  organisation's settings without `repo` and `admin:org`, which both
  write. Fine-grained tokens may need the organisation's approval.
- **Cloudflare.** Not yet run against a real account. Say so.

## Planning a restore

There is no restore tool. The person runs a restore from the CLI. Your part is the plan: what will happen, what it needs, and what the person must decide. Everything below is read-only.

### What to read

1. **The snapshot's report** (`report`). Read it all, and pass these sections on as they are:
   - *Check before relying on a restore*: what was skipped and may not come back.
   - *References to other subscriptions*: IDs a restore sends as they are, into someone else's subscription.
   - *Access a restore needs outside its target*: each action, and the resource it is needed on.
   - Anything the capture could not read. A gap in the snapshot is a gap in the restore.
2. **A diff into the target** (`diff`, with the same `--rename` and `--leave-out` the restore will use). A target that should be empty shows everything as missing. Anything extra already exists there, and is not the snapshot's to change. The `--json` document lists `left_out` and `access_elsewhere`.
3. **What already holds access in the target.** Look before suggesting any role assignment: the target's own administrators are usually there already, and a restored assignment of the same role to the same principal is refused.

### What the person decides

Put each of these to the person as a decision, with your suggestion and why. Don't settle any of them yourself.

- **Who restores, and with what.** Suggest a separate restore identity (`permissions` with `access: restore`), scoped to the target, and removed afterwards. Running as the person works, but the restore then has all of their rights.
- **Each grant outside the target.** Every line under *Access a restore needs outside its target* is a grant in another subscription. Each one is the person's to make, or the object goes in `--leave-out`. These come from Azure's documentation, not from a StackDNA restore: say so.
- **Each role assignment.** List the source's assignments by principal and role, and suggest one of:
  - *leave out*: the target already has it, or the principal would gain write access it should not have there (a deploy identity, a pipeline, the source's own capture identity);
  - *restore*;
  - *the person's call*: people and groups.
  Assignments that name a restored resource (a cluster's identities) follow it.
- **Names.** Global names (storage accounts, registries, DNS labels) must be new, through `--rename`. Check each new name is free before the restore, not during it.
- **Secrets.** `--values` supplies what capture withheld. You never see or print those values.

### What a restore cannot change

- **A plain value that names something.** An event hub name in a diagnostic setting, or a hostname in an app setting, is a value, not a reference. `--rename` doesn't touch it, so the restored copy still points where the source did. Find these in the plan, for example a log destination shared with the source. Say how they'll be repointed after the restore, and that until then the target's data goes where the source's does.
- **What something else manages.** A cluster's node resources, and what a driver made for a claim, come from the cluster, not the snapshot.

### After the restore

- Diff again. Expect no differences except what was left out, and report anything else as it is.
- Repoint the plain values from the plan, then diff once more.
- Give the person the teardown, as you would undo steps for access: the restored resources, the restore identity and its grants, including those outside the target.
