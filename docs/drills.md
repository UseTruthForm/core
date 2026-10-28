# Drill accounts (internal)

How StackDNA's own test accounts are set up for the real restore drills
(`scripts/drill-*.sh`). This is about testing StackDNA, not about a
customer's setup: for that, see [permissions.md](permissions.md) and
`stackdna permissions`.

Only free resources are created, and every drill deletes what it made and
checks the account against its baseline afterwards. Anything metered needs
the owner's go-ahead first.

## AWS

| Account | Used for | Identity |
|---|---|---|
| Main sandbox (the organisation's management account) | every AWS drill, IAM included (a role and a managed policy, since 2026-10-24) | IAM user `tf-pilot-automation`: `ReadOnlyAccess` and `PowerUserAccess`, plus the inline policies below |
| `stackdna-drill-b` (a member account, created 2026-10-23; its services were still not activated after 40 minutes: CloudFormation answers OptInRequired, S3 NotSignedUp) | cross-account restores; proving the `stackdna permissions` role | profile `stackdna-drill-b`, which assumes `OrganizationAccountAccessRole` from `tf-pilot-automation` |

`PowerUserAccess` covers every service except IAM and Organizations, so
IAM types need their own grant. Two inline policies on
`tf-pilot-automation` give it, each limited by name:

- `tf-pilot-iam-scoped` (not StackDNA's): roles and instance profiles named
  `tf-pilot-*`.
- `stackdna-drill-iam`: roles and policies named `stackdna-drill*`, plus
  IAM read. The policy is kept outside the repository in the handoff
  folder and is attached by the account owner, not by an agent.

Two traps from setting this up:

- **Root cannot assume a role.** A profile for the member account has to
  start from an IAM user or role (`tf-pilot-automation`), not from the
  root login.
- **`OrganizationAccountAccessRole` is full admin** in the member
  account. That is what the drills need, and the account holds nothing
  else.

Closing a member account starts a 90-day closure period, and only 10% of
an organisation's accounts can be closed in any 30 days (minimum one).
Keep it rather than create and close accounts per test.

## Azure and Google Cloud

The sandbox subscription and project are the ones in
[permissions.md](permissions.md)'s verification notes. Least-privilege
proofs used a temporary service principal or service account holding
exactly the role under test, deleted afterwards and checked to be gone.

## Signing in

`aws login --profile stackdna-admin` (AWS CLI 2.32 and later) keeps a short session
that refreshes itself through the sign-in service. The read-only guard
let that refresh through only from 2026-10-23 on: before, such a profile
worked until its first cached credentials expired, then every capture
failed with "refused by StackDNA's read-only guard".
