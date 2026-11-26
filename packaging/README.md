# TruthForm

TruthForm reads the live configuration of a cloud account, a Kubernetes
cluster or a SaaS organisation into a **snapshot**: plain YAML files you
can review, commit and diff. From a snapshot it can **diff** what is
running against what was captured, and **restore** what is missing, into
the same place or another account, subscription, project or region.

It is one binary with nothing to install. It runs in your environment,
with your credentials, and sends nothing anywhere else: it talks only to
the platforms you point it at, and to where they publish their API
schemas.

## Which edition this is

    truthform version

| Edition | Can | Use it for |
|---|---|---|
| full | capture, diff, restore | your own environments |
| capture-only | capture, diff | an assessment: it has no restore, and every request it makes goes through a read-only guard, so it cannot change anything it reaches |

## First steps

1. **Give it access.** `truthform permissions` prints exactly what to grant
   on a platform, as a template for the platform's own tool, with every
   command to grant, verify and remove it. It grants nothing itself.
   Read-only access is enough for capture and diff.

        truthform permissions --platform aws --account 111122223333 --principal arn:aws:iam::111122223333:role/ops

   (Use your own account ID and the ARN of the user or role that will
   run TruthForm; `aws sts get-caller-identity` prints both.)

2. **Check what it can read.** `truthform check` names the identity it
   runs as, warns about access it does not need, and lists every type it
   can read, cannot read (denied), and why.

        truthform check --platform aws --region us-east-1 --profile truthform-reader

3. **Capture.**

        truthform capture --platform aws --region us-east-1 --profile truthform-reader --out snap/aws

   Read `snap/aws/REPORT.md` first: it says what was captured, what was
   not and why, and what a restore would need.

## Guides

The `docs` folder beside this file:

- `docs/guide.md`: every command, what a snapshot holds and does not,
  restore, whole environments, exit codes, JSON output, known limits.
- `docs/permissions.md`: what to grant on each platform, and which grants
  have been verified against real accounts.
- `docs/agents.md`: using TruthForm from an AI agent (`truthform mcp`), and
  how an agent should help someone set up access.

## Exit codes

`0` success, `1` error, `2` differences found (diff, compare), `3`
incomplete: something could not be read or applied, and the output says
what.

## Other people's software

TruthForm is built with Go and open-source modules. Their licences are in
`THIRD_PARTY_NOTICES.txt`, beside this file.

## Verifying this download

    sha256sum -c SHA256SUMS --ignore-missing
