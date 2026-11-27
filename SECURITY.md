# Security

## Reporting a vulnerability

Please report it privately, through GitHub: on this repository's
**Security** tab, choose **Report a vulnerability**. Don't open a public
issue, pull request or discussion.

Say what an attacker could do and how: the command, the input, and the
release (`truthform version`). Leave out credentials and snapshots of real
environments.

A report needs a reproduction against a real build: what you ran, and what
it printed. One without, or about code that is not in TruthForm, is closed,
whatever tool wrote it; a scanner's or an AI's finding is welcome once you
have shown it happens.

We aim to reply within three working days, and to agree with you when the
fix and the advisory are published.

## What counts

TruthForm reads a live system with the caller's credentials and writes a
snapshot. A vulnerability is, for example:

- a capture that writes to what it reads;
- a secret value that reaches a snapshot, a log or the MCP server's replies;
- a restore that does more than its plan says;
- a snapshot that, when read, makes TruthForm run code or reach somewhere
  it should not;
- a release archive that is not what its checksum and provenance say.

## Supported versions

Fixes go into the next release. Until 1.0 only the latest release is
supported, so the fix for any version is to upgrade.

Every pull request and release is scanned for known vulnerabilities in Go
and in every module (`scripts/vulncheck.sh`), and one is refused.
