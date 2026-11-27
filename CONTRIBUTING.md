# Contributing to TruthForm

Thank you for helping. Issues and pull requests are welcome. Everyone taking
part follows the [Code of Conduct](CODE_OF_CONDUCT.md), and how decisions are
made is in [GOVERNANCE.md](GOVERNANCE.md).

## Before you start

- **For a bug,** open an issue with the command you ran, what it printed, and
  `truthform version`. Leave out anything from a real environment: names,
  IDs, keys and snapshots. A snapshot can hold what TruthForm could not
  withhold.
- **For a security problem,** don't open an issue. See [SECURITY.md](SECURITY.md).
- **For a larger change** (a new platform, a change to the snapshot format or
  to what a capture withholds), open an issue first so we can agree on the
  shape before you write it.

## Building and testing

TruthForm is one Go module. The Go version is in `go.mod`.

    go build ./cmd/truthform
    go vet ./...
    go test ./...

`go test ./...` runs every adapter's restore drill against its fake, with no
cloud account. The Kubernetes tests need etcd and kube-apiserver binaries:
`scripts/envtest-assets.sh` fetches them and prints their directory, which
goes in `TRUTHFORM_KUBE_ASSETS`. Without it those tests are skipped. CI
sets `TRUTHFORM_REQUIRE_KUBE_ASSETS=1`, so there a missing binary fails.
CI also runs:

    go test -tags captureonly ./cmd/truthform/   # the capture-only edition
    bash scripts/vulncheck.sh           # known vulnerabilities in the binary
    bash scripts/third-party.sh         # licences of every module

A dependency must be under a licence `scripts/third-party.sh` allows.

## What a change must keep

The [rules TruthForm keeps](README.md#rules-it-keeps) are what a pull
request is reviewed against. In short: capture and diff cannot write, a
secret value never reaches a snapshot, and nothing is left out without a
reason in `coverage.yaml`. A change that touches any of them needs a test
that would fail without it.

## Sign your commits off

TruthForm uses the [Developer Certificate of Origin](https://developercertificate.org/)
(DCO). Each commit carries a line that says you wrote it, or otherwise have
the right to submit it under the project's licence:

    Signed-off-by: Your Name <you@example.com>

`git commit -s` adds it. A pull request whose commits are not all signed off
cannot be merged.

## Licence

TruthForm is under the [Apache License 2.0](LICENSE). What you contribute is
under the same licence (section 5 of the licence), and you keep the
copyright in it.
