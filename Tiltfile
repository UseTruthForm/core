###############################################################################
# TruthForm dev loop
#
#   tilt up --port 10352
#
# Any free port works. 10352 keeps clear of a Tilt already running on the
# default 10350 (another repo's, say), so both run side by side.
#
# Only what works today is wired here. A resource for an adapter that does
# not exist yet would sit green and do nothing, which reads as coverage, so
# each emulator/mock profile is added in the same change as its adapter.
#
# Cost: everything here is local and free. The drill builds throwaway kind
# clusters (truthform-src, truthform-dst). The platform capture is read-only
# and is there only when you name a cluster for it:
#
#   tilt up --port 10352 -- --platform-context=kind-mycluster
#
# or put {"platform-context": "kind-mycluster"} in tilt_config.json
# (gitignored), which Tilt reads on every start.
###############################################################################

config.define_string("platform-context", args=False, usage="kube context of a cluster to capture read-only (capture-platform)")
cfg = config.parse()
PLATFORM_CONTEXT = cfg.get("platform-context", "")

EXE = ".exe" if os.name == "nt" else ""
BIN = "bin/truthform" + EXE
GO_SRC = ["cmd", "internal", "go.mod", "go.sum"]

# Rebuild on every save.
local_resource(
    "build",
    cmd=["go", "build", "-o", BIN, "./cmd/truthform"],
    deps=GO_SRC,
    labels=["core"],
)

# The etcd and kube-apiserver binaries for the API-server restore drill,
# fetched once into ~/.cache/truthform/envtest.
KUBE_ASSETS = str(local("bash scripts/envtest-assets.sh", quiet=True, echo_off=True)).strip()

# Unit tests on every save, including the restore drill on two real API
# servers (internal/kube/drill_test.go). TRUTHFORM_REQUIRE_KUBE_ASSETS makes a
# missing binary fail instead of quietly skipping the drill.
#
# Go's test cache stays on: a save re-runs only the packages it affects, and
# a package's tests re-run when a file they read changes. With -count=1 every
# save ran every package, about two and a half minutes even for a comment.
# For a full uncached run: go test -count=1 ./...
local_resource(
    "unit-tests",
    cmd=["go", "test", "./..."],
    deps=GO_SRC + ["testdata"],
    env={"TRUTHFORM_KUBE_ASSETS": KUBE_ASSETS, "TRUTHFORM_REQUIRE_KUBE_ASSETS": "1"},
    resource_deps=["build"],
    labels=["core"],
)

# The restore drill (scripts/drill-kind.sh): capture twice for determinism,
# exact capture set, restore into a fresh cluster, zero diff, secrets
# arrive. About two minutes, so it runs when you click it, not on save.
local_resource(
    "restore-drill",
    cmd=["bash", "scripts/drill-kind.sh"],
    env={"BIN": BIN},
    trigger_mode=TRIGGER_MODE_MANUAL,
    auto_init=False,
    resource_deps=["unit-tests"],
    labels=["drills"],
)

# Real-world check: capture a cluster you name read-only, keep the last
# capture, and schema-diff against it, so a platform or operator upgrade
# shows up as the API fields it added or removed. The snapshots are written
# under .truthform/ (gitignored): they describe your platform, and secret
# values are withheld but key names are not. Without --platform-context the
# resource is not shown, rather than shown failing for a cluster you lack.
if PLATFORM_CONTEXT:
    local_resource(
        "capture-platform",
        cmd=["bash", "scripts/capture-platform.sh"],
        env={"BIN": BIN, "CONTEXT": PLATFORM_CONTEXT},
        trigger_mode=TRIGGER_MODE_MANUAL,
        auto_init=False,
        resource_deps=["build"],
        labels=["real-world"],
    )

# What the AWS adapter can capture, measured from AWS's public registry
# bundle with the adapter's own rules. Offline apart from downloading that
# bundle; no account is touched. Run it to see when AWS adds types.
local_resource(
    "aws-coverage",
    cmd=[BIN, "aws-coverage"],
    trigger_mode=TRIGGER_MODE_MANUAL,
    auto_init=False,
    resource_deps=["build"],
    labels=["real-world"],
)
