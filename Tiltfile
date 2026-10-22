###############################################################################
# StackDNA dev loop
#
#   tilt up --port 10352
#
# Port 10352 because a platform Tilt (kind-tiltdev) owns
# 10350; both run side by side.
#
# Only what works today is wired here. A resource for an adapter that does
# not exist yet would sit green and do nothing, which reads as coverage, so
# each emulator/mock profile is added in the same change as its adapter.
#
# Cost: everything here is local and free. The drill builds throwaway kind
# clusters (stackdna-src, stackdna-dst); the platform capture is read-only
# against your existing kind-tiltdev cluster and changes nothing on it.
###############################################################################

EXE = ".exe" if os.name == "nt" else ""
BIN = "bin/stackdna" + EXE
GO_SRC = ["cmd", "internal", "go.mod", "go.sum"]

# Rebuild on every save.
local_resource(
    "build",
    cmd=["go", "build", "-o", BIN, "./cmd/stackdna"],
    deps=GO_SRC,
    labels=["core"],
)

# The etcd and kube-apiserver binaries for the API-server restore drill,
# fetched once into ~/.cache/stackdna/envtest.
KUBE_ASSETS = str(local("bash scripts/envtest-assets.sh", quiet=True, echo_off=True)).strip()

# Unit tests on every save, including the restore drill on two real API
# servers (internal/kube/drill_test.go). STACKDNA_REQUIRE_KUBE_ASSETS makes a
# missing binary fail instead of quietly skipping the drill.
local_resource(
    "unit-tests",
    cmd=["go", "test", "-count=1", "./..."],
    deps=GO_SRC + ["testdata"],
    env={"STACKDNA_KUBE_ASSETS": KUBE_ASSETS, "STACKDNA_REQUIRE_KUBE_ASSETS": "1"},
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

# Real-world check: capture the platform cluster read-only, keep the last
# capture, and schema-diff against it, so a platform or operator upgrade
# shows up as the API fields it added or removed. The snapshots are written
# under .stackdna/ (gitignored): they describe your platform, and secret
# values are withheld but key names are not.
local_resource(
    "capture-platform",
    cmd=["bash", "scripts/capture-platform.sh"],
    env={"BIN": BIN, "CONTEXT": "kind-tiltdev"},
    trigger_mode=TRIGGER_MODE_MANUAL,
    auto_init=False,
    resource_deps=["build"],
    labels=["real-world"],
)
