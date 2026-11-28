package main

import (
	"runtime/debug"
	"strings"
	"testing"
)

// One release's binaries must write the same graph, so the generator names
// the version and commit and nothing that differs between them, the build
// time included.
func TestGeneratorIsVersionAndCommitOnly(t *testing.T) {
	v, c, b := version, commit, built
	defer func() { version, commit, built = v, c, b }()
	version, commit, built = "v9.9.9", "abc123", "2026-01-01T00:00:00Z"
	_, _, _, dirty := versionInfo()
	if got, want := generator(), generatorOf("v9.9.9", "abc123", dirty); got != want {
		t.Errorf("generator() = %q, want %q", got, want)
	}
	for _, c := range []struct {
		ver, rev string
		dirty    bool
		want     string
	}{
		{"v9.9.9", "abc123", false, "truthform v9.9.9 (abc123)"},
		{"v9.9.9", "abc123", true, "truthform v9.9.9 (abc123, with uncommitted changes)"},
		{"dev", "", false, "truthform dev (unknown commit)"},
	} {
		if got := generatorOf(c.ver, c.rev, c.dirty); got != c.want {
			t.Errorf("generatorOf(%q, %q, %v) = %q, want %q", c.ver, c.rev, c.dirty, got, c.want)
		}
	}
}

// The version line names the edition: a capture-only binary must say it
// cannot restore, so whoever holds it knows what it can do. CI runs this in
// both editions.
func TestVersionNamesEdition(t *testing.T) {
	v := versionString()
	want := "full"
	if captureOnly {
		want = "capture-only"
	}
	if !strings.Contains(v, want) || !strings.HasPrefix(v, "truthform ") {
		t.Errorf("version %q does not name the %s edition", v, want)
	}
}

// Every way a binary is made names its source: a release archive by its
// stamp, a clone's build by its commit, and a go install by the module
// version Go recorded, which is all such a build has.
func TestVersionFromEveryKindOfBuild(t *testing.T) {
	vcs := func(m string) *debug.BuildInfo {
		return &debug.BuildInfo{Main: debug.Module{Version: m}, Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "3cb06a9a97bc5d1e2f30415263748596a7b8c9d0"},
			{Key: "vcs.time", Value: "2026-11-27T23:27:06Z"},
			{Key: "vcs.modified", Value: "true"}}}
	}
	mod := func(m string) *debug.BuildInfo { return &debug.BuildInfo{Main: debug.Module{Version: m}} }
	for _, c := range []struct {
		name                       string
		ver, rev, date             string
		bi                         *debug.BuildInfo
		wantVer, wantRev, wantDate string
		wantDirty                  bool
	}{
		{"release archive", "v0.1.0-beta.26", "3cb06a9a97bc", "2026-11-27T23:35:22Z", mod("(devel)"), "v0.1.0-beta.26", "3cb06a9a97bc", "2026-11-27T23:35:22Z", false},
		{"go build in a clone", "dev", "", "", vcs("v0.1.0-beta.26.0.20261127232706-3cb06a9a97bc+dirty"), "dev", "3cb06a9a97bc", "2026-11-27T23:27:06Z", true},
		{"go install of a tag", "dev", "", "", mod("v0.1.0-beta.26"), "v0.1.0-beta.26", "", "", false},
		{"go install of a commit", "dev", "", "", mod("v0.1.0-beta.26.0.20261128010203-0123456789ab"), "v0.1.0-beta.26.0.20261128010203-0123456789ab", "0123456789ab", "2026-11-28T01:02:03Z", false},
		{"go install before any tag", "dev", "", "", mod("v0.0.0-20261128010203-0123456789ab"), "v0.0.0-20261128010203-0123456789ab", "0123456789ab", "2026-11-28T01:02:03Z", false},
		{"go run, nothing recorded", "dev", "", "", mod("(devel)"), "dev", "", "", false},
		{"no build info", "dev", "", "", nil, "dev", "", "", false},
	} {
		ver, rev, date, dirty := versionFrom(c.ver, c.rev, c.date, c.bi)
		if ver != c.wantVer || rev != c.wantRev || date != c.wantDate || dirty != c.wantDirty {
			t.Errorf("%s: got %q %q %q %v, want %q %q %q %v", c.name, ver, rev, date, dirty, c.wantVer, c.wantRev, c.wantDate, c.wantDirty)
		}
	}
}
