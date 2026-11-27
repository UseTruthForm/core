package main

import (
	"fmt"
	"regexp"
	"runtime"
	"runtime/debug"
	"time"
)

// Set by the release build: -ldflags "-X main.version=v0.1.0 -X
// main.commit=<sha> -X main.built=<UTC time>". A build without them
// takes what Go recorded in the binary instead (see versionFrom), so a
// binary handed to someone can always be traced to its source.
var (
	version = "dev"
	commit  = ""
	built   = ""
)

func versionInfo() (ver, rev, date string, dirty bool) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		bi = nil
	}
	return versionFrom(version, commit, built, bi)
}

// pseudo is the tail of a Go pseudo-version, such as
// v0.1.0-beta.26.0.20261128010203-3cb06a9a97bc: the commit's UTC time, then
// the first 12 characters of its hash.
var pseudo = regexp.MustCompile(`[.-](\d{14})-([0-9a-f]{12})$`)

// versionFrom names a build from what the release stamped (ver, rev, date)
// and what Go recorded in it (bi, nil when it recorded nothing):
//
//   - A release archive was stamped: that wins.
//   - "go build" in a clone: Go records the commit (vcs.revision). The
//     version stays "dev", so a local build never reads as a release.
//   - "go install ...@v0.1.0-beta.26": Go records the module's version,
//     and no commit. The version is the release's own name.
//   - "go install ...@main" or "@<commit>": a pseudo-version, which ends
//     in the commit's time and hash, so both are known.
func versionFrom(ver, rev, date string, bi *debug.BuildInfo) (string, string, string, bool) {
	dirty := false
	if bi != nil {
		vcs := false
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				vcs = true
				if rev == "" {
					rev = s.Value
				}
			case "vcs.time":
				if date == "" {
					date = s.Value
				}
			case "vcs.modified":
				dirty = s.Value == "true"
			}
		}
		if m := bi.Main.Version; ver == "dev" && !vcs && m != "" && m != "(devel)" {
			ver = m
			if p := pseudo.FindStringSubmatch(m); p != nil {
				if rev == "" {
					rev = p[2]
				}
				if t, err := time.Parse("20060102150405", p[1]); err == nil && date == "" {
					date = t.UTC().Format(time.RFC3339)
				}
			}
		}
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	return ver, rev, date, dirty
}

// generator names the build that wrote a file, so a consumer holding only
// the file can say which one made it.
func generator() string {
	ver, rev, _, dirty := versionInfo()
	return generatorOf(ver, rev, dirty)
}

// generatorOf takes only what it may print. The edition, OS and build time
// would make one release's binaries write different bytes from one snapshot.
func generatorOf(ver, rev string, dirty bool) string {
	if rev == "" {
		rev = "unknown commit"
	}
	if dirty {
		rev += ", with uncommitted changes"
	}
	return fmt.Sprintf("truthform %s (%s)", ver, rev)
}

// versionString is one line for people and bug reports: which build, which
// source, which edition (a capture-only binary must say so).
func versionString() string {
	ver, rev, date, dirty := versionInfo()
	edition := "full"
	if captureOnly {
		edition = "capture-only (restore disabled; every request read-only)"
	}
	src := rev
	if src == "" {
		src = "unknown commit"
	}
	if dirty {
		src += ", with uncommitted changes"
	}
	if date != "" {
		src += ", " + date
	}
	return fmt.Sprintf("truthform %s (%s) %s %s/%s, %s", ver, src, runtime.Version(), runtime.GOOS, runtime.GOARCH, edition)
}
