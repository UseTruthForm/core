package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Set by the release build: -ldflags "-X main.version=v0.1.0 -X
// main.commit=<sha> -X main.built=<UTC time>". A plain go build leaves
// them empty and reads the commit from the build's own VCS stamp, so a
// binary handed to someone can always be traced to its source.
var (
	version = "dev"
	commit  = ""
	built   = ""
)

func versionInfo() (ver, rev, date string, dirty bool) {
	ver, rev, date = version, commit, built
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
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
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	return ver, rev, date, dirty
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
	return fmt.Sprintf("stackdna %s (%s) %s %s/%s, %s", ver, src, runtime.Version(), runtime.GOOS, runtime.GOARCH, edition)
}
