//go:build captureonly

package main

// captureOnly is set by `go build -tags captureonly`: a binary to hand a
// client for information gathering. Its restore command refuses to run, and
// every client it builds, restore's included, sits behind the read-only
// guard, so there is no path in it by which a write leaves the machine.
const captureOnly = true
