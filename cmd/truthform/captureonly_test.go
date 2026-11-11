//go:build captureonly

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The capture-only build refuses restore. Run with: go test -tags captureonly ./cmd/truthform/
func TestCaptureOnlyRefusesRestore(t *testing.T) {
	if !captureOnly {
		t.Fatal("captureonly tag set but captureOnly is false")
	}
	if os.Getenv("TRUTHFORM_CHILD") == "1" {
		os.Args = []string{"truthform", "restore", "--from", "x", "--context", "y"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestCaptureOnlyRefusesRestore")
	cmd.Env = append(os.Environ(), "TRUTHFORM_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "capture-only build") {
		t.Fatalf("restore was not refused: err=%v\n%s", err, out)
	}
}
