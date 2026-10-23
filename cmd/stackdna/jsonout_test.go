package main

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stackdna/core/internal/snapshot"
)

func asJSON(t *testing.T, f func()) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	dst, on := jsonDst, jsonOut
	jsonDst, jsonOut, emitted = &buf, true, false
	defer func() { jsonDst, jsonOut = dst, on }()
	f()
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("not one JSON document: %v\n%s", err, buf.String())
	}
	if m["schema"] != jsonSchema {
		t.Errorf("schema %v", m["schema"])
	}
	return m
}

// --json is accepted anywhere among the arguments and removed before the
// command parses its flags (which would refuse it).
func TestTakeJSONFlag(t *testing.T) {
	args, ok := takeJSONFlag([]string{"--platform", "aws", "--json", "--region", "us-east-1"})
	if !ok || !reflect.DeepEqual(args, []string{"--platform", "aws", "--region", "us-east-1"}) {
		t.Errorf("got %v %v", args, ok)
	}
	if _, ok := takeJSONFlag([]string{"--region", "json"}); ok {
		t.Error("a value is not the flag")
	}
}

// The document carries what a pipeline acts on, and the exit code is the
// one a person would get.
func TestDiffAndRestoreDocuments(t *testing.T) {
	var code int
	d := asJSON(t, func() {
		code = report([]snapshot.Change{{Key: "k1", Kind: "changed", Fields: []string{"spec.a"}}, {Key: "k2", Kind: "missing"}}, "snap", "aws us-east-1")
	})
	if code != 2 || d["differences"] != float64(2) || len(d["changes"].([]any)) != 2 {
		t.Errorf("diff: exit %d, %v", code, d)
	}
	r := asJSON(t, func() {
		emitRestore([]snapshot.Result{{Key: "a", OK: true, Detail: "created x"}, {Key: "b", Detail: "refused"}}, "aws us-east-1")
	})
	if r["applied"] != float64(1) || r["total"] != float64(2) || r["complete"] != false {
		t.Errorf("restore: %v", r)
	}
}

// A capture's document says whether it is complete and names its gaps,
// read from the snapshot as written.
func TestCaptureDocument(t *testing.T) {
	dir := t.TempDir()
	s := snapshot.Snapshot{Platform: "aws", Policy: "default", Coverage: []snapshot.Coverage{
		{Resource: "AWS::S3::Bucket", Kind: "AWS::S3::Bucket", Captured: 1},
		{Resource: "AWS::IAM::Role", Kind: "AWS::IAM::Role", NotCaptured: "list failed: AccessDenied"}}}
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	c := asJSON(t, func() { emitCapture(dir, s, "aws us-east-1") })
	if c["complete"] != false || len(c["gaps"].([]any)) != 1 || c["digest"] == "" {
		t.Errorf("capture: %v", c)
	}
}

// A run that fails still ends with one document naming the failure and
// the exit code: before, an error left stdout empty and "| jq" read it as
// all clear (review of #21).
func TestFailedRunHasADocument(t *testing.T) {
	d := asJSON(t, func() {
		lastErr = nil
		code := compare([]string{"no-such-a", "no-such-b"})
		if !emitted {
			emitError(code)
		}
	})
	if d["exit"] != float64(1) || d["error"] == nil {
		t.Errorf("failed compare: %v", d)
	}
}

// A bad flag is exit 1 (an error), not 2, which means differences found.
func TestBadFlagIsAnError(t *testing.T) {
	for name, run := range map[string]func([]string) int{
		"diff":    func(a []string) int { return diff(context.Background(), a) },
		"capture": func(a []string) int { return capture(context.Background(), a) },
		"restore": func(a []string) int { return restore(context.Background(), a) },
	} {
		if code := run([]string{"--no-such-flag"}); code != 1 {
			t.Errorf("%s with a bad flag exited %d, want 1", name, code)
		}
	}
}

// Only commands with a document of their own take --json; the others
// refuse instead of running quietly ("mcp --json" served on stderr).
func TestJSONCommands(t *testing.T) {
	for c, want := range map[string]bool{"capture": true, "diff": true, "restore": true, "compare": true, "mcp": false, "version": false, "report": false} {
		if jsonCommands[c] != want {
			t.Errorf("%s: %v", c, jsonCommands[c])
		}
	}
}
