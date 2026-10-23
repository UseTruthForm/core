package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stackdna/core/internal/snapshot"
)

func asJSON(t *testing.T, f func()) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	dst, on := jsonDst, jsonOut
	jsonDst, jsonOut = &buf, true
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
