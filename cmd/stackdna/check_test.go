package main

import (
	"strings"
	"testing"

	"github.com/stackdna/core/internal/snapshot"
)

// A refused type and a type read empty both capture nothing; check must
// never show the first as the second. And a 403 the capture already
// explained as a plan limit is not a permission to grant: on the first
// real run, GitHub's "Upgrade to GitHub Pro" for rulesets was counted as
// denied (2026-10-23).
func TestCheckTellsDeniedFromEmptyAndFromPlanLimits(t *testing.T) {
	s := snapshot.Snapshot{
		Objects: []snapshot.Object{{Body: map[string]any{"kind": "Q"}}},
		Coverage: []snapshot.Coverage{
			{Resource: "AWS::SQS::Queue", Captured: 1},
			{Resource: "AWS::SNS::Topic"},
			{Resource: "AWS::IAM::Role", Captured: 1, Skipped: map[string]int{"service-linked role; AWS creates it when the service is used": 6}},
			{Resource: "AWS::KMS::Key", NotCaptured: "list failed: User: arn:aws:sts::1:assumed-role/r/s is not authorized to perform: kms:ListKeys"},
			{Resource: "Microsoft.Web/sites", NotCaptured: "list failed: HTTP 403: AuthorizationFailed"},
			{Resource: "AWS::Lambda::Function", NotCaptured: "list failed: HTTP 500: internal error"},
			{Resource: "github/ruleset", NotCaptured: "not available on this account's plan: GET /repos/o/r/rulesets: HTTP 403: Upgrade to GitHub Pro"},
			{Resource: "AWS::X::Y", NotCaptured: "not selected (--types)"},
		},
		Skips: []snapshot.Skip{
			{Resource: "AWS::S3::Bucket", Name: "b", Reason: "listed but could not be read: AccessDenied"},
			{Resource: "AWS::S3::Bucket", Name: "c", Reason: "listed but could not be read: timeout"},
		},
	}
	rc := classify(s)
	if len(rc.Denied) != 3 || !strings.Contains(strings.Join(rc.Denied, "\n"), "kms:ListKeys") || !strings.Contains(strings.Join(rc.Denied, "\n"), "AuthorizationFailed") || !strings.Contains(strings.Join(rc.Denied, "\n"), "AWS::S3::Bucket b") {
		t.Errorf("denied: %v", rc.Denied)
	}
	if len(rc.Failed) != 2 {
		t.Errorf("failed (not a denial): %v", rc.Failed)
	}
	if rc.Empty != 1 || rc.WithObjects != 2 || rc.Skipped != 6 {
		t.Errorf("read: %+v", rc)
	}
	if rc.ByDesign["not available on this account's plan"] != 1 || rc.ByDesign["not selected (--types)"] != 1 {
		t.Errorf("by design: %v", rc.ByDesign)
	}
}
