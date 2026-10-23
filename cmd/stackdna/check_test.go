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
			{Resource: "github/org/hooks", NotCaptured: "list failed: GET /orgs/o/hooks: HTTP 403: nope"},
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
	denied := strings.Join(rc.Denied, "\n")
	for _, want := range []string{"kms:ListKeys", "AuthorizationFailed", "AWS::S3::Bucket b", "github/org/hooks"} {
		if !strings.Contains(denied, want) {
			t.Errorf("denied lacks %s: %v", want, rc.Denied)
		}
	}
	if len(rc.Denied) != 4 || len(rc.Failed) != 2 {
		t.Errorf("denied %v, failed %v", rc.Denied, rc.Failed)
	}
	if rc.Empty != 1 || rc.WithObjects != 2 || rc.Skipped != 6 {
		t.Errorf("read: %+v", rc)
	}
	if rc.ByDesign["not available on this account's plan"] != 1 || rc.ByDesign["not selected (--types)"] != 1 {
		t.Errorf("by design: %v", rc.ByDesign)
	}
}

// gcp and azarm record a skip twice: in the type's coverage under the
// reason's first words, and in full in the skip list. Adding the two
// counted a Google-owned skip twice and denied reads as skipped on
// purpose, and a type whose every item was refused counted as read
// (review of #23).
func TestCheckCountsEachSkipOnceAndRefusedItemsAsRefused(t *testing.T) {
	s := snapshot.Snapshot{
		Coverage: []snapshot.Coverage{
			{Resource: "iam.googleapis.com/ServiceAccount", Skipped: map[string]int{"Google-owned": 1}},
			{Resource: "storage.googleapis.com/Bucket", Skipped: map[string]int{"listed but could not be read": 2}},
		},
		Skips: []snapshot.Skip{
			{Resource: "iam.googleapis.com/ServiceAccount", Name: "x", Reason: "Google-owned: made by a Google service"},
			{Resource: "storage.googleapis.com/Bucket", Name: "a", Reason: "listed but could not be read: HTTP 403: PERMISSION_DENIED"},
			{Resource: "storage.googleapis.com/Bucket", Name: "b", Reason: "listed but could not be read: HTTP 403: PERMISSION_DENIED"},
		},
	}
	rc := classify(s)
	if rc.Skipped != 1 || rc.WithObjects != 1 || rc.Empty != 0 || len(rc.Denied) != 2 {
		t.Errorf("%+v", rc)
	}
}

// A 401 is a credential that expired or is wrong, and GitHub's rate limit
// is a 403: neither is a permission to grant (review of #23). A "not
// found" or "not set up" a missing permission can also produce is listed
// as unsure, not counted as fine.
func TestCheckDeniedIsOnlyPermission(t *testing.T) {
	for msg, want := range map[string]bool{
		"list failed: HTTP 403: Resource not accessible by integration": true,
		"list failed: HTTP 403: forbidden":                              true,
		"list failed: HTTP 401: Bad credentials":                        false,
		"list failed: HTTP 403: API rate limit exceeded for user":       false,
		"list failed: HTTP 4030 weird":                                  false,
	} {
		if got := isDenied(msg); got != want {
			t.Errorf("%q: denied=%v, want %v", msg, got, want)
		}
	}
	rc := classify(snapshot.Snapshot{Coverage: []snapshot.Coverage{
		{Resource: "github/org/teams", NotCaptured: "not found: GET /orgs/o/teams: not visible to this token"},
		{Resource: "AWS::Foo::Bar", NotCaptured: "not set up in this account: the role does not have access to the service"},
		{Resource: "AWS::Baz::Qux", NotCaptured: "not set up in this account: not subscribed"},
		// The word "permissions" in a URL is not a refusal: on the first
		// real run this plan limit was listed as unsure.
		{Resource: "github/repo/actions/permissions/x", NotCaptured: "not available on this account's plan: GET /repos/o/r/actions/permissions/x: HTTP 422"},
	}})
	if len(rc.Unsure) != 2 || rc.ByDesign["not set up in this account"] != 1 || rc.ByDesign["not available on this account's plan"] != 1 {
		t.Errorf("unsure %v, by design %v", rc.Unsure, rc.ByDesign)
	}
}

// "aws::s3::*" selected nothing and check said it could read every type it
// was asked to (review of #23).
func TestCheckRefusesTypesThatMatchNothing(t *testing.T) {
	s := snapshot.Snapshot{Coverage: []snapshot.Coverage{
		{Resource: "AWS::S3::Bucket", NotCaptured: "not selected (--types)"},
		{Resource: "AWS::SQS::Queue"},
	}}
	if err := typesMatched(s, []string{"aws::s3::*"}); err == nil {
		t.Error("a pattern that selected nothing was accepted")
	}
	if err := typesMatched(s, []string{"AWS::SQS::*"}); err != nil {
		t.Error(err)
	}
}
