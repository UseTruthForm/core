package awscc

import (
	"context"
	"strings"
	"testing"

	"github.com/stackdna/core/internal/snapshot"
)

// queueIn returns the target's shop-jobs queue.
func queueIn(t *testing.T, f *Fake) (string, map[string]any) {
	t.Helper()
	for _, id := range f.IDs("AWS::SQS::Queue") {
		if p := f.Stored("AWS::SQS::Queue", id); p["QueueName"] == "shop-jobs" {
			return id, p
		}
	}
	t.Fatal("shop-jobs not in the target")
	return "", nil
}

// A target whose queue has drifted (another visibility timeout, a
// retention period someone added) is left alone by default and brought in
// line with --update: changed properties replaced, the added one removed.
func TestUpdateBringsExistingInLine(t *testing.T) {
	e := newEnv(t)
	snap, err := e.adapter(e.src).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	mustCreate(t, e.dst, "AWS::SQS::Queue", map[string]any{"QueueName": "shop-jobs", "VisibilityTimeout": 30, "MessageRetentionPeriod": 600})

	for _, r := range e.adapter(e.dst).Restore(context.Background(), snap) {
		if strings.HasSuffix(r.Key, "AWS::SQS::Queue||shop-jobs") && (r.OK || !strings.Contains(r.Detail, "--update")) {
			t.Errorf("without --update: ok=%v %s", r.OK, r.Detail)
		}
	}
	if e.dst.Updates != 0 {
		t.Fatalf("%d updates sent without --update", e.dst.Updates)
	}

	a := e.adapter(e.dst)
	a.Options.Update = true
	for _, r := range a.Restore(context.Background(), snap) {
		if !r.OK {
			t.Errorf("%s: %s", r.Key, r.Detail)
		}
		if strings.HasSuffix(r.Key, "AWS::SQS::Queue||shop-jobs") && !strings.Contains(r.Detail, "updated") {
			t.Errorf("queue: %s", r.Detail)
		}
	}
	_, q := queueIn(t, e.dst)
	if canon(q["VisibilityTimeout"]) != "60" {
		t.Errorf("VisibilityTimeout %v, want 60", q["VisibilityTimeout"])
	}
	if _, ok := q["MessageRetentionPeriod"]; ok {
		t.Errorf("MessageRetentionPeriod someone added was not removed: %v", q)
	}
	got, err := a.Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range snapshot.Compare(snap, got) {
		t.Errorf("after --update the target still differs: %+v", c)
	}
}

// A change AWS can only make by replacing the resource (a VPC's CIDR
// block) is refused and named, and nothing is sent.
func TestUpdateRefusesReplacement(t *testing.T) {
	e := newEnv(t)
	snap, err := e.adapter(e.src).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	mustCreate(t, e.dst, "AWS::EC2::VPC", map[string]any{"CidrBlock": "10.9.0.0/16", "Tags": tags("Name", "main", "team", "shop")})
	a := e.adapter(e.dst)
	a.Options.Update = true
	seen := false
	for _, r := range a.Restore(context.Background(), snap) {
		if strings.HasSuffix(r.Key, "AWS::EC2::VPC||main") {
			seen = true
			if r.OK || !strings.Contains(r.Detail, "differs in CidrBlock") || !strings.Contains(r.Detail, "does not replace") {
				t.Errorf("vpc: ok=%v %s", r.OK, r.Detail)
			}
		}
	}
	if !seen {
		t.Fatal("no result for the VPC")
	}
	if e.dst.Updates != 0 {
		t.Errorf("%d updates sent; a create-only change must send none", e.dst.Updates)
	}
}

// The fake refuses what Cloud Control refuses in a patch, so a restore
// that sends a create-only or read-only change fails here as it would in
// AWS.
func TestFakeUpdateRefusals(t *testing.T) {
	reg := fixtures(t)
	f := NewWorld(reg).Account(srcAccount, region)
	vpc := mustCreate(t, f, "AWS::EC2::VPC", map[string]any{"CidrBlock": "10.0.0.0/16"})
	id := vpc["VpcId"].(string)
	for _, c := range []struct {
		op   PatchOp
		want string
	}{
		{PatchOp{Op: "replace", Path: "/CidrBlock", Value: "10.1.0.0/16"}, "NotUpdatable"},
		{PatchOp{Op: "replace", Path: "/DefaultSecurityGroup", Value: "sg-1"}, "read-only"},
		{PatchOp{Op: "add", Path: "/Bogus", Value: 1}, "extraneous"},
	} {
		if err := f.Update(context.Background(), "AWS::EC2::VPC", id, []PatchOp{c.op}); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: got %v, want %q", c.op, err, c.want)
		}
	}
	if err := f.Update(context.Background(), "AWS::EC2::VPC", id, []PatchOp{{Op: "replace", Path: "/EnableDnsHostnames", Value: true}}); err != nil {
		t.Errorf("an updatable property was refused: %v", err)
	}
}
