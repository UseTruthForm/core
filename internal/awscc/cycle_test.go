package awscc

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

// iamRefs makes the fake refuse what IAM refuses: a role holding a managed
// policy that does not exist, and a policy attached to a role that does not
// exist ("NotFound Policy ...", the first real IAM drill, 2026-10-24).
func iamRefs(f *Fake) func(string, map[string]any) error {
	return func(typ string, props map[string]any) error {
		has := func(t, field, want string) bool {
			for _, p := range f.res[t] {
				if p[field] == want {
					return true
				}
			}
			return false
		}
		list := func(v any) []string {
			var out []string
			for _, x := range asSlice(v) {
				if s, ok := x.(string); ok {
					out = append(out, s)
				}
			}
			return out
		}
		switch typ {
		case "AWS::IAM::Role":
			for _, a := range list(props["ManagedPolicyArns"]) {
				if strings.Contains(a, ":aws:policy/") {
					continue // AWS-managed, always there
				}
				if !has("AWS::IAM::ManagedPolicy", "PolicyArn", a) {
					return fmt.Errorf("NotFound Policy %s does not exist or is not attachable", a)
				}
			}
		case "AWS::IAM::ManagedPolicy":
			for _, r := range list(props["Roles"]) {
				if !has("AWS::IAM::Role", "RoleName", r) {
					return fmt.Errorf("NoSuchEntity The role with name %s cannot be found", r)
				}
			}
		}
		return nil
	}
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

// A role and the managed policy attached to it name each other. Captured,
// the references must be tokens both ways (left literal, restore could not
// see them); restored into an empty account, one side is created without
// the reference and given it once the other exists, and the account then
// matches the snapshot.
func TestIAMRoleAndPolicyCycleRestores(t *testing.T) {
	reg := fixtures(t)
	w := NewWorld(reg)
	src := newAccount(w, srcAccount)
	src.Validate = iamRefs(src)
	doc := map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Action": "sqs:ReceiveMessage", "Resource": "*"}}}
	trust := map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Principal": map[string]any{"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}}}
	mustCreate(t, src, "AWS::IAM::Role", map[string]any{"RoleName": "shop-app", "AssumeRolePolicyDocument": trust})
	pol := mustCreate(t, src, "AWS::IAM::ManagedPolicy", map[string]any{"ManagedPolicyName": "shop-read", "PolicyDocument": doc, "Roles": []any{"shop-app"}})
	if err := src.Update(context.Background(), "AWS::IAM::Role", "shop-app", []PatchOp{{Op: "add", Path: "/ManagedPolicyArns", Value: []any{pol["PolicyArn"]}}}); err != nil {
		t.Fatal(err)
	}

	snap, err := Capture(context.Background(), src, reg, region, Policy{Types: []string{"AWS::IAM::Role", "AWS::IAM::ManagedPolicy"}}, Tuning{})
	if err != nil {
		t.Fatal(err)
	}
	var roleSpec map[string]any
	for _, o := range snap.Objects {
		if o.Kind() == "AWS::IAM::Role" {
			roleSpec, _ = o.Body["spec"].(map[string]any)
		}
	}
	if arns := fmt.Sprint(roleSpec["ManagedPolicyArns"]); !strings.Contains(arns, "{{truthform|AWS::IAM::ManagedPolicy|") {
		t.Fatalf("the role's policy ARN was left literal, so restore cannot order by it: %s", arns)
	}

	dst := newAccount(w, dstAccount)
	dst.Validate = iamRefs(dst)
	results := Restore(context.Background(), dst, reg, snap, RestoreOptions{}, Tuning{})
	deferred := 0
	for _, r := range results {
		if !r.OK {
			t.Errorf("%s: %s", r.Key, r.Detail)
		}
		if strings.Contains(r.Detail, "a reference cycle") {
			deferred++
		}
	}
	if deferred != 1 {
		t.Errorf("want exactly one member of the cycle deferred, got %d: %+v", deferred, results)
	}
	after, err := Capture(context.Background(), dst, reg, region, Policy{Types: []string{"AWS::IAM::Role", "AWS::IAM::ManagedPolicy"}}, Tuning{})
	if err != nil {
		t.Fatal(err)
	}
	if ch := snapshot.Compare(snap, after); len(ch) != 0 {
		t.Errorf("restored account differs from the snapshot: %+v", ch)
	}

	// Restored again into the same account, nothing differs: the member
	// that was deferred is compared whole, not stripped (the real drill's
	// second restore reported the policy as differing in Roles).
	for _, r := range Restore(context.Background(), dst, reg, snap, RestoreOptions{}, Tuning{}) {
		if !r.OK || !strings.Contains(r.Detail, "identical") {
			t.Errorf("second restore %s: ok=%v %s", r.Key, r.OK, r.Detail)
		}
	}
}

// A cycle whose referencing properties are required cannot be broken; it
// is reported, and neither member is sent.
func TestUnbreakableCycleIsReported(t *testing.T) {
	reg := fixtures(t)
	a := snapshot.Object{Body: map[string]any{"apiVersion": APIVersion, "kind": "AWS::IAM::Role", "metadata": map[string]any{"name": "app"},
		"spec": map[string]any{"RoleName": "shop-app", "AssumeRolePolicyDocument": "{{truthform|AWS::IAM::ManagedPolicy|read|PolicyArn}}"}}}
	b := snapshot.Object{Body: map[string]any{"apiVersion": APIVersion, "kind": "AWS::IAM::ManagedPolicy", "metadata": map[string]any{"name": "read"},
		"spec": map[string]any{"PolicyDocument": "{{truthform|AWS::IAM::Role|app|Arn}}"}}}
	_, defs, unbroken := breakCycles(reg, nil, []snapshot.Object{a, b})
	if len(unbroken) != 2 {
		t.Errorf("required properties deferred: defs=%+v unbroken=%d", defs, len(unbroken))
	}
}

// A breakable cycle beside an unbreakable one: the unbreakable pair is
// reported, and the breakable pair is still restored. The first version
// dropped the breakable pair without a result as soon as any cycle stayed
// unbroken, so a restore reported nothing about two objects it never sent
// (review of #26).
func TestBreakableCycleRestoresBesideAnUnbreakableOne(t *testing.T) {
	reg := fixtures(t)
	w := NewWorld(reg)
	src := newAccount(w, srcAccount)
	doc := map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Action": "sqs:ReceiveMessage", "Resource": "*"}}}
	trust := map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Principal": map[string]any{"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}}}
	mustCreate(t, src, "AWS::IAM::Role", map[string]any{"RoleName": "shop-app", "AssumeRolePolicyDocument": trust})
	pol := mustCreate(t, src, "AWS::IAM::ManagedPolicy", map[string]any{"ManagedPolicyName": "shop-read", "PolicyDocument": doc, "Roles": []any{"shop-app"}})
	if err := src.Update(context.Background(), "AWS::IAM::Role", "shop-app", []PatchOp{{Op: "add", Path: "/ManagedPolicyArns", Value: []any{pol["PolicyArn"]}}}); err != nil {
		t.Fatal(err)
	}
	snap, err := Capture(context.Background(), src, reg, region, Policy{Types: []string{"AWS::IAM::Role", "AWS::IAM::ManagedPolicy"}}, Tuning{})
	if err != nil {
		t.Fatal(err)
	}
	breakable := map[string]bool{}
	for _, o := range snap.Objects {
		breakable[o.Key()] = true
	}
	if len(breakable) != 2 {
		t.Fatalf("captured %d objects, want the role and the policy", len(breakable))
	}
	// Required properties naming each other: no creation order exists.
	snap.Objects = append(snap.Objects,
		snapshot.Object{Body: map[string]any{"apiVersion": APIVersion, "kind": "AWS::IAM::Role", "metadata": map[string]any{"name": "stuck"},
			"spec": map[string]any{"RoleName": "stuck", "AssumeRolePolicyDocument": "{{truthform|AWS::IAM::ManagedPolicy|stuck|PolicyArn}}"}}},
		snapshot.Object{Body: map[string]any{"apiVersion": APIVersion, "kind": "AWS::IAM::ManagedPolicy", "metadata": map[string]any{"name": "stuck"},
			"spec": map[string]any{"PolicyDocument": "{{truthform|AWS::IAM::Role|stuck|Arn}}"}}})

	dst := newAccount(w, dstAccount)
	dst.Validate = iamRefs(dst)
	got := map[string]snapshot.Result{}
	for _, r := range Restore(context.Background(), dst, reg, snap, RestoreOptions{}, Tuning{}) {
		got[r.Key] = r
	}
	for _, o := range snap.Objects {
		r, ok := got[o.Key()]
		switch {
		case !ok:
			t.Errorf("%s: no result at all", o.Key())
		case breakable[o.Key()] && !r.OK:
			t.Errorf("%s (breakable cycle): %s", o.Key(), r.Detail)
		case !breakable[o.Key()] && (r.OK || !strings.Contains(r.Detail, "cannot be broken")):
			t.Errorf("%s (unbreakable cycle): ok=%v %s", o.Key(), r.OK, r.Detail)
		}
	}
}

// When the target cannot be read again to set a deferred property, the
// result says so, with the error, not "not found again" (review of #26).
func TestDeferredRereadFailureIsNamed(t *testing.T) {
	reg := fixtures(t)
	w := NewWorld(reg)
	src := newAccount(w, srcAccount)
	doc := map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Action": "sqs:ReceiveMessage", "Resource": "*"}}}
	trust := map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Principal": map[string]any{"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}}}
	mustCreate(t, src, "AWS::IAM::Role", map[string]any{"RoleName": "shop-app", "AssumeRolePolicyDocument": trust})
	pol := mustCreate(t, src, "AWS::IAM::ManagedPolicy", map[string]any{"ManagedPolicyName": "shop-read", "PolicyDocument": doc, "Roles": []any{"shop-app"}})
	if err := src.Update(context.Background(), "AWS::IAM::Role", "shop-app", []PatchOp{{Op: "add", Path: "/ManagedPolicyArns", Value: []any{pol["PolicyArn"]}}}); err != nil {
		t.Fatal(err)
	}
	snap, err := Capture(context.Background(), src, reg, region, Policy{Types: []string{"AWS::IAM::Role", "AWS::IAM::ManagedPolicy"}}, Tuning{})
	if err != nil {
		t.Fatal(err)
	}
	dst := newAccount(w, dstAccount)
	dst.Validate = iamRefs(dst)
	created := 0
	dst.AfterCreate = func(string, map[string]any) { created++ }
	dst.ListError = func(string, map[string]any) error {
		if created >= 2 {
			return fmt.Errorf("AccessDeniedException: not authorized to list")
		}
		return nil
	}
	named := false
	for _, r := range Restore(context.Background(), dst, reg, snap, RestoreOptions{}, Tuning{}) {
		if strings.Contains(r.Detail, "a reference cycle") {
			t.Errorf("%s reported set although the target could not be read: %s", r.Key, r.Detail)
		}
		if strings.Contains(r.Detail, "could not be read again") && strings.Contains(r.Detail, "not authorized to list") {
			named = true
		}
	}
	if !named {
		t.Error("no result names the failed reread and its error")
	}
}
