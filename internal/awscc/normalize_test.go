package awscc

import (
	"testing"
)

// AWS does not return write-only values, but normalize must not rely on
// it: a Get that did return Lambda code or an S3 lifecycle transition (a
// nested write-only pointer through an array) still yields a spec without
// them, and Code, emptied, disappears instead of surviving as {}.
func TestNormalizeDropsWriteOnlyEvenIfReturned(t *testing.T) {
	reg := fixtures(t)
	lambda := normalize(reg.Types["AWS::Lambda::Function"], "shop-api", map[string]any{
		"FunctionName": "shop-api", "Arn": "arn:aws:lambda:us-east-1:1:function:shop-api",
		"Code": map[string]any{"ZipFile": "secret code", "S3Bucket": "b"},
	})
	if _, ok := lambda.spec["Code"]; ok {
		t.Errorf("Code survived: %v", lambda.spec)
	}
	if _, ok := lambda.spec["Arn"]; ok || lambda.stat["Arn"] == nil {
		t.Errorf("Arn should move to status: spec %v status %v", lambda.spec, lambda.stat)
	}

	bucket := normalize(reg.Types["AWS::S3::Bucket"], "b", map[string]any{
		"BucketName": "b",
		"LifecycleConfiguration": map[string]any{"Rules": []any{
			map[string]any{"Id": "r1", "Status": "Enabled", "Transition": map[string]any{"StorageClass": "GLACIER"}},
			map[string]any{"Id": "r2", "Status": "Enabled", "ExpirationInDays": 30.0},
		}},
	})
	rules := bucket.spec["LifecycleConfiguration"].(map[string]any)["Rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("rules %v", rules)
	}
	for _, r := range rules {
		if _, ok := r.(map[string]any)["Transition"]; ok {
			t.Errorf("write-only Transition survived in %v", r)
		}
	}
	if rules[1].(map[string]any)["ExpirationInDays"] != 30.0 {
		t.Errorf("non-write-only value lost: %v", rules[1])
	}
}

func TestRefable(t *testing.T) {
	for _, c := range []struct {
		attr, v string
		want    bool
	}{
		{"VpcId", "vpc-0123456789abcdef0", true},
		{"Arn", "arn:aws:iam::1:role/x", true},
		{"QueueUrl", "https://sqs.us-east-1.amazonaws.com/1/q", true},
		{"identifier", "abcd1234", true},
		// Status words and short values must never become references.
		{"State", "available", false},
		{"DomainName", "b.s3.amazonaws.com", false},
		{"RoleId", "abc", false},
		{"MetadataConfiguration.Destination", "arn:aws:s3:::x", false},
	} {
		if got := refable(c.attr, c.v); got != c.want {
			t.Errorf("refable(%q, %q) = %v, want %v", c.attr, c.v, got, c.want)
		}
	}
}
