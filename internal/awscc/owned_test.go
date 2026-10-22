package awscc

import (
	"context"
	"strings"
	"testing"
)

// Identifiers and ARNs from the full us-east-2 capture (2026-10-21).
func TestOwnedByAWS(t *testing.T) {
	const me = "999988887777"
	owned := []struct{ typ, id string }{
		// AWS's default patch baselines live in AWS's own account.
		{"AWS::SSM::PatchBaseline", "arn:aws:ssm:us-east-2:733109147000:patchbaseline/pb-00b74ab6b2168e3c7"},
		{"AWS::IAM::ManagedPolicy", "arn:aws:iam::aws:policy/AccountManagementFromVercel"},
		{"AWS::RAM::Permission", "arn:aws:ram::aws:permission/APIGatewayPrivateDomainNameManagementPolicyDefaultPermission"},
		{"AWS::SSM::Document", "AWS-RunShellScript"},
		{"AWS::SSM::Document", "AmazonCloudWatch-ManageAgent"},
		{"AWS::KMS::Alias", "alias/aws/dynamodb"},
		{"AWS::CodeDeploy::DeploymentConfig", "CodeDeployDefault.AllAtOnce"},
		{"AWS::ElastiCache::ParameterGroup", "default.valkey7"},
	}
	for _, c := range owned {
		if ownedByID(c.typ, c.id, me) == "" {
			t.Errorf("%s %s should be AWS-owned", c.typ, c.id)
		}
	}
	mine := []struct{ typ, id string }{
		{"AWS::IAM::ManagedPolicy", "arn:aws:iam::999988887777:policy/shop"},
		{"AWS::S3::Bucket", "arn:aws:s3:::shop-assets"}, // empty account AND region: a customer bucket
		{"AWS::SSM::Document", "shop-deploy"},
		{"AWS::KMS::Alias", "alias/shop"},
		{"AWS::ElastiCache::ParameterGroup", "shop.redis7"},
	}
	for _, c := range mine {
		if why := ownedByID(c.typ, c.id, me); why != "" {
			t.Errorf("%s %s is the customer's, got %q", c.typ, c.id, why)
		}
	}
	// After a read: the resource's own read-only ARN decides, never a
	// writable property that merely points at an AWS-managed policy.
	reg := fixtures(t)
	if ownedByProps(reg.Types["AWS::Lambda::Function"], map[string]any{"Arn": "arn:aws:lambda:us-east-2::function/aws-builtin"}, me) == "" {
		t.Error("own ARN with an empty account and a region should be AWS-owned")
	}
	if why := ownedByProps(reg.Types["AWS::IAM::Role"], map[string]any{"Arn": "arn:aws:iam::999988887777:role/shop", "PermissionsBoundaryArn": "arn:aws:iam::aws:policy/X"}, me); why != "" {
		t.Errorf("a reference to an AWS-managed ARN does not make the role AWS's: %q", why)
	}
}

// AWS-owned resources are skipped before they are read: the capture spent
// most of its 2,774 throttled reads on them. The alias is marked unreadable
// in the fake, so a read would show up as an unreadable skip instead.
func TestOwnedSkippedBeforeRead(t *testing.T) {
	str := map[string]any{"type": "string"}
	alias := &TypeInfo{Name: "AWS::KMS::Alias", PrimaryIdentifier: []string{"AliasName"},
		Handlers: map[string]bool{"list": true, "read": true, "create": true}, Properties: map[string]any{"AliasName": str}}
	reg := &Registry{Types: map[string]*TypeInfo{alias.Name: alias}}
	f := NewWorld(reg).Account(srcAccount, region)
	f.Seed(alias.Name, map[string]any{"AliasName": "alias/aws/s3"})
	f.Seed(alias.Name, map[string]any{"AliasName": "alias/shop"})
	f.Unreadable = map[string]bool{"AWS::KMS::Alias|alias/aws/s3": true}
	snap, err := Capture(context.Background(), f, reg, region, Policy{}, Tuning{})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Objects) != 1 || snap.Objects[0].Name() != "alias/shop" {
		t.Fatalf("objects: %+v", snap.Objects)
	}
	if len(snap.Skips) != 1 || !strings.HasPrefix(snap.Skips[0].Reason, OwnedByAWS) {
		t.Fatalf("skips: %+v", snap.Skips)
	}
}
