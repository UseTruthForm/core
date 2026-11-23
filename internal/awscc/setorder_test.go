package awscc

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

// A snapshot that sets a write-only property (who gets admin on an EKS
// cluster at creation), and holds a set of references (its SubnetIds), is
// found identical by a second restore: what AWS never returns is not
// compared, and a set is in order once its references are tokens, not by
// the IDs one account happened to generate.
func TestRestoreFindsWriteOnlyAndReferenceSetsIdentical(t *testing.T) {
	dir := t.TempDir()
	for src, name := range map[string]string{
		filepath.Join("..", "..", "testdata", "aws", "schemas", "aws-ec2-vpc.json"):    "vpc.json",
		filepath.Join("..", "..", "testdata", "aws", "schemas", "aws-ec2-subnet.json"): "subnet.json",
		filepath.Join("..", "translate", "testdata", "aws", "aws-eks-cluster.json"):    "eks.json",
	} {
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	reg, err := ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	tok := func(kind, name, attr string) string { return refToken(kind, name, attr) }
	var objs []snapshot.Object
	add := func(kind, name string, spec map[string]any) {
		o, err := reg.Object(kind, name, spec)
		if err != nil {
			t.Fatal(err)
		}
		objs = append(objs, o)
	}
	add("AWS::EC2::VPC", "net", map[string]any{"CidrBlock": "10.0.0.0/16", "Tags": []any{map[string]any{"Key": "Name", "Value": "net"}}})
	var ids []any
	for i, n := range []string{"a", "b", "c", "d", "e", "f"} {
		add("AWS::EC2::Subnet", "net-"+n, map[string]any{"VpcId": tok("AWS::EC2::VPC", "net", "VpcId"), "CidrBlock": fmt.Sprintf("10.0.%d.0/24", i),
			"Tags": []any{map[string]any{"Key": "Name", "Value": "net-" + n}}})
		ids = append(ids, tok("AWS::EC2::Subnet", "net-"+n, "SubnetId"))
	}
	add("AWS::EKS::Cluster", "shop", map[string]any{"Name": "shop", "RoleArn": "arn:aws:iam::" + tok("account", "self", "id") + ":role/eks",
		"ResourcesVpcConfig": map[string]any{"SubnetIds": ids},
		"AccessConfig":       map[string]any{"AuthenticationMode": "API", "BootstrapClusterCreatorAdminPermissions": false}})
	s := snapshot.Snapshot{Platform: "aws", Objects: objs}
	f := NewWorld(reg).Account("222222222222", "eu-west-1")
	for _, r := range Restore(context.Background(), f, reg, s, RestoreOptions{}, Tuning{}) {
		if !r.OK {
			t.Fatalf("%s: %s", r.Key, r.Detail)
		}
	}
	for _, r := range Restore(context.Background(), f, reg, s, RestoreOptions{}, Tuning{}) {
		if !r.OK || r.Detail != "already present and identical" {
			t.Errorf("again: %s: %s", r.Key, r.Detail)
		}
	}
}
