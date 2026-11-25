package awscc

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// A tag's value in a policy's condition is a label, and so is the name of
// something outside AWS: the namespace "shop" a role's trust policy and a
// pod identity association name must not become a token for the ECR
// repository (or the EKS cluster) called shop. It did; the association was
// then named by another hash than the snapshot's, and a second restore
// created it again. A generated ID in the same places stays a reference.
func TestNamesOutsideAWSAreNotReferences(t *testing.T) {
	dir := t.TempDir()
	for _, src := range []string{
		filepath.Join("..", "..", "testdata", "aws", "schemas", "aws-iam-role.json"),
		filepath.Join("..", "..", "testdata", "aws", "schemas", "aws-ecr-repository.json"),
		filepath.Join("..", "..", "testdata", "aws", "schemas", "aws-ec2-vpc.json"),
		filepath.Join("..", "translate", "testdata", "aws", "aws-eks-podidentityassociation.json"),
	} {
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(src)), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	reg, err := ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	repo := normalize(reg.Types["AWS::ECR::Repository"], "shop", map[string]any{
		"RepositoryName": "shop", "Arn": "arn:aws:ecr:us-east-2:111111111111:repository/shop"})
	orders := normalize(reg.Types["AWS::ECR::Repository"], "orders", map[string]any{
		"RepositoryName": "orders", "Arn": "arn:aws:ecr:us-east-2:111111111111:repository/orders"})
	vpc := normalize(reg.Types["AWS::EC2::VPC"], "vpc-0def5678", map[string]any{"VpcId": "vpc-0def5678", "CidrBlock": "10.42.0.0/16",
		"Tags": []any{map[string]any{"Key": "Name", "Value": "main"}}})
	cond := func() map[string]any {
		return map[string]any{"StringEquals": map[string]any{
			"aws:RequestTag/kubernetes-namespace":       "shop",
			"aws:RequestTag/kubernetes-service-account": []any{"orders"},
			"aws:RequestTag/vpc":                        "vpc-0def5678",
			"aws:SourceVpc":                             "vpc-0def5678",
		}}
	}
	role := normalize(reg.Types["AWS::IAM::Role"], "app", map[string]any{"RoleName": "app", "Arn": "arn:aws:iam::111111111111:role/app",
		"AssumeRolePolicyDocument": map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{
			"Effect": "Allow", "Principal": map[string]any{"Service": "pods.eks.amazonaws.com"}, "Action": []any{"sts:AssumeRole", "sts:TagSession"}, "Condition": cond()}}}})
	assoc := normalize(reg.Types["AWS::EKS::PodIdentityAssociation"], "arn:aws:eks:us-east-2:111111111111:podidentityassociation/c/a-1", map[string]any{
		"AssociationArn": "arn:aws:eks:us-east-2:111111111111:podidentityassociation/c/a-1", "ClusterName": "c",
		"Namespace": "shop", "ServiceAccount": "orders", "RoleArn": "arn:aws:iam::111111111111:role/app"})
	name([]*resource{repo, orders, vpc, role, assoc}, "111111111111")
	got := role.spec["AssumeRolePolicyDocument"].(map[string]any)["Statement"].([]any)[0].(map[string]any)["Condition"]
	want := cond()
	se := want["StringEquals"].(map[string]any)
	// The VPC's ID is generated: a reference wherever it stands.
	se["aws:RequestTag/vpc"] = refToken("AWS::EC2::VPC", "main", "VpcId")
	se["aws:SourceVpc"] = refToken("AWS::EC2::VPC", "main", "VpcId")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the role's condition: %v", got)
	}
	if assoc.spec["Namespace"] != "shop" || assoc.spec["ServiceAccount"] != "orders" {
		t.Errorf("the association names %v/%v", assoc.spec["Namespace"], assoc.spec["ServiceAccount"])
	}
	if assoc.spec["RoleArn"] != refToken("AWS::IAM::Role", "app", "Arn") {
		t.Errorf("the association's role: %v", assoc.spec["RoleArn"])
	}
}
