package awscc

import (
	"strings"
	"testing"
)

func fixtures(t *testing.T) *Registry {
	t.Helper()
	reg, err := ReadDir("../../testdata/aws/schemas")
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

// These are AWS's published schemas, copied unmodified. The assertions pin
// what the adapter relies on, so a schema-format change AWS makes shows up
// here rather than as a capture that quietly stops working.
func TestSchemaFacts(t *testing.T) {
	reg := fixtures(t)
	if len(reg.Types) != 10 {
		t.Fatalf("loaded %d types, want 10", len(reg.Types))
	}
	cases := []struct {
		typ         string
		id          string
		generatedID bool
		writeOnly   string
		readOnly    string
	}{
		{"AWS::EC2::VPC", "VpcId", true, "", "VpcId"},
		{"AWS::S3::Bucket", "BucketName", false, "", "Arn"},
		{"AWS::IAM::Role", "RoleName", false, "", "Arn"},
		{"AWS::SQS::Queue", "QueueUrl", true, "", "Arn"},
		{"AWS::SecretsManager::Secret", "Id", true, "SecretString", ""},
		{"AWS::SSM::Parameter", "Name", false, "", ""},
	}
	for _, c := range cases {
		ty := reg.Types[c.typ]
		if ty == nil {
			t.Errorf("%s not loaded", c.typ)
			continue
		}
		if ty.PrimaryIdentifier[0] != c.id {
			t.Errorf("%s identifier %v, want %s", c.typ, ty.PrimaryIdentifier, c.id)
		}
		if ty.GeneratedID() != c.generatedID {
			t.Errorf("%s GeneratedID %v, want %v", c.typ, ty.GeneratedID(), c.generatedID)
		}
		if c.writeOnly != "" && !ty.IsWriteOnly(c.writeOnly) {
			t.Errorf("%s: %s should be write-only (have %v)", c.typ, c.writeOnly, ty.WriteOnly)
		}
		if c.readOnly != "" && !ty.IsReadOnly(c.readOnly) {
			t.Errorf("%s: %s should be read-only (have %v)", c.typ, c.readOnly, ty.ReadOnly)
		}
		if !ty.Capturable() {
			t.Errorf("%s should have list and read handlers", c.typ)
		}
	}
	if !strings.HasPrefix(reg.Digest, "sha256:") {
		t.Errorf("digest %q", reg.Digest)
	}
}

// AWS::ApiGateway::Resource can only be listed per RestApi. The parent must
// be derived from the schemas, not from a table in code.
func TestListPlanFromSchemas(t *testing.T) {
	reg := fixtures(t)
	plan, reason := reg.Plan(reg.Types["AWS::ApiGateway::Resource"])
	if reason != "" {
		t.Fatal(reason)
	}
	if plan.ParentType != "AWS::ApiGateway::RestApi" || plan.FromParent["RestApiId"] != "RestApiId" || len(plan.Enums) != 0 {
		t.Fatalf("plan = %+v", plan)
	}
	if plan, _ := reg.Plan(reg.Types["AWS::S3::Bucket"]); plan.ParentType != "" {
		t.Fatalf("bucket lists directly, got %+v", plan)
	}
}

// Shapes the fixtures do not have, taken from real registry types:
// WAFv2 lists per Scope (an enum, not a parent), Glue tables need two
// properties that one parent carries, and S3 Tables spells its suffix ARN.
func TestListPlanShapes(t *testing.T) {
	ty := func(name string, ids []string, props map[string]any, listReq ...string) *TypeInfo {
		return &TypeInfo{Name: name, PrimaryIdentifier: ids, Properties: props, ListRequires: listReq,
			Handlers: map[string]bool{"list": true, "read": true}}
	}
	str := map[string]any{"type": "string"}
	reg := &Registry{Types: map[string]*TypeInfo{}}
	for _, t := range []*TypeInfo{
		ty("AWS::WAFv2::IPSet", []string{"Name", "Id", "Scope"}, map[string]any{"Scope": map[string]any{"type": "string", "enum": []any{"CLOUDFRONT", "REGIONAL"}}}, "Scope"),
		ty("AWS::Glue::Database", []string{"DatabaseName"}, map[string]any{"CatalogId": str, "DatabaseName": str}),
		ty("AWS::Glue::Table", []string{"Id"}, map[string]any{"CatalogId": str, "DatabaseName": str}, "CatalogId", "DatabaseName"),
		ty("AWS::S3Tables::TableBucket", []string{"TableBucketARN"}, map[string]any{"TableBucketARN": str}),
		ty("AWS::S3Tables::TableBucketPolicy", []string{"TableBucketARN"}, map[string]any{"TableBucketARN": str}),
		ty("AWS::S3Tables::Namespace", []string{"TableBucketARN", "Namespace"}, map[string]any{"TableBucketARN": str}, "TableBucketARN"),
		ty("AWS::QuickSight::Theme", []string{"AwsAccountId", "ThemeId"}, map[string]any{"AwsAccountId": str}, "AwsAccountId"),
	} {
		reg.Types[t.Name] = t
	}
	if p, why := reg.Plan(reg.Types["AWS::WAFv2::IPSet"]); why != "" || p.ParentType != "" || strings.Join(p.Enums["Scope"], ",") != "CLOUDFRONT,REGIONAL" {
		t.Errorf("WAFv2: %+v %s", p, why)
	}
	if p, why := reg.Plan(reg.Types["AWS::Glue::Table"]); why != "" || p.ParentType != "AWS::Glue::Database" || p.FromParent["CatalogId"] != "CatalogId" {
		t.Errorf("Glue: %+v %s", p, why)
	}
	if p, why := reg.Plan(reg.Types["AWS::S3Tables::Namespace"]); why != "" || p.ParentType != "AWS::S3Tables::TableBucket" {
		t.Errorf("S3Tables: %+v %s", p, why)
	}
	// The account ID is not a resource: reported, not guessed.
	if _, why := reg.Plan(reg.Types["AWS::QuickSight::Theme"]); !strings.Contains(why, "AwsAccountId") {
		t.Errorf("QuickSight should be unresolved, got %q", why)
	}
}

func TestFieldsFromSchema(t *testing.T) {
	reg := fixtures(t)
	f := reg.Types["AWS::Lambda::Function"].Fields()
	for _, want := range []string{"Code", "Code.S3Bucket", "Code.ZipFile", "Role", "Environment.Variables.*"} {
		if !contains(f, want) {
			t.Errorf("Lambda fields missing %q", want)
		}
	}
	if FieldsDigest(f) != FieldsDigest(reg.Types["AWS::Lambda::Function"].Fields()) {
		t.Error("fields digest not stable")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
