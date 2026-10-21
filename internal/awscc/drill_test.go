package awscc

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackdna/core/internal/drilltest"
	"github.com/stackdna/core/internal/platform"
	"github.com/stackdna/core/internal/snapshot"
)

var _ platform.Platform = (*Adapter)(nil)

const (
	srcAccount = "111111111111"
	dstAccount = "222222222222"
	region     = "us-east-1"
	zipCode    = "def handler(event, context):\n    return 'stackdna'\n"
	secretVal  = "s3cr3t-value-never-on-disk"
)

func mustCreate(t *testing.T, f *Fake, typ string, props map[string]any) map[string]any {
	t.Helper()
	id, err := f.Create(context.Background(), typ, props)
	if err != nil {
		t.Fatalf("seed %s: %v", typ, err)
	}
	return f.Stored(typ, id)
}

func tags(kv ...string) []any {
	var out []any
	for i := 0; i < len(kv); i += 2 {
		out = append(out, map[string]any{"Key": kv[i], "Value": kv[i+1]})
	}
	return out
}

// newAccount returns a fake account that behaves as AWS was observed to.
func newAccount(w *World, account string) *Fake {
	f := w.Account(account, region)
	// Creating a REST API also creates its root resource "/", which Cloud
	// Control lists. Seen in the first real-account drill (2026-10-21):
	// without this the fake drill passed while the real one would have
	// tried to create the root and failed for want of a ParentId.
	//
	// A subnet created with a zone name is read back with the zone ID too,
	// and a create carrying both is refused (same drill): restore must
	// drop one or every subnet fails.
	f.AfterCreate = func(typ string, props map[string]any) {
		switch typ {
		case "AWS::ApiGateway::RestApi":
			id := f.Seed("AWS::ApiGateway::Resource", map[string]any{"RestApiId": props["RestApiId"]})
			props["RootResourceId"] = strings.Split(id, "|")[1]
		case "AWS::EC2::Subnet":
			if az, ok := props["AvailabilityZone"].(string); ok {
				props["AvailabilityZoneId"] = "use1-az" + az[len(az)-1:]
			} else if id, ok := props["AvailabilityZoneId"].(string); ok {
				props["AvailabilityZone"] = region + id[len(id)-1:]
			}
		}
	}
	f.Validate = func(typ string, d map[string]any) error {
		_, name := d["AvailabilityZone"]
		_, id := d["AvailabilityZoneId"]
		if typ == "AWS::EC2::Subnet" && name && id {
			return fmt.Errorf("Invalid request provided: Both AvailabilityZone and AvailabilityZoneId cannot be specified")
		}
		return nil
	}
	return f
}

// defaultVPC is what AWS puts in every account and region.
func defaultVPC(f *Fake) string {
	return f.Seed("AWS::EC2::VPC", map[string]any{"CidrBlock": "172.31.0.0/16"})
}

// seedShop builds a small but realistic application through the fake's
// validating Create, wiring references with the account's real IDs as a
// person (or Terraform) would.
func seedShop(t *testing.T, f *Fake) {
	defVPC := defaultVPC(f)
	vpc := mustCreate(t, f, "AWS::EC2::VPC", map[string]any{"CidrBlock": "10.0.0.0/16", "Tags": tags("Name", "main", "team", "shop")})
	mustCreate(t, f, "AWS::EC2::Subnet", map[string]any{"VpcId": vpc["VpcId"], "CidrBlock": "10.0.1.0/24", "AvailabilityZone": region + "a", "Tags": tags("Name", "app")})
	// A subnet someone added to the default VPC: the VPC is AWS's own and
	// is skipped as baseline, but the subnet is not and must be remapped
	// to the target account's default VPC.
	mustCreate(t, f, "AWS::EC2::Subnet", map[string]any{"VpcId": defVPC, "CidrBlock": "172.31.99.0/24", "Tags": tags("Name", "legacy-app")})
	// Tags deliberately out of order: the schema marks them a set.
	role := mustCreate(t, f, "AWS::IAM::Role", map[string]any{
		"RoleName": "shop-lambda",
		"AssumeRolePolicyDocument": map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{
			"Effect": "Allow", "Principal": map[string]any{"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}}},
		"Tags": tags("team", "shop", "env", "prod"),
	})
	queue := mustCreate(t, f, "AWS::SQS::Queue", map[string]any{"QueueName": "shop-jobs", "VisibilityTimeout": 60})
	secret := mustCreate(t, f, "AWS::SecretsManager::Secret", map[string]any{"Name": "shop/db", "SecretString": secretVal})
	mustCreate(t, f, "AWS::Lambda::Function", map[string]any{
		"FunctionName": "shop-api", "Role": role["Arn"], "Runtime": "python3.13", "Handler": "app.handler",
		"Code":        map[string]any{"ZipFile": zipCode},
		"Environment": map[string]any{"Variables": map[string]any{"QUEUE_URL": queue["QueueUrl"], "SECRET_ID": secret["Id"]}},
	})
	mustCreate(t, f, "AWS::S3::Bucket", map[string]any{"BucketName": "shop-assets", "VersioningConfiguration": map[string]any{"Status": "Enabled"}})
	mustCreate(t, f, "AWS::SSM::Parameter", map[string]any{"Name": "/shop/env", "Type": "String", "Value": "prod"})
	api := mustCreate(t, f, "AWS::ApiGateway::RestApi", map[string]any{"Name": "shop"})
	// Resources have no name of their own; nested ones reference each
	// other's generated IDs, so their logical names come from hashes of
	// tokenized specs and must still agree across accounts.
	orders := mustCreate(t, f, "AWS::ApiGateway::Resource", map[string]any{"RestApiId": api["RestApiId"], "ParentId": api["RootResourceId"], "PathPart": "orders"})
	mustCreate(t, f, "AWS::ApiGateway::Resource", map[string]any{"RestApiId": api["RestApiId"], "ParentId": orders["ResourceId"], "PathPart": "{id}"})

	// What AWS and CloudFormation own, which must be skipped.
	f.Seed("AWS::S3::Bucket", map[string]any{"BucketName": "legacy-stack-bucket", "Tags": tags("aws:cloudformation:stack-name", "legacy")})
	f.Seed("AWS::IAM::Role", map[string]any{"RoleName": "AWSServiceRoleForSupport", "Path": "/aws-service-role/support.amazonaws.com/",
		"AssumeRolePolicyDocument": map[string]any{}})
}

var shopKeys = []string{
	"AWS::EC2::VPC||main",
	"AWS::EC2::Subnet||app",
	"AWS::EC2::Subnet||legacy-app",
	"AWS::IAM::Role||shop-lambda",
	"AWS::SQS::Queue||shop-jobs",
	"AWS::SecretsManager::Secret||shop/db",
	"AWS::Lambda::Function||shop-api",
	"AWS::S3::Bucket||shop-assets",
	"AWS::SSM::Parameter||/shop/env",
	"AWS::ApiGateway::RestApi||shop",
	// Pinned: the hash of a tokenized spec. If these change, names in
	// existing snapshots change, which is a format change.
	"AWS::ApiGateway::Resource||h-0b3a4f829256",
	"AWS::ApiGateway::Resource||h-8a8b99be7fdf",
}

type env struct {
	reg      *Registry
	src, dst *Fake
	pol      Policy
	vals     map[string]map[string]any
}

func newEnv(t *testing.T) env {
	reg := fixtures(t)
	w := NewWorld(reg)
	// The baseline is a capture of a fresh account: just the default VPC.
	fresh := newAccount(w, "333333333333")
	defaultVPC(fresh)
	base, err := Capture(context.Background(), fresh, reg, region, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if len(base.Objects) != 1 {
		t.Fatalf("baseline should hold only the default VPC, got %d objects", len(base.Objects))
	}
	e := env{reg: reg, src: newAccount(w, srcAccount), dst: newAccount(w, dstAccount)}
	e.pol = Policy{}.WithBaseline(base, "sha256:test-baseline")
	seedShop(t, e.src)
	defaultVPC(e.dst)
	e.vals = map[string]map[string]any{
		"AWS::Lambda::Function/shop-api":      {"Code": map[string]any{"ZipFile": zipCode}},
		"AWS::SecretsManager::Secret/shop/db": {"SecretString": secretVal},
	}
	return e
}

func (e env) adapter(f *Fake) *Adapter {
	return &Adapter{API: f, Registry: e.reg, Region: region, Policy: e.pol, Options: RestoreOptions{Values: e.vals}}
}

func keys(t *testing.T) []string {
	var out []string
	for _, k := range shopKeys {
		out = append(out, APIVersion+"|"+k)
	}
	return out
}

func TestDrillOnFakeAccounts(t *testing.T) {
	e := newEnv(t)
	snap := drilltest.Run(t, drilltest.Spec{Source: e.adapter(e.src), Target: e.adapter(e.dst), ExpectKeys: keys(t)})

	// The drill proved the target captures identically. These prove the
	// values behind the tokens are the target's own, and that write-only
	// values arrived although they were never in the snapshot.
	dstID := func(typ string, match func(map[string]any) bool) map[string]any {
		for _, id := range e.dst.IDs(typ) {
			if p := e.dst.Stored(typ, id); match(p) {
				return p
			}
		}
		t.Fatalf("%s not found in target", typ)
		return nil
	}
	tagged := func(name string) func(map[string]any) bool {
		return func(p map[string]any) bool { return baseName(e.reg.Types["AWS::EC2::Subnet"], p) == name }
	}
	byName := func(k, v string) func(map[string]any) bool {
		return func(p map[string]any) bool { return p[k] == v }
	}
	lambda := dstID("AWS::Lambda::Function", byName("FunctionName", "shop-api"))
	role := dstID("AWS::IAM::Role", byName("RoleName", "shop-lambda"))
	queue := dstID("AWS::SQS::Queue", byName("QueueName", "shop-jobs"))
	secret := dstID("AWS::SecretsManager::Secret", byName("Name", "shop/db"))
	if lambda["Role"] != role["Arn"] {
		t.Errorf("lambda role %v, want target role %v", lambda["Role"], role["Arn"])
	}
	vars := lambda["Environment"].(map[string]any)["Variables"].(map[string]any)
	if vars["QUEUE_URL"] != queue["QueueUrl"] || vars["SECRET_ID"] != secret["Id"] {
		t.Errorf("lambda env %v not remapped to target queue %v / secret %v", vars, queue["QueueUrl"], secret["Id"])
	}
	if lambda["Code"].(map[string]any)["ZipFile"] != zipCode {
		t.Error("lambda code did not arrive")
	}
	if secret["SecretString"] != secretVal {
		t.Error("secret value did not arrive")
	}
	defVPC := e.dst.IDs("AWS::EC2::VPC")[0] // seeded first: the target's default VPC
	if sub := dstID("AWS::EC2::Subnet", tagged("legacy-app")); sub["VpcId"] != defVPC {
		t.Errorf("legacy-app subnet in %v, want the target's default VPC %v", sub["VpcId"], defVPC)
	}

	// Nothing account-specific or secret may be in the spec of any object.
	for _, o := range snap.Objects {
		s := canon(o.Body["spec"])
		for _, bad := range []string{srcAccount, secretVal, "stackdna'", "vpc-"} {
			if strings.Contains(s, bad) {
				t.Errorf("%s spec contains %q: %s", o.Key(), bad, s)
			}
		}
	}

	// Restoring again finds everything present and creates nothing.
	before := e.dst.Count()
	for _, r := range e.adapter(e.dst).Restore(context.Background(), snap) {
		if !r.OK || r.Detail != "already present and identical" {
			t.Errorf("second restore: %s: ok=%v %s", r.Key, r.OK, r.Detail)
		}
	}
	if after := e.dst.Count(); canon(after) != canon(before) {
		t.Errorf("second restore created resources: %v -> %v", before, after)
	}
}

// The snapshot on disk holds no secret, no code and no source account ID in
// any spec, and the skipped resources are reported with reasons.
func TestSnapshotOnDisk(t *testing.T) {
	e := newEnv(t)
	snap, err := e.adapter(e.src).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := snap.Write(dir); err != nil {
		t.Fatal(err)
	}
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		for _, bad := range []string{secretVal, "return 'stackdna'"} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s contains %q", p, bad)
			}
		}
		return nil
	})
	want := map[string]string{
		"AWS::S3::Bucket/legacy-stack-bucket":     "managed by CloudFormation stack legacy",
		"AWS::IAM::Role/AWSServiceRoleForSupport": "service-linked role",
		"AWS::EC2::VPC/":                          "identical to the account baseline",
		"AWS::ApiGateway::Resource/h-":            "created by AWS with AWS::ApiGateway::RestApi/shop (its RootResourceId)",
	}
	for _, s := range snap.Skips {
		for k, reason := range want {
			if strings.HasPrefix(s.Resource+"/"+s.Name, k) && strings.Contains(s.Reason, reason) {
				delete(want, k)
			}
		}
	}
	if len(want) > 0 {
		t.Errorf("skips missing: %v (got %+v)", want, snap.Skips)
	}
	lambda := find(t, snap, "AWS::Lambda::Function")
	ann := lambda.Body["metadata"].(map[string]any)["annotations"].(map[string]any)[annWriteOnly]
	if !strings.Contains(ann.(string), "Code") {
		t.Errorf("lambda write-only annotation %v does not name Code", ann)
	}
	role := find(t, snap, "AWS::IAM::Role")
	if tg := canon(role.Body["spec"].(map[string]any)["Tags"]); tg != `[{"Key":"env","Value":"prod"},{"Key":"team","Value":"shop"}]` {
		t.Errorf("role tags not in canonical order: %s", tg)
	}
}

func find(t *testing.T, s snapshot.Snapshot, kind string) snapshot.Object {
	t.Helper()
	for _, o := range s.Objects {
		if o.Kind() == kind {
			return o
		}
	}
	t.Fatalf("no %s in snapshot", kind)
	return snapshot.Object{}
}

// Without the write-only values, Lambda cannot be created and says why;
// the secret is created but the result names what was not supplied.
func TestRestoreWithoutWriteOnlyValues(t *testing.T) {
	e := newEnv(t)
	snap, _ := e.adapter(e.src).Capture(context.Background())
	a := e.adapter(e.dst)
	a.Options = RestoreOptions{}
	for _, r := range a.Restore(context.Background(), snap) {
		switch {
		case strings.Contains(r.Key, "Lambda"):
			if r.OK || !strings.Contains(r.Detail, "required property Code is write-only") {
				t.Errorf("lambda: ok=%v %s", r.OK, r.Detail)
			}
		case strings.Contains(r.Key, "SecretsManager"):
			if !r.OK || !strings.Contains(r.Detail, "write-only, not supplied: GenerateSecretString, SecretString") {
				t.Errorf("secret: ok=%v %s", r.OK, r.Detail)
			}
		case !r.OK:
			t.Errorf("%s: %s", r.Key, r.Detail)
		}
	}
}

// A target without a default VPC cannot hold the legacy-app subnet; the
// result names the missing dependency instead of sending a source ID.
func TestRestoreMissingDependency(t *testing.T) {
	e := newEnv(t)
	snap, _ := e.adapter(e.src).Capture(context.Background())
	empty := newAccount(NewWorld(e.reg), dstAccount)
	for _, r := range e.adapter(empty).Restore(context.Background(), snap) {
		if strings.HasSuffix(r.Key, "legacy-app") {
			if r.OK || !strings.Contains(r.Detail, "depends on AWS::EC2::VPC/h-") || !strings.Contains(r.Detail, "is not in the target") {
				t.Errorf("legacy-app: ok=%v %s", r.OK, r.Detail)
			}
		} else if !r.OK {
			t.Errorf("%s: %s", r.Key, r.Detail)
		}
	}
}

// The fake refuses another account's IDs, as AWS does. Without this the
// drill could pass with references that were never remapped.
func TestFakeRefusesForeignIDs(t *testing.T) {
	reg := fixtures(t)
	w := NewWorld(reg)
	a, b := newAccount(w, srcAccount), newAccount(w, dstAccount)
	vpc := mustCreate(t, a, "AWS::EC2::VPC", map[string]any{"CidrBlock": "10.0.0.0/16"})
	_, err := b.Create(context.Background(), "AWS::EC2::Subnet", map[string]any{"VpcId": vpc["VpcId"], "CidrBlock": "10.0.1.0/24"})
	if err == nil || !strings.Contains(err.Error(), "belongs to account "+srcAccount) {
		t.Fatalf("want foreign-ID refusal, got %v", err)
	}
}

// A type the region does not offer is not captured by design; it is not a
// failure that marks the snapshot incomplete.
func TestUnsupportedTypeIsNotAFailure(t *testing.T) {
	reg := fixtures(t)
	f := NewWorld(reg).Account(srcAccount, region)
	f.Unsupported["AWS::SSM::Parameter"] = true
	snap, err := Capture(context.Background(), f, reg, region, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range snap.Coverage {
		if c.Resource == "AWS::SSM::Parameter" && c.NotCaptured != "not available in this account or region" {
			t.Errorf("coverage %+v", c)
		}
		if strings.HasPrefix(c.NotCaptured, "list failed") {
			t.Errorf("%s reported as failed: %s", c.Resource, c.NotCaptured)
		}
	}
}
