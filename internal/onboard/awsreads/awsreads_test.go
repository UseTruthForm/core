package awsreads

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/stackdna/core/internal/awscc"
)

func reg(schemas map[string]string) *awscc.Registry {
	r := &awscc.Registry{Types: map[string]*awscc.TypeInfo{}}
	for name, s := range schemas {
		r.Types[name] = &awscc.TypeInfo{Name: name, Raw: []byte(s)}
	}
	return r
}

// Kept: reads of configuration the base lacks. Not kept, and the type
// reported short: writes and data reads a schema lists under read (the
// real ones: kms:Decrypt, secretsmanager:GetSecretValue,
// cloudwatch:PutMetricAlarm).
func TestComputeKeepsOnlyConfigurationReads(t *testing.T) {
	base, err := ParsePolicy([]byte(`{"Statement":[{"Effect":"Allow","Action":["x:List*","kms:Describe*"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	res, err := Compute([]*awscc.Registry{reg(map[string]string{
		"AWS::X::A": `{"handlers":{"list":{"permissions":["x:ListA"]},"read":{"permissions":["x:GetA","x:DescribeA"]}}}`,
		"AWS::X::B": `{"handlers":{"read":{"permissions":["x:GetB","kms:Decrypt","kms:DescribeKey"]}}}`,
		"AWS::X::C": `{"handlers":{"read":{"permissions":["secretsmanager:GetSecretValue","cloudwatch:PutMetricAlarm"]}}}`,
		"AWS::X::D": `{"handlers":{"list":{"permissions":["x:ListD"]}}}`,
	})}, base)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"x:DescribeA", "x:GetA", "x:GetB"}; !reflect.DeepEqual(res.Actions, want) {
		t.Errorf("actions %v, want %v", res.Actions, want)
	}
	if !reflect.DeepEqual(res.Completed, []string{"AWS::X::A"}) {
		t.Errorf("completed %v", res.Completed)
	}
	if !reflect.DeepEqual(res.Short["AWS::X::B"], []string{"kms:Decrypt"}) || len(res.Short["AWS::X::C"]) != 2 {
		t.Errorf("short %v", res.Short)
	}
}

func TestParsePolicyRefusesWhatItCannotList(t *testing.T) {
	if _, err := ParsePolicy([]byte(`{"Statement":[{"Effect":"Allow","NotAction":["iam:*"]}]}`)); err == nil {
		t.Error("NotAction accepted")
	}
	if _, err := ParsePolicy([]byte(`{"Statement":[{"Effect":"Deny","Action":"*"}]}`)); err == nil {
		t.Error("a policy granting nothing accepted")
	}
	g, _ := ParsePolicy([]byte(`{"Statement":[{"Effect":"Allow","Action":"Bedrock:Get*"}]}`))
	if !g.Allows("bedrock:GetBlueprint") || g.Allows("bedrock:ListBlueprints") || g.Allows("xbedrock:GetX") {
		t.Error("glob matching is wrong")
	}
}

// The committed add-on is what a capture role is given: only reads of
// configuration, each policy within IAM's size limit, and its count as
// stated. A hand edit that slips in a write fails here.
func TestCommittedAddOnIsOnlyReadsAndFits(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "templates", "aws-read-addon.json"))
	if err != nil {
		t.Fatal(err)
	}
	var a struct {
		Chunks      [][]string `json:"chunks"`
		ActionCount int        `json:"actionCount"`
	}
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i, c := range a.Chunks {
		pol, _ := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Resource": "*", "Action": c}}})
		if len(pol) > MaxPolicyChars {
			t.Errorf("policy %d is %d characters, over IAM's %d", i, len(pol), MaxPolicyChars)
		}
		for _, x := range c {
			if !IsRead(x) {
				t.Errorf("%s is not a read of configuration", x)
			}
			if seen[x] {
				t.Errorf("%s twice", x)
			}
			seen[x] = true
		}
	}
	if len(seen) != a.ActionCount || len(seen) == 0 {
		t.Errorf("%d actions, file says %d", len(seen), a.ActionCount)
	}
	if len(a.Chunks) > 9 {
		t.Errorf("%d policies: with ReadOnlyAccess that is over a role's 10 managed policies", len(a.Chunks))
	}
}
