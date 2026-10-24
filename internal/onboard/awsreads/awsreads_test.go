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

func TestMissingIsWhatTheBaseLacks(t *testing.T) {
	base, err := ParsePolicy([]byte(`{"Statement":[{"Effect":"Allow","Action":["x:List*","kms:Describe*"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	m, err := Missing([]*awscc.Registry{reg(map[string]string{
		"AWS::X::A": `{"handlers":{"list":{"permissions":["x:ListA"]},"read":{"permissions":["x:GetA","x:DescribeA"]}}}`,
		"AWS::X::D": `{"handlers":{"list":{"permissions":["x:ListD"]},"create":{"permissions":["x:CreateD"]}}}`,
	})}, base)
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string][]string{"AWS::X::A": {"x:DescribeA", "x:GetA"}}; !reflect.DeepEqual(m, want) {
		t.Errorf("missing %v, want %v (a type needing nothing is absent; create permissions are not reads)", m, want)
	}
}

// Kept only when named as a read and AWS does not say otherwise; secrets
// never. Each case is a real action from 2026-10-24: names alone kept
// bedrock:GetSession (AWS: data plane); AWS alone would keep
// secretsmanager:GetSecretValue and cleanrooms:PassMembership (no flags)
// and drop quicksight:DescribeTopicPermissions (filed as permissions
// management, so marked a write).
func TestJudge(t *testing.T) {
	ref := &Reference{Actions: map[string]Flags{
		"bedrock:getblueprint":                       {},
		"bedrock:getsession":                         {IsDataPlane: true},
		"bedrock:listsessions":                       {IsDataPlane: true, IsList: true},
		"quicksight:describetopicpermissions":        {IsPermissionManagement: true, IsWrite: true},
		"bcm-pricing-calculator:listtagsforresource": {IsTaggingOnly: true, IsWrite: true},
		"route53globalresolver:listtagsforresource":  {IsWrite: true},
		"cloudwatch:putmetricalarm":                  {IsWrite: true},
		"secretsmanager:getsecretvalue":              {},
		"kms:decrypt":                                {},
		"cleanrooms:passmembership":                  {},
		"cassandra:selectmultiregionresource":        {},
	}}
	for a, want := range map[string]bool{
		"bedrock:GetBlueprint":                       true,
		"bedrock:GetSession":                         false,
		"bedrock:ListSessions":                       false,
		"quicksight:DescribeTopicPermissions":        true,
		"bcm-pricing-calculator:ListTagsForResource": true,
		"route53globalresolver:ListTagsForResource":  false, // a bare write flag: refused, conservatively
		"cloudwatch:PutMetricAlarm":                  false,
		"secretsmanager:GetSecretValue":              false,
		"kms:Decrypt":                                false,
		"cleanrooms:PassMembership":                  false,
		"cassandra:SelectMultiRegionResource":        false,
		"mediatailor:GetFunction":                    true, // not listed: kept by name
		"mediatailor:StartChannel":                   false,
		"securitylake:List*":                         false,
	} {
		if got := ref.Judge(a); got.Keep != want {
			t.Errorf("%s: keep=%v (%s), want %v", a, got.Keep, got.Why, want)
		}
	}
	if v := ref.Judge("mediatailor:GetFunction"); v.Why != "read by name" {
		t.Errorf("an action AWS does not list must say it was kept by name: %q", v.Why)
	}
}

// A schema's wildcard becomes the concrete reads AWS lists: securitylake:List*
// and managed-fleets:Get* (a service AWS does not list) were in the first
// add-on as wildcards, which grant whatever AWS adds later.
func TestWildcardsAreExpandedNotGranted(t *testing.T) {
	ref := &Reference{
		Actions: map[string]Flags{"securitylake:listdatalakes": {IsList: true}, "securitylake:listlogsources": {IsList: true},
			"securitylake:listsecretthings": {IsDataPlane: true}, "securitylake:createdatalake": {IsWrite: true}},
		Names: map[string]string{"securitylake:listdatalakes": "securitylake:ListDataLakes", "securitylake:listlogsources": "securitylake:ListLogSources",
			"securitylake:listsecretthings": "securitylake:ListSecretThings", "securitylake:createdatalake": "securitylake:CreateDataLake"},
	}
	res := Decide(map[string][]string{"AWS::SecurityLake::DataLake": {"securitylake:List*"}, "AWS::X::Y": {"managed-fleets:Get*"}}, ref)
	if !reflect.DeepEqual(res.Actions, []string{"securitylake:ListDataLakes", "securitylake:ListLogSources"}) {
		t.Errorf("actions %v", res.Actions)
	}
	if !reflect.DeepEqual(res.Completed, []string{"AWS::SecurityLake::DataLake"}) || res.Short["AWS::X::Y"]["managed-fleets:Get*"] == "" {
		t.Errorf("completed %v short %v", res.Completed, res.Short)
	}
}

func TestDecide(t *testing.T) {
	ref := &Reference{Actions: map[string]Flags{"x:geta": {}, "x:getb": {}, "kms:decrypt": {}}}
	res := Decide(map[string][]string{
		"AWS::X::A": {"x:GetA"},
		"AWS::X::B": {"x:GetB", "kms:Decrypt"},
		"AWS::X::N": {"new:GetThing"},
	}, ref)
	if !reflect.DeepEqual(res.Actions, []string{"new:GetThing", "x:GetA", "x:GetB"}) || !reflect.DeepEqual(res.Unverified, []string{"new:GetThing"}) {
		t.Errorf("actions %v unverified %v", res.Actions, res.Unverified)
	}
	if !reflect.DeepEqual(res.Completed, []string{"AWS::X::A", "AWS::X::N"}) || res.Short["AWS::X::B"]["kms:Decrypt"] == "" {
		t.Errorf("completed %v short %v", res.Completed, res.Short)
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

// The page's layout is what the scheduled job depends on: a changed
// layout must fail, never yield an empty policy (every read would then
// look missing).
func TestParsePolicyPage(t *testing.T) {
	page := []byte("# ReadOnlyAccess\n\n## Policy version\n\n**Policy version:** v190 (default)\n\n## JSON policy document\n\n```\n{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"a:Get*\"],\"Resource\":\"*\"}]}\n```\n\n## Learn more\n")
	doc, ver, err := ParsePolicyPage(page)
	if err != nil || ver != "v190" {
		t.Fatalf("%v %q", err, ver)
	}
	if g, err := ParsePolicy(doc); err != nil || !g.Allows("a:GetX") {
		t.Errorf("policy from the page: %v", err)
	}
	for _, bad := range []string{"# ReadOnlyAccess\nno version here\n", "**Policy version:** v1\n## JSON policy document\n```\n{not json\n```\n"} {
		if _, _, err := ParsePolicyPage([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// The committed add-on is what a capture role is given: no wildcard, no
// secret or data read, each policy within IAM's size limit, its count as
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
			if !IsConfigurationRead(x) {
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
