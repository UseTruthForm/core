package awsreads

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

func grants(t *testing.T, actions ...string) *Grants {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"Statement": []any{map[string]any{"Effect": "Allow", "Action": actions}}})
	g, err := ParsePolicy(b)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestMissingIsWhatTheBaseLacks(t *testing.T) {
	m, err := Missing([]*awscc.Registry{reg(map[string]string{
		"AWS::X::A": `{"handlers":{"list":{"permissions":["x:ListA"]},"read":{"permissions":["x:GetA","x:DescribeA"]}}}`,
		"AWS::X::D": `{"handlers":{"list":{"permissions":["x:ListD"]},"create":{"permissions":["x:CreateD"]}}}`,
	})}, grants(t, "x:List*"))
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string][]string{"AWS::X::A": {"x:DescribeA", "x:GetA"}}; !reflect.DeepEqual(m, want) {
		t.Errorf("missing %v, want %v (a type needing nothing is absent; create permissions are not reads)", m, want)
	}
}

// Each source catches what the others miss; every case is a real action
// (2026-10-24, review of #24). Names alone kept bedrock:GetSession (AWS:
// data plane). AWS's flags alone keep secretsmanager:GetSecretValue,
// ivs:GetStreamKey and glue:GetConnection (no flags), and drop
// quicksight:DescribeTopicPermissions (filed as permissions management).
// AWS's sensitive mark alone is on names and descriptions too.
func TestJudge(t *testing.T) {
	ref := &Reference{
		Actions: map[string]Flags{
			"bedrock:getblueprint":                {},
			"bedrock:getsession":                  {IsDataPlane: true},
			"quicksight:describetopicpermissions": {IsPermissionManagement: true, IsWrite: true},
			"datazone:getdomainpolicy":            {IsPermissionManagement: true, IsWrite: true},
			"cloudwatch:putmetricalarm":           {IsWrite: true},
			"secretsmanager:getsecretvalue":       {},
			"ivs:getstreamkey":                    {},
			"glue:getconnection":                  {},
			"datazone:getconnection":              {},
			"quicksight:describedashboard":        {},
			"geo:describekey":                     {},
			"cleanrooms:passmembership":           {},
			"x:getunchecked":                      {},
		},
		SecretFields: map[string][]string{
			"bedrock:getblueprint":                {},
			"quicksight:describetopicpermissions": {},
			"datazone:getconnection":              {"GetConnectionOutput.connectionCredentials"},
			"quicksight:describedashboard":        {},
			"geo:describekey":                     {"DescribeKeyResponse.Key"},
		},
	}
	for a, want := range map[string]string{
		"bedrock:GetBlueprint":                "read",
		"bedrock:GetSession":                  "AWS: data plane",
		"quicksight:DescribeTopicPermissions": "read",       // on the reviewed list
		"datazone:GetDomainPolicy":            "AWS: write", // same category, not on the list
		"cloudwatch:PutMetricAlarm":           "not named as a read",
		"secretsmanager:GetSecretValue":       "named like a secret or data read",
		"ivs:GetStreamKey":                    "named like a secret or data read",
		"glue:GetConnection":                  "returns the connection's password",
		"datazone:GetConnection":              "AWS marks its output sensitive: GetConnectionOutput.connectionCredentials",
		"geo:DescribeKey":                     "AWS marks its output sensitive",
		"quicksight:DescribeDashboard":        "read",
		"cleanrooms:PassMembership":           "not named as a read",
		"ec2:GetPasswordData":                 "named like a secret or data read",
		"sts:GetServiceBearerToken":           "named like a secret or data read",
		"ecr:GetDownloadUrlForLayer":          "named like a secret or data read",
		"securitylake:List*":                  "wildcard",
	} {
		if got := ref.Judge(a); !strings.HasPrefix(got.Why, want) {
			t.Errorf("%s: %q (keep=%v), want %q", a, got.Why, got.Keep, want)
		}
	}
	if v := ref.Judge("mediatailor:GetFunction"); !v.Keep || !strings.Contains(v.Unverified, "does not list") {
		t.Errorf("an action AWS does not list is kept by name and says so: %+v", v)
	}
	if v := ref.Judge("x:GetUnchecked"); !v.Keep || !strings.Contains(v.Unverified, "output could not be checked") {
		t.Errorf("an action whose output was not checked is kept and says so: %+v", v)
	}
}

// A wildcard's expansion leaves out what ReadOnlyAccess grants (one took
// 15 such actions), and a refused expansion leaves the type short: the
// first version counted it complete (review of #24).
func TestDecideExpandsWildcardsAndCountsRefusals(t *testing.T) {
	ref := &Reference{
		Actions:      map[string]Flags{"w:listportals": {IsList: true}, "w:listsessions": {IsList: true}, "w:listgranted": {IsList: true}, "w:createportal": {IsWrite: true}},
		Names:        map[string]string{"w:listportals": "w:ListPortals", "w:listsessions": "w:ListSessions", "w:listgranted": "w:ListGranted", "w:createportal": "w:CreatePortal"},
		SecretFields: map[string][]string{"w:listportals": {}, "w:listsessions": {"SessionSummary.username"}},
	}
	base := grants(t, "w:ListGranted", "q:Get*")
	res := Decide(map[string][]string{"AWS::W::Portal": {"w:List*"}, "AWS::Q::Y": {"managed-fleets:Get*"}}, ref, base)
	if !reflect.DeepEqual(res.Actions, []string{"w:ListPortals"}) {
		t.Errorf("actions %v: ReadOnlyAccess's w:ListGranted and the refused w:ListSessions must not be in it", res.Actions)
	}
	if res.Short["AWS::W::Portal"]["w:ListSessions"] == "" || res.Short["AWS::Q::Y"]["managed-fleets:Get*"] == "" || len(res.Completed) != 0 {
		t.Errorf("completed %v short %v", res.Completed, res.Short)
	}
	if !reflect.DeepEqual(res.OmittedByReadOnlyAccess, []string{"w:ListPortals"}) {
		t.Errorf("ReadOnlyAccess covers w and leaves ListPortals out: listed for review, got %v", res.OmittedByReadOnlyAccess)
	}
}

// AWS marks names and descriptions sensitive too; only fields named like
// a secret count, and a bare value or key only inside a secret's shape.
func TestSecretFields(t *testing.T) {
	sens := map[string]any{"smithy.api#sensitive": map[string]any{}}
	shapes := map[string]shape{
		"x#GetStreamKey":         {Type: "operation", Output: &member{Target: "x#GetStreamKeyResponse"}},
		"x#GetStreamKeyResponse": {Members: map[string]member{"streamKey": {Target: "x#StreamKey"}, "nextToken": {Target: "x#Token"}}},
		"x#StreamKey":            {Members: map[string]member{"value": {Target: "x#Value", Traits: sens}, "name": {Target: "x#Name", Traits: sens}}},
		"x#Token":                {Traits: sens},
		"x#Dashboard":            {Members: map[string]member{"Value": {Target: "x#V", Traits: sens}, "Description": {Target: "x#D", Traits: sens}, "Items": {Target: "x#List"}}},
		"x#List":                 {Member: &member{Target: "x#Cred"}},
		"x#Cred":                 {Members: map[string]member{"password": {Target: "x#P", Traits: sens}}},
	}
	out := map[string]bool{}
	secretFields(shapes, "x#GetStreamKeyResponse", map[string]bool{}, out)
	if !reflect.DeepEqual(out, map[string]bool{"StreamKey.value": true}) {
		t.Errorf("stream key: %v (the name is sensitive but not a secret; nextToken is paging)", out)
	}
	out = map[string]bool{}
	secretFields(shapes, "x#Dashboard", map[string]bool{}, out)
	if !reflect.DeepEqual(out, map[string]bool{"Cred.password": true}) {
		t.Errorf("dashboard: %v (a Value outside a secret's shape is configuration; the nested password is not)", out)
	}
	if o, ok := outputOf(shapes, "GetStreamKey"); !ok || o != "x#GetStreamKeyResponse" {
		t.Errorf("outputOf: %q %v", o, ok)
	}
}

func TestParsePolicyRefusesWhatItCannotList(t *testing.T) {
	if _, err := ParsePolicy([]byte(`{"Statement":[{"Effect":"Allow","NotAction":["iam:*"]}]}`)); err == nil {
		t.Error("NotAction accepted")
	}
	if _, err := ParsePolicy([]byte(`{"Statement":[{"Effect":"Deny","Action":"*"}]}`)); err == nil {
		t.Error("a policy granting nothing accepted")
	}
	g := grants(t, "Bedrock:Get*")
	if !g.Allows("bedrock:GetBlueprint") || g.Allows("bedrock:ListBlueprints") || g.Allows("xbedrock:GetX") || !g.Covers("bedrock:Anything") || g.Covers("x:y") {
		t.Error("glob matching or service coverage is wrong")
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

// Allowed is the floor the committed file is held to. The reviewer put
// iam:CreateAccessKey, s3:PutBucketPolicy and sts:AssumeRole into the file
// and the tests passed (review of #24); these must never be allowed.
func TestAllowedRefusesWritesAndSecrets(t *testing.T) {
	for _, a := range []string{"iam:CreateAccessKey", "s3:PutBucketPolicy", "sts:AssumeRole", "ivs:GetStreamKey", "ivs:BatchGetStreamKey",
		"glue:GetConnection", "secretsmanager:GetSecretValue", "ec2:GetPasswordData", "ssm:GetParameterHistory", "s3:GetObjectVersion",
		"kms:Decrypt", "securitylake:List*", "waf:GetChangeToken", "datazone:GetEnvironmentCredentials"} {
		if Allowed(a) {
			t.Errorf("%s allowed", a)
		}
	}
	for _, a := range []string{"bedrock:GetBlueprint", "quicksight:DescribeDashboard", "geo:ListMaps"} {
		if !Allowed(a) {
			t.Errorf("%s refused", a)
		}
	}
}

// The committed add-on is what a capture role is given: only actions
// Allowed accepts, each policy within IAM's size limit, its count as
// stated.
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
			if !Allowed(x) {
				t.Errorf("%s may not be in the add-on", x)
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
