package awscc

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/usetruthform/core/internal/snapshot"
)

// Failures from the broadened real drill, us-east-2, 2026-10-22.

// A VPC's default security group is AWS's: the VPC reports it as
// DefaultSecurityGroup. The group reporting its own ID as GroupId must not
// hide that (it sorts first, so it claimed the value for itself).
func TestVPCDefaultSecurityGroupIsCreatedByAWS(t *testing.T) {
	reg := fixtures(t)
	sg := normalize(reg.Types["AWS::EC2::SecurityGroup"], "sg-0abc1234", map[string]any{
		"Id": "sg-0abc1234", "GroupId": "sg-0abc1234", "GroupName": "default", "GroupDescription": "default VPC security group", "VpcId": "vpc-0def5678"})
	vpc := normalize(reg.Types["AWS::EC2::VPC"], "vpc-0def5678", map[string]any{
		"VpcId": "vpc-0def5678", "CidrBlock": "10.42.0.0/16", "DefaultSecurityGroup": "sg-0abc1234"})
	markCreatedBy([]*resource{sg, vpc})
	if sg.createdBy != vpc || sg.createdAt != "DefaultSecurityGroup" {
		t.Errorf("default security group not marked as created with the VPC (createdBy=%v, at %q)", sg.createdBy, sg.createdAt)
	}
}

// A tag value equal to a chosen name is a label, not a reference: the VPC's
// Name tag must not become a token for the ECR repository of that name.
func TestChosenNameInTagIsNotAReference(t *testing.T) {
	reg := fixtures(t)
	repo := normalize(reg.Types["AWS::ECR::Repository"], "shop", map[string]any{
		"RepositoryName": "shop", "Arn": "arn:aws:ecr:us-east-2:111111111111:repository/shop"})
	vpc := normalize(reg.Types["AWS::EC2::VPC"], "vpc-0def5678", map[string]any{
		"VpcId": "vpc-0def5678", "CidrBlock": "10.42.0.0/16",
		"Tags": []any{map[string]any{"Key": "Name", "Value": "shop"}}})
	name([]*resource{repo, vpc}, "")
	want := []any{map[string]any{"Key": "Name", "Value": "shop"}}
	if !reflect.DeepEqual(vpc.spec["Tags"], want) {
		t.Errorf("tag rewritten to %v", vpc.spec["Tags"])
	}
}

// A generated ID in a tag still differs per account, so it stays a
// reference: the rule above is about chosen names only.
func TestGeneratedIDInTagIsAReference(t *testing.T) {
	reg := fixtures(t)
	vpc := normalize(reg.Types["AWS::EC2::VPC"], "vpc-0def5678", map[string]any{
		"VpcId": "vpc-0def5678", "CidrBlock": "10.42.0.0/16",
		"Tags": []any{map[string]any{"Key": "Name", "Value": "shop"}}})
	sn := normalize(reg.Types["AWS::EC2::Subnet"], "subnet-0aa", map[string]any{
		"SubnetId": "subnet-0aa", "VpcId": "vpc-0def5678", "CidrBlock": "10.42.1.0/24",
		"Tags": []any{map[string]any{"Key": "vpc", "Value": "vpc-0def5678"}}})
	name([]*resource{vpc, sn}, "")
	tag := sn.spec["Tags"].([]any)[0].(map[string]any)["Value"]
	if tag != refToken("AWS::EC2::VPC", "shop", "identifier") && tag != refToken("AWS::EC2::VPC", "shop", "VpcId") {
		t.Errorf("generated VPC ID in a tag kept literally: %v", tag)
	}
}

// SNS reads an unset ArchivePolicy back as {} and refuses it on create
// ("Unknown attribute ArchivePolicy").
func TestEmptyObjectIsUnset(t *testing.T) {
	reg := fixtures(t)
	r := normalize(reg.Types["AWS::SNS::Topic"], "arn:aws:sns:us-east-2:111111111111:alerts", map[string]any{
		"TopicName": "alerts", "FifoTopic": false, "ArchivePolicy": map[string]any{},
		"TopicArn": "arn:aws:sns:us-east-2:111111111111:alerts"})
	if _, ok := r.spec["ArchivePolicy"]; ok {
		t.Errorf("empty ArchivePolicy kept: %v", r.spec)
	}
}

// Only one field of a security group's ingress rules is write-only; the
// annotation must not say the rules themselves are absent.
func TestWriteOnlyFieldsAreExact(t *testing.T) {
	got := writeOnlyFields(fixtures(t).Types["AWS::EC2::SecurityGroup"])
	if want := []string{"SecurityGroupIngress[].SourceSecurityGroupName"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// sgAccount behaves as EC2 does with security groups: a VPC comes with a
// default group (reported as its DefaultSecurityGroup) that allows itself
// in and everything out; a new group gets allow-all egress; every rule is
// also listed as a resource of its own, read back with its group's name
// and its source group's name and owner account; a rule naming its group
// both ways, or another account as owner, is refused; and so is a rule
// that already exists (in probes Cloud Control adopted such a duplicate,
// so refusing it is the stricter case).
func sgAccount(w *World, account string) *Fake {
	f := w.Account(account, region)
	groupName := func(id string) any { return f.res["AWS::EC2::SecurityGroup"][id]["GroupName"] }
	readBack := func(typ string, p map[string]any) {
		if typ != "AWS::EC2::SecurityGroupIngress" {
			return
		}
		p["GroupName"] = groupName(p["GroupId"].(string))
		if src, ok := p["SourceSecurityGroupId"].(string); ok {
			p["SourceSecurityGroupName"], p["SourceSecurityGroupOwnerId"] = groupName(src), f.ID
		}
	}
	rule := func(typ, group string, r map[string]any) {
		p := deepCopy(r)
		p["GroupId"] = group
		f.w.mu.Lock()
		readBack(typ, p)
		f.w.mu.Unlock()
		f.Seed(typ, p)
	}
	allOut := map[string]any{"IpProtocol": "-1", "FromPort": -1, "ToPort": -1, "CidrIp": "0.0.0.0/0"}
	f.AfterCreate = func(typ string, props map[string]any) {
		switch typ {
		case "AWS::EC2::VPC":
			sg := f.Seed("AWS::EC2::SecurityGroup", map[string]any{"GroupName": "default", "GroupDescription": "default VPC security group", "VpcId": props["VpcId"]})
			self := map[string]any{"IpProtocol": "-1", "FromPort": -1, "ToPort": -1, "SourceSecurityGroupId": sg}
			f.w.mu.Lock()
			g := f.res["AWS::EC2::SecurityGroup"][sg]
			inline := deepCopy(self)
			inline["SourceSecurityGroupOwnerId"] = f.ID
			g["GroupId"], g["SecurityGroupIngress"], g["SecurityGroupEgress"] = sg, []any{inline}, []any{allOut}
			props["DefaultSecurityGroup"] = sg
			f.w.mu.Unlock()
			rule("AWS::EC2::SecurityGroupIngress", sg, self)
			rule("AWS::EC2::SecurityGroupEgress", sg, allOut)
		case "AWS::EC2::SecurityGroup":
			f.w.mu.Lock()
			props["GroupId"] = props["Id"]
			if props["SecurityGroupEgress"] == nil {
				props["SecurityGroupEgress"] = []any{allOut}
			}
			in, _ := props["SecurityGroupIngress"].([]any)
			out, _ := props["SecurityGroupEgress"].([]any)
			f.w.mu.Unlock()
			for _, r := range in {
				rule("AWS::EC2::SecurityGroupIngress", props["Id"].(string), r.(map[string]any))
			}
			for _, r := range out {
				rule("AWS::EC2::SecurityGroupEgress", props["Id"].(string), r.(map[string]any))
			}
		case "AWS::EC2::SecurityGroupIngress":
			// A rule added on its own shows on its group too.
			f.w.mu.Lock()
			g := f.res["AWS::EC2::SecurityGroup"][props["GroupId"].(string)]
			r := deepCopy(props)
			delete(r, "GroupId")
			delete(r, "Id")
			in, _ := g["SecurityGroupIngress"].([]any)
			g["SecurityGroupIngress"] = append(in, r)
			readBack(typ, props)
			f.w.mu.Unlock()
		}
	}
	f.Validate = func(typ string, desired map[string]any) error {
		if typ != "AWS::EC2::SecurityGroupIngress" && typ != "AWS::EC2::SecurityGroupEgress" {
			return nil
		}
		refused := errors.New(typ + " create FAILED: InternalFailure Resource Handler Internal Failure")
		if desired["GroupId"] != nil && desired["GroupName"] != nil {
			return refused
		}
		if o, ok := desired["SourceSecurityGroupOwnerId"]; ok && o != f.ID {
			return fmt.Errorf("%s: source group owner %v is not this account", typ, o)
		}
		ruleKey := func(p map[string]any) string {
			return fmt.Sprint(p["GroupId"], p["IpProtocol"], p["FromPort"], p["ToPort"], p["CidrIp"], p["SourceSecurityGroupId"])
		}
		for _, have := range f.res[typ] {
			if ruleKey(have) == ruleKey(desired) {
				return refused
			}
		}
		return nil
	}
	return f
}

// Every security group rule is listed twice, inline and as its own
// resource, and AWS creates rules with VPCs and groups. A restore must
// recognise the copies AWS made instead of failing on them, and still
// restore a rule someone added to the default group.
func TestSecurityGroupRulesRestoreOnce(t *testing.T) {
	reg := fixtures(t)
	w := NewWorld(reg)
	src, dst := sgAccount(w, srcAccount), sgAccount(w, dstAccount)
	vpc := mustCreate(t, src, "AWS::EC2::VPC", map[string]any{"CidrBlock": "10.42.0.0/16", "Tags": tags("Name", "app")})
	mustCreate(t, src, "AWS::EC2::SecurityGroup", map[string]any{"GroupName": "web", "GroupDescription": "web", "VpcId": vpc["VpcId"],
		"SecurityGroupIngress": []any{map[string]any{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIp": "10.42.0.0/16"}}})
	mustCreate(t, src, "AWS::EC2::SecurityGroupIngress", map[string]any{"GroupId": vpc["DefaultSecurityGroup"],
		"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "10.0.0.0/8"})

	ad := func(f *Fake) *Adapter { return &Adapter{API: f, Registry: reg, Region: region} }
	snap, err := ad(src).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range ad(dst).Restore(context.Background(), snap) {
		if !r.OK {
			t.Errorf("%s: %s", r.Key, r.Detail)
		}
	}
	got, err := ad(dst).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ch := snapshot.Compare(snap, got); len(ch) > 0 {
		t.Errorf("target differs from the snapshot: %+v", ch)
	}
	for _, o := range snap.Objects {
		if s := canon(o.Body["spec"]); strings.Contains(s, srcAccount) {
			t.Errorf("%s names the source account: %s", o.Key(), s)
		}
	}
	n := 0
	for _, id := range dst.IDs("AWS::EC2::SecurityGroupIngress") {
		if p := dst.Stored("AWS::EC2::SecurityGroupIngress", id); fmt.Sprint(p["FromPort"]) == "22" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("rule added to the default group restored %d times, want 1", n)
	}
}

// A resource created but not yet readable is waited for, not reported as
// a failure.
func TestReadBackWaitsForEventualConsistency(t *testing.T) {
	step, limit := readBackStep, readBackLimit
	readBackStep, readBackLimit = time.Millisecond, time.Second
	defer func() { readBackStep, readBackLimit = step, limit }()
	e := newEnv(t)
	snap, err := e.adapter(e.src).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	e.dst.ReadLag = 3
	for _, r := range e.adapter(e.dst).Restore(context.Background(), snap) {
		if !r.OK {
			t.Errorf("%s: %s", r.Key, r.Detail)
		}
	}
}

// The account is replaced where it is structural, never inside prose.
func TestAccountTokenIsStructural(t *testing.T) {
	reg := fixtures(t)
	r := normalize(reg.Types["AWS::SSM::Parameter"], "/p", map[string]any{"Name": "/p", "Type": "String",
		"Value": `{"principal":"arn:aws:iam::111111111111:root","owner":"111111111111"}`})
	r.spec["DataType"] = "111111111111"
	r.spec["Description"] = "ticket 111111111111 closed"
	accountize(r, "111111111111")
	if want := `{"principal":"arn:aws:iam::` + accountToken + `:root","owner":"111111111111"}`; r.spec["Value"] != want {
		t.Errorf("ARN inside a JSON string: got %v", r.spec["Value"])
	}
	if r.spec["DataType"] != accountToken {
		t.Errorf("whole value: got %v", r.spec["DataType"])
	}
	if r.spec["Description"] != "ticket 111111111111 closed" {
		t.Errorf("prose rewritten: %v", r.spec["Description"])
	}
}

// A generated ID that is a whole value inside a document kept as JSON text
// (a policy naming a VPC in a condition) is a reference too: a translation
// writes a token there, and a capture of what its restore made must read
// the same. A chosen name inside such a document stays a word, and so does
// an ID inside prose.
func TestGeneratedIDInJSONTextIsAReference(t *testing.T) {
	reg := fixtures(t)
	vpc := normalize(reg.Types["AWS::EC2::VPC"], "vpc-0def5678", map[string]any{
		"VpcId": "vpc-0def5678", "CidrBlock": "10.42.0.0/16",
		"Tags": []any{map[string]any{"Key": "Name", "Value": "shop"}}})
	repo := normalize(reg.Types["AWS::ECR::Repository"], "images", map[string]any{
		"RepositoryName": "images", "Arn": "arn:aws:ecr:us-east-2:111111111111:repository/images"})
	doc := normalize(reg.Types["AWS::SSM::Parameter"], "policy", map[string]any{
		"Name": "policy", "Type": "String", "Value": `{"Condition":{"StringNotEquals":{"aws:SourceVpc":["vpc-0def5678"]}},"Note":"images"}`})
	prose := normalize(reg.Types["AWS::SSM::Parameter"], "note", map[string]any{
		"Name": "note", "Type": "String", "Value": `see "vpc-0def5678"`})
	name([]*resource{vpc, repo, doc, prose}, "")
	got, _ := doc.spec["Value"].(string)
	a := `{"Condition":{"StringNotEquals":{"aws:SourceVpc":["` + refToken("AWS::EC2::VPC", "shop", "VpcId") + `"]}},"Note":"images"}`
	b := `{"Condition":{"StringNotEquals":{"aws:SourceVpc":["` + refToken("AWS::EC2::VPC", "shop", "identifier") + `"]}},"Note":"images"}`
	if got != a && got != b {
		t.Errorf("JSON text: %s", got)
	}
	if v := prose.spec["Value"]; v != `see "vpc-0def5678"` {
		t.Errorf("prose rewritten: %v", v)
	}
}
