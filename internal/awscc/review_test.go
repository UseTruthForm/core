package awscc

import (
	"context"
	"strings"
	"testing"

	"github.com/stackdna/core/internal/snapshot"
)

// Failures from the review of #14 to #16, 2026-10-22.

// A REST API named like an ECR repository keeps its own Name: a value
// equal to the resource's own name is not a reference to a namesake.
func TestOwnNameIsNotAReference(t *testing.T) {
	reg := fixtures(t)
	repo := normalize(reg.Types["AWS::ECR::Repository"], "stackdna-drill", map[string]any{"RepositoryName": "stackdna-drill"})
	api := normalize(reg.Types["AWS::ApiGateway::RestApi"], "abc123", map[string]any{"RestApiId": "abc123", "Name": "stackdna-drill"})
	name([]*resource{repo, api}, "")
	if api.spec["Name"] != "stackdna-drill" {
		t.Errorf("Name became %v", api.spec["Name"])
	}
}

// Sets resolved out of order are not a change: the update compares them
// sorted, as the live side is, and sends nothing.
func TestUpdateComparesSetsSorted(t *testing.T) {
	reg := fixtures(t)
	f := NewWorld(reg).Account(srcAccount, region)
	id, err := f.Create(context.Background(), "AWS::SQS::Queue", map[string]any{"QueueName": "q",
		"Tags": []any{map[string]any{"Key": "a", "Value": "1"}, map[string]any{"Key": "b", "Value": "2"}}})
	if err != nil {
		t.Fatal(err)
	}
	ex := normalize(reg.Types["AWS::SQS::Queue"], id, f.Stored("AWS::SQS::Queue", id))
	desired := map[string]any{"QueueName": "q", "Tags": []any{map[string]any{"Key": "b", "Value": "2"}, map[string]any{"Key": "a", "Value": "1"}}}
	ok, detail := update(context.Background(), f, reg.Types["AWS::SQS::Queue"], "AWS::SQS::Queue/q", ex, desired, map[string]map[string]any{})
	if !ok || f.Updates != 0 {
		t.Errorf("reordered tags sent an update: ok=%v %s (%d updates)", ok, detail, f.Updates)
	}
}

// A create-only field that is also write-only is never read back, so a
// value supplied for it is no replacement.
func TestWriteOnlyCreateOnlyIsNotCompared(t *testing.T) {
	ty := &TypeInfo{Name: "X::Y::Z", CreateOnly: []string{"/properties/Secret"}, WriteOnly: []string{"/properties/Secret"}}
	if ch := createOnlyChanges(ty, map[string]any{}, map[string]any{"Secret": "s"}); len(ch) > 0 {
		t.Errorf("got %v", ch)
	}
}

func volume(az string) snapshot.Snapshot {
	return snapshot.Snapshot{ServerVersion: "cloudcontrol/us-east-1", Objects: []snapshot.Object{{Body: map[string]any{
		"apiVersion": APIVersion, "kind": "AWS::EC2::Volume", "metadata": map[string]any{"name": "data"},
		"spec": map[string]any{"AvailabilityZone": az, "Size": 8}}}}}
}

// A zone with no counterpart is refused whether a resource names it by ID
// or by name (a volume's AvailabilityZone).
func TestUnmappedZoneByName(t *testing.T) {
	four := append(fakeZones("us-east-1"), Zone{Name: "us-east-1d", ID: "use1-az4"})
	if _, _, err := Retarget(volume("us-east-1d"), "us-west-2", four, fakeZones("us-west-2"), nil); err == nil || !strings.Contains(err.Error(), "us-east-1d") {
		t.Errorf("volume in an unmapped zone, by name: %v", err)
	}
}

// An explicit pair takes its target out of the default pairing, so two
// zones never become one; and an entry that names no source zone is
// refused, not dropped.
func TestZoneMapIsExclusiveAndChecked(t *testing.T) {
	s := snapshot.Snapshot{ServerVersion: "cloudcontrol/us-east-1", Objects: []snapshot.Object{
		volume("us-east-1a").Objects[0], {Body: map[string]any{"apiVersion": APIVersion, "kind": "AWS::EC2::Volume",
			"metadata": map[string]any{"name": "other"}, "spec": map[string]any{"AvailabilityZone": "us-east-1c"}}}}}
	got, _, err := Retarget(s, "us-west-2", fakeZones("us-east-1"), fakeZones("us-west-2"), map[string]string{"use1-az1": "usw2-az3"})
	if err != nil {
		t.Fatal(err)
	}
	a := got.Objects[0].Body["spec"].(map[string]any)["AvailabilityZone"]
	b := got.Objects[1].Body["spec"].(map[string]any)["AvailabilityZone"]
	if a != "us-west-2c" || b == a {
		t.Errorf("zones %v and %v: the mapped one must be usw2-az3 and the other elsewhere", a, b)
	}
	for _, bad := range []map[string]string{{"us-east-1a": "usw2-az3"}, {"use1-az9": "usw2-az1"}, {"use1-az1": "usw2-az9"}} {
		if _, _, err := Retarget(volume("us-east-1a"), "us-west-2", fakeZones("us-east-1"), fakeZones("us-west-2"), bad); err == nil || !strings.Contains(err.Error(), "zone map") {
			t.Errorf("zone map %v accepted", bad)
		}
	}
}

// A regional endpoint's host follows the region: an ECR image, a service
// principal.
func TestRetargetRegionalHosts(t *testing.T) {
	s := snapshot.Snapshot{ServerVersion: "cloudcontrol/us-east-1", Objects: []snapshot.Object{{Body: map[string]any{
		"apiVersion": APIVersion, "kind": "AWS::ECS::TaskDefinition", "metadata": map[string]any{"name": "t"},
		"spec": map[string]any{"Image": "111111111111.dkr.ecr.us-east-1.amazonaws.com/app:1", "Principal": "logs.us-east-1.amazonaws.com"}}}}}
	got, _, err := Retarget(s, "us-west-2", fakeZones("us-east-1"), fakeZones("us-west-2"), nil)
	if err != nil {
		t.Fatal(err)
	}
	spec := got.Objects[0].Body["spec"].(map[string]any)
	if spec["Image"] != "111111111111.dkr.ecr.us-west-2.amazonaws.com/app:1" || spec["Principal"] != "logs.us-west-2.amazonaws.com" {
		t.Errorf("got %v", spec)
	}
}
