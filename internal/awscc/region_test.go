package awscc

import (
	"context"
	"strings"
	"testing"

	"github.com/stackdna/core/internal/snapshot"
)

const otherRegion = "us-west-2"

// crossRegion captures the shop in one region and returns it with a target
// account in another region, holding that region's default VPC, and a
// policy carrying both regions' baselines (their default subnets sit in
// different zones, so each region's own are skipped).
func crossRegion(t *testing.T) (env, snapshot.Snapshot, *Fake, Policy) {
	e := newEnv(t)
	fresh := newAccountIn(NewWorld(e.reg), "444444444444", otherRegion)
	defaultVPC(fresh)
	base2, err := Capture(context.Background(), fresh, e.reg, otherRegion, Policy{}, Tuning{})
	if err != nil {
		t.Fatal(err)
	}
	pol := e.pol.WithBaseline(base2, "sha256:test-baseline-2")
	src := e.adapter(e.src)
	src.Policy = pol
	snap, err := src.Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dst := newAccountIn(e.src.w, "555555555555", otherRegion)
	defaultVPC(dst)
	return e, snap, dst, pol
}

func (e env) adapterIn(f *Fake, region string, p Policy) *Adapter {
	a := e.adapter(f)
	a.Region, a.Policy = region, p
	return a
}

// A snapshot captured in one region restores into another: zones are paired
// in zone-ID order, the region in values and ARNs follows, and the target
// then matches the snapshot retargeted the same way.
func TestCrossRegionRestore(t *testing.T) {
	e, snap, dst, pol := crossRegion(t)
	a := e.adapterIn(dst, otherRegion, pol)
	for _, r := range a.Restore(context.Background(), snap) {
		if !r.OK {
			t.Errorf("%s: %s", r.Key, r.Detail)
		}
	}
	want, notes, err := a.ForRegion(context.Background(), snap)
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) == 0 || notes[0] != region+" -> "+otherRegion || !strings.Contains(strings.Join(notes, "\n"), "use1-az1 (us-east-1a) -> usw2-az1 (us-west-2a)") {
		t.Errorf("mapping notes %v", notes)
	}
	got, err := a.Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range snapshot.Compare(want, got) {
		t.Errorf("target differs from the retargeted snapshot: %+v", c)
	}
	for _, o := range want.Objects {
		if s := canon(o.Body["spec"]); strings.Contains(s, "use1-") || strings.Contains(s, region) {
			t.Errorf("%s still names the source region: %s", o.Key(), s)
		}
	}
}

// An explicit pairing overrides the default one.
func TestCrossRegionZoneMap(t *testing.T) {
	e, snap, dst, pol := crossRegion(t)
	a := e.adapterIn(dst, otherRegion, pol)
	a.ZoneMap = map[string]string{"use1-az1": "usw2-az3"}
	for _, r := range a.Restore(context.Background(), snap) {
		if !r.OK {
			t.Errorf("%s: %s", r.Key, r.Detail)
		}
	}
	for _, id := range dst.IDs("AWS::EC2::Subnet") {
		if p := dst.Stored("AWS::EC2::Subnet", id); baseName(e.reg.Types["AWS::EC2::Subnet"], p) == "app" && p["AvailabilityZoneId"] != "usw2-az3" {
			t.Errorf("app subnet in %v, want the mapped usw2-az3", p["AvailabilityZoneId"])
		}
	}
}

// A zone with no counterpart refuses the whole restore before anything is
// sent, naming what uses it.
func TestCrossRegionMissingZoneRefusesEverything(t *testing.T) {
	e, snap, dst, pol := crossRegion(t)
	// The source region lists more zones than the target, and the shop's
	// zone sorts past the target's count, as a subnet in the sixth zone of
	// a six-zone region would when restored into a three-zone one.
	dst.RegionZones = map[string][]Zone{
		region:      {{Name: "us-east-1x", ID: "use1-az0"}, {Name: "us-east-1y", ID: "use1-az00"}, {Name: "us-east-1a", ID: "use1-az1"}},
		otherRegion: fakeZones(otherRegion)[:2],
	}
	before := dst.Count()
	for _, r := range e.adapterIn(dst, otherRegion, pol).Restore(context.Background(), snap) {
		if r.OK || !strings.Contains(r.Detail, "no counterpart for") {
			t.Errorf("%s: ok=%v %s", r.Key, r.OK, r.Detail)
		}
	}
	if canon(dst.Count()) != canon(before) {
		t.Errorf("resources were created although the restore was refused: %v -> %v", before, dst.Count())
	}
}

// The region is rewritten where it is structural, never inside prose.
func TestRetargetRegionIsStructural(t *testing.T) {
	s := snapshot.Snapshot{ServerVersion: "cloudcontrol/us-east-1", Objects: []snapshot.Object{{Body: map[string]any{
		"apiVersion": APIVersion, "kind": "AWS::SSM::Parameter", "metadata": map[string]any{"name": "/p"},
		"spec": map[string]any{"Value": `{"topic":"arn:aws:sns:us-east-1:111111111111:alerts"}`, "Region": "us-east-1", "Description": "moved from us-east-1 last year"},
	}}}}
	got, _, err := Retarget(s, "us-west-2", fakeZones("us-east-1"), fakeZones("us-west-2"), nil)
	if err != nil {
		t.Fatal(err)
	}
	spec := got.Objects[0].Body["spec"].(map[string]any)
	if spec["Value"] != `{"topic":"arn:aws:sns:us-west-2:111111111111:alerts"}` || spec["Region"] != "us-west-2" || spec["Description"] != "moved from us-east-1 last year" {
		t.Errorf("got %v", spec)
	}
	if got.ServerVersion != "cloudcontrol/us-west-2" || s.Objects[0].Body["spec"].(map[string]any)["Region"] != "us-east-1" {
		t.Error("retarget must label the copy and leave the original alone")
	}
}
