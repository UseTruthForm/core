package awscc

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A Route 53 record set is identified by its name, zone, type and
// SetIdentifier, and a simple record has no SetIdentifier. The fake
// creates it without one, invents none, and a capture names it by its own
// name, the same in every account.
func TestCompoundIdentifierWithAPartLeftOut(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"aws-route53-hostedzone.json", "aws-route53-recordset.json"} {
		b, err := os.ReadFile(filepath.Join("..", "translate", "testdata", "aws", n))
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dir, n), b, 0o644)
	}
	reg, err := ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	f := NewWorld(reg).Account("111111111111", "eu-west-1")
	ctx := context.Background()
	zone, err := f.Create(ctx, "AWS::Route53::HostedZone", map[string]any{"Name": "shop.example."})
	if err != nil {
		t.Fatal(err)
	}
	zid := f.Stored("AWS::Route53::HostedZone", zone)["Id"].(string)
	id, err := f.Create(ctx, "AWS::Route53::RecordSet", map[string]any{"HostedZoneId": zid, "Name": "www.shop.example.", "Type": "A", "TTL": "60", "ResourceRecords": []any{"192.0.2.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if id != "www.shop.example.|"+zid+"|A|" {
		t.Errorf("identifier %q", id)
	}
	if _, set := f.Stored("AWS::Route53::RecordSet", id)["SetIdentifier"]; set {
		t.Error("the fake invented a SetIdentifier")
	}
	if _, err := f.Create(ctx, "AWS::Route53::RecordSet", map[string]any{"HostedZoneId": zid, "Name": "www.shop.example.", "Type": "A", "TTL": "60", "ResourceRecords": []any{"192.0.2.2"}}); err == nil {
		t.Error("a second set of one name and type was created")
	}
	s, err := Capture(ctx, f, reg, "eu-west-1", Policy{}, Tuning{})
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, o := range s.Objects {
		names[o.Kind()+"/"+o.Name()] = true
	}
	if !names["AWS::Route53::RecordSet/www.shop.example."] || !names["AWS::Route53::HostedZone/shop.example."] {
		t.Errorf("captured as %v", names)
	}
}
