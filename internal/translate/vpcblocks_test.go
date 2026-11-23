package translate

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/awscc"
	"github.com/usetruthform/core/internal/snapshot"
)

func TestVPCBlocks(t *testing.T) {
	for in, want := range map[string]string{
		"10.20.0.0/16":              "10.20.0.0/16",
		"10.20.3.0/24":              "10.20.3.0/24",
		"10.20.3.7/24":              "10.20.3.0/24",
		"10.0.0.0/15":               "10.0.0.0/16, 10.1.0.0/16",
		"10.4.0.0/14":               "10.4.0.0/16, 10.5.0.0/16, 10.6.0.0/16, 10.7.0.0/16",
		"10.20.0.0/16 10.30.0.0/24": "10.20.0.0/16, 10.30.0.0/24",
		"10.30.0.0/24 10.20.0.0/16": "10.20.0.0/16, 10.30.0.0/24",
		// A block of 10.0.0.0/16 is added to no VPC that has one of
		// 10.0.0.0/15, so it is the first.
		"10.1.0.0/16 10.0.5.0/24": "10.0.5.0/24, 10.1.0.0/16",
		"10.9.0.0/16 10.0.5.0/24": "10.0.5.0/24, 10.9.0.0/16",
		// As is one of 172.31.0.0/16.
		"172.20.0.0/16 172.31.0.0/20": "172.31.0.0/20, 172.20.0.0/16",
		// A private block is added to no VPC created with a public one.
		"100.64.0.0/16 10.20.0.0/16":     "10.20.0.0/16, 100.64.0.0/16",
		"52.0.0.0/20 192.168.4.0/24":     "192.168.4.0/24, 52.0.0.0/20",
		"100.64.0.0/16 100.65.0.0/16":    "100.64.0.0/16, 100.65.0.0/16",
		"198.19.0.0/20 100.64.0.0/16":    "198.19.0.0/20, 100.64.0.0/16",
		"192.168.0.0/20 192.168.64.0/20": "192.168.0.0/20, 192.168.64.0/20",
	} {
		var ps []netip.Prefix
		for _, s := range strings.Fields(in) {
			ps = append(ps, netip.MustParsePrefix(s))
		}
		got, why := vpcBlocks(ps)
		if why != "" || prefixList(got) != want {
			t.Errorf("%s: %s (%s), want %s", in, prefixList(got), why, want)
		}
	}
	for in, part := range map[string]string{
		"10.20.0.0/29":                 "narrower than a VPC block",
		"10.0.0.0/8":                   "more than 50 blocks",
		"10.0.0.0/9":                   "more than 50 blocks",
		"10.0.0.0/10":                  "64 blocks",
		"10.20.0.0/16 172.20.0.0/16":   "more than one of",
		"192.168.0.0/24 10.0.0.0/24":   "more than one of",
		"198.19.0.0/24 10.20.0.0/16":   "198.19.0.0/16 and a private range",
		"198.19.0.0/24 198.19.1.0/24":  "can each only be the block a VPC is created with",
		"10.0.0.0/24 10.0.1.0/24":      "can each only be the block a VPC is created with",
		"172.31.0.0/20 172.31.16.0/20": "can each only be the block a VPC is created with",
		"10.20.0.0/16 10.20.4.0/24":    "overlap",
		"127.0.0.0/16":                 "which no VPC takes",
		"169.254.0.0/16":               "which no VPC takes",
		"0.0.0.0/16":                   "which no VPC takes",
		"224.1.0.0/16":                 "which no VPC takes",
	} {
		var ps []netip.Prefix
		for _, s := range strings.Fields(in) {
			ps = append(ps, netip.MustParsePrefix(s))
		}
		if got, why := vpcBlocks(ps); !strings.Contains(why, part) || got != nil {
			t.Errorf("%s: %v, %q; want a refusal that says %q", in, got, why, part)
		}
	}
	blocks := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16"), netip.MustParsePrefix("10.1.0.0/16")}
	if b, ok := vpcBlockOf(blocks, netip.MustParsePrefix("10.1.4.0/24")); !ok || b != blocks[1] {
		t.Errorf("a subnet's block: %v %v", b, ok)
	}
	// A subnet across two blocks is in neither.
	if _, ok := vpcBlockOf(blocks, netip.MustParsePrefix("10.0.0.0/15")); ok {
		t.Error("a subnet as wide as the two blocks was put in one")
	}
}

func wideFixture(space []any, subnets map[string]string) snapshot.Snapshot {
	var subs []any
	for _, n := range sortedKeys(subnets) {
		subs = append(subs, map[string]any{"name": n, "properties": map[string]any{"addressPrefix": subnets[n], "defaultOutboundAccess": false}})
	}
	return snapshot.Snapshot{Platform: "azure", Policy: "default", Objects: []snapshot.Object{
		az("Microsoft.Network/virtualNetworks", "net", "wide", map[string]any{"location": "westeurope",
			"properties": map[string]any{"addressSpace": map[string]any{"addressPrefixes": space}, "subnets": subs}}),
	}}
}

// A network wider than a VPC's one block, with a second range besides,
// is a VPC with the rest of its addresses added as blocks, and restores:
// a subnet in an added block is created after the block is associated.
func TestAWideNetworkIsAVPCOfSeveralBlocks(t *testing.T) {
	tg := targets(t)
	src := wideFixture([]any{"10.0.0.0/15", "10.9.0.0/24"}, map[string]string{"a": "10.0.1.0/24", "b": "10.1.1.0/24", "c": "10.9.0.0/25"})
	r, err := Translate(src, netMaps()["aws"], tg)
	if err != nil {
		t.Fatal(err)
	}
	e := entry(t, r, "Microsoft.Network/virtualNetworks net/wide")
	if e.State != WithLosses {
		t.Fatalf("%s %s", e.State, e.Reason)
	}
	l := lossAbout(e, "addressPrefixes")
	if l == nil || l.Widens || !strings.Contains(l.Why, "10.0.0.0/16, 10.1.0.0/16, 10.9.0.0/24") {
		t.Errorf("the blocks are not named, or named as a widening: %+v", l)
	}
	s := r.Snapshots["aws"]
	var vpcBlock string
	added := map[string]bool{}
	for _, o := range s.Objects {
		sp, _ := o.Body["spec"].(map[string]any)
		switch o.Kind() {
		case awsVPC:
			vpcBlock, _ = sp["CidrBlock"].(string)
		case awsVPCBlock:
			added[sp["CidrBlock"].(string)] = true
			if sp["VpcId"] != awsRef(awsVPC, "wide", "VpcId") {
				t.Errorf("a block of another VPC: %v", sp["VpcId"])
			}
		}
	}
	if vpcBlock != "10.0.0.0/16" || len(added) != 2 || !added["10.1.0.0/16"] || !added["10.9.0.0/24"] {
		t.Errorf("created with %s, added %v", vpcBlock, added)
	}
	// Several at a time, many times: the order is the restore's, not luck.
	for i := 0; i < 20; i++ {
		f := awscc.NewWorld(tg.AWS).Account("111111111111", "eu-west-1")
		for _, res := range awscc.Restore(context.Background(), f, tg.AWS, s, awscc.RestoreOptions{}, awscc.Tuning{Parallel: 8}) {
			if !res.OK {
				t.Fatalf("run %d: %s: %s", i, res.Key, res.Detail)
			}
		}
		if c := f.Count(); c[awsVPC] != 1 || c[awsVPCBlock] != 2 || c[awsSN] != 3 {
			t.Fatalf("created %v", c)
		}
		if i > 0 {
			continue
		}
		for _, res := range awscc.Restore(context.Background(), f, tg.AWS, s, awscc.RestoreOptions{}, awscc.Tuning{}) {
			if !res.OK || res.Detail != "already present and identical" {
				t.Errorf("again: %s: %v %s", res.Key, res.OK, res.Detail)
			}
		}
		if c := f.Count(); c[awsVPCBlock] != 2 {
			t.Errorf("a second restore added blocks: %v", c)
		}
	}
	// More blocks than the default quota: said, not refused.
	r, err = Translate(wideFixture([]any{"10.8.0.0/13"}, map[string]string{"a": "10.8.1.0/24"}), netMaps()["aws"], tg)
	if err != nil {
		t.Fatal(err)
	}
	if e := entry(t, r, "Microsoft.Network/virtualNetworks net/wide"); e.State != WithLosses || !anyRequirement(r, "has 8 IPv4 CIDR blocks: raise the account's quota") {
		t.Errorf("eight blocks: %s %s %v", e.State, e.Reason, r.Report.Requirements)
	}
	// A network AWS takes no VPC of is refused with why, and a subnet
	// wider than a block too.
	for space, part := range map[string]string{"10.0.0.0/8": "more than 50 blocks", "10.20.0.0/29": "narrower than a VPC block"} {
		r, err := Translate(wideFixture([]any{space}, map[string]string{"a": "10.20.0.0/29"}), netMaps()["aws"], tg)
		if err != nil {
			t.Fatal(err)
		}
		if e := entry(t, r, "Microsoft.Network/virtualNetworks net/wide"); e.State != Refused || !strings.Contains(e.Reason, part) {
			t.Errorf("%s: %s %q", space, e.State, e.Reason)
		}
	}
	r, err = Translate(wideFixture([]any{"10.0.0.0/15"}, map[string]string{"all": "10.0.0.0/15"}), netMaps()["aws"], tg)
	if err != nil {
		t.Fatal(err)
	}
	if e := entry(t, r, "Microsoft.Network/virtualNetworks net/wide"); e.State != Refused || !strings.Contains(e.Reason, "inside one of the VPC's blocks (10.0.0.0/16, 10.1.0.0/16)") {
		t.Errorf("a subnet across blocks: %s %q", e.State, e.Reason)
	}
	// GCP has no such limit: one network, as before.
	r, err = Translate(src, netMaps()["gcp"], tg)
	if err != nil {
		t.Fatal(err)
	}
	if e := entry(t, r, "Microsoft.Network/virtualNetworks net/wide"); e.State == Refused {
		t.Errorf("gcp: %s", e.Reason)
	}
}
