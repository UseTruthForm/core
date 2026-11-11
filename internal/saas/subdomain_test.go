package saas

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

// dnsZone is one Cloudflare account with example.com as a first
// environment has it: an apex and a wildcard on the environment's
// address, a per-service wildcard, a CNAME out of the zone, and mail.
func dnsZone(t *testing.T) (*fake, string) {
	t.Helper()
	f := newFake(t, Cloudflare, spec(t, "cloudflare.json"), "acct-1111")
	cloudflare(f)
	zone := f.seed(t, "/zones", map[string]any{"name": "example.com", "type": "full", "account": map[string]any{"id": "acct-1111"}})
	zid := stringOf(zone["id"])
	for _, r := range []map[string]any{
		{"type": "A", "name": "example.com", "content": "192.0.2.1", "ttl": 1, "proxied": false},
		{"type": "A", "name": "*.example.com", "content": "192.0.2.1", "ttl": 1, "proxied": false},
		{"type": "CNAME", "name": "*.auth.example.com", "content": "auth.example.com", "ttl": 1, "proxied": false},
		{"type": "CNAME", "name": "docs.example.com", "content": "pages.example.net", "ttl": 300, "proxied": true},
		{"type": "MX", "name": "example.com", "content": "mx1.mail.example.net", "priority": 10, "ttl": 1, "proxied": false},
		{"type": "TXT", "name": "example.com", "content": "\"v=spf1 include:mail.example.net -all\"", "ttl": 1, "proxied": false},
		{"type": "TXT", "name": "_dmarc.example.com", "content": "\"v=DMARC1; p=none\"", "ttl": 1, "proxied": false},
		{"type": "CNAME", "name": "sel1._domainkey.example.com", "content": "sel1.dkim.example.net", "ttl": 1, "proxied": false},
		{"type": "NS", "name": "lab.example.com", "content": "ns1.example.net", "ttl": 1, "proxied": false},
	} {
		f.seed(t, "/zones/"+zid+"/dns_records", r)
	}
	return f, zid
}

func capture(t *testing.T, f *fake) snapshot.Snapshot {
	t.Helper()
	s, err := (&Adapter{Client: f.client(true)}).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func names(s snapshot.Snapshot) []string {
	var out []string
	for _, o := range s.Objects {
		out = append(out, o.Name())
	}
	return out
}

// The records go one level down in the same zone, names and in-zone
// CNAME targets alike, each with the mark and the target's address; mail
// and a delegation stay out.
func TestASubdomainPutsTheZoneOneLevelDown(t *testing.T) {
	f, _ := dnsZone(t)
	d := &Subdomain{Name: "Test.Example.com.", Addresses: map[string]string{"192.0.2.1": "198.51.100.7"}, Targets: map[string]string{"pages.example.net": "pages-test.example.net"}}
	got, left, err := d.Map(capture(t, f))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"example.com/A *.test.example.com 198.51.100.7",
		"example.com/A test.example.com 198.51.100.7",
		"example.com/CNAME *.auth.test.example.com auth.test.example.com",
		"example.com/CNAME docs.test.example.com pages-test.example.net",
		"example.com",
	}
	if !slices.Equal(names(got), want) {
		t.Errorf("mapped\n %v\nwant\n %v", names(got), want)
	}
	for _, o := range got.Objects {
		if spec, _ := o.Body["spec"].(map[string]any); o.Kind() == recordKind && spec["comment"] != "truthform: test.example.com" {
			t.Errorf("%s: comment %v, not the mark", o.Name(), spec["comment"])
		}
	}
	why := map[string]string{}
	for _, l := range left {
		why[l.Name] = l.Reason
	}
	for _, n := range []string{"MX example.com", "TXT example.com", "TXT _dmarc.example.com", "CNAME sel1._domainkey.example.com"} {
		if !strings.Contains(why[n], "mail") {
			t.Errorf("%s: left out as %q, want mail", n, why[n])
		}
	}
	if !strings.Contains(why["NS lab.example.com"], "delegation") {
		t.Errorf("NS left out as %q, want a delegation", why["NS lab.example.com"])
	}
	if len(left) != 5 {
		t.Errorf("left out %d, want 5: %v", len(left), left)
	}
}

func TestASubdomainMustBeBelowAZoneInTheSnapshot(t *testing.T) {
	f, _ := dnsZone(t)
	for _, n := range []string{"example.com", "test.example.org", "*.test.example.com", ""} {
		if _, _, err := (&Subdomain{Name: n}).Map(capture(t, f)); err == nil {
			t.Errorf("--subdomain %q accepted", n)
		}
	}
}

func subRestore(f *fake, d *Subdomain, mapped snapshot.Snapshot, opt RestoreOptions) []snapshot.Result {
	opt.Present = map[string]bool{zoneKind: true}
	opt.Allow = d.Allow
	return (&Adapter{Client: f.client(opt.DryRun), Options: opt}).Restore(context.Background(), mapped)
}

// A restore into the zone it came from creates the new records and
// nothing else: the first environment's records and the zone are as they
// were, a second run writes nothing, and a diff of the subdomain is clean.
func TestASubdomainRestoreLeavesTheSourceRecordsAlone(t *testing.T) {
	f, _ := dnsZone(t)
	before := capture(t, f)
	d := &Subdomain{Name: "test.example.com", Addresses: map[string]string{"192.0.2.1": "198.51.100.7"}}
	mapped, _, err := d.Map(before)
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := d.Check(mapped, before); len(c) > 0 {
		t.Fatalf("conflicts in an empty subdomain: %v", c)
	}
	f.writes = 0
	for _, r := range subRestore(f, d, mapped, RestoreOptions{}) {
		if !r.OK {
			t.Errorf("%s: %s", r.Key, r.Detail)
		}
	}
	if f.writes != 4 {
		t.Errorf("%d writes, want the 4 records", f.writes)
	}
	after := capture(t, f)
	for _, o := range before.Objects {
		if !slices.Contains(names(after), o.Name()) {
			t.Errorf("%s gone after the restore", o.Name())
		}
	}
	var kept snapshot.Snapshot
	kept.Objects = slices.DeleteFunc(slices.Clone(after.Objects), func(o snapshot.Object) bool {
		return under(o.Name(), "test.example.com") || strings.Contains(o.Name(), "test.example.com ")
	})
	if ch := snapshot.Compare(before, kept); len(ch) > 0 {
		t.Errorf("the source's records changed: %+v", ch)
	}
	f.writes = 0
	for _, r := range subRestore(f, d, mapped, RestoreOptions{Update: true}) {
		if !r.OK {
			t.Errorf("again: %s: %s", r.Key, r.Detail)
		}
	}
	if f.writes != 0 {
		t.Errorf("a second restore wrote %d times", f.writes)
	}
	if ch := snapshot.Compare(mapped, d.Scope(after)); len(ch) > 0 {
		t.Errorf("diff of the subdomain: %+v", ch)
	}
}

// A dry run lists every write and sends none.
func TestADryRunWritesNothing(t *testing.T) {
	f, _ := dnsZone(t)
	d := &Subdomain{Name: "test.example.com", Addresses: map[string]string{"192.0.2.1": "198.51.100.7"}}
	mapped, _, _ := d.Map(capture(t, f))
	f.writes = 0
	would := 0
	for _, r := range subRestore(f, d, mapped, RestoreOptions{DryRun: true}) {
		if !r.OK {
			t.Errorf("%s: %s", r.Key, r.Detail)
		}
		if r.Detail == "would create" {
			would++
		}
	}
	if f.writes != 0 || would != 4 {
		t.Errorf("dry run: %d writes, %d would create; want 0 and 4", f.writes, would)
	}
}

// A record already at a planned name that Truthform did not make stops
// the restore; so does the subdomain delegated away. A wildcard above the
// subdomain, and an address left as the source's, are reported.
func TestASubdomainRestoreFindsWhatIsInTheWay(t *testing.T) {
	f, zid := dnsZone(t)
	src := capture(t, f)
	f.seed(t, "/zones/"+zid+"/dns_records", map[string]any{"type": "A", "name": "test.example.com", "content": "203.0.113.9", "ttl": 1, "proxied": false})
	f.seed(t, "/zones/"+zid+"/dns_records", map[string]any{"type": "TXT", "name": "old.test.example.com", "content": "\"x\"", "comment": "truthform: test.example.com", "ttl": 1, "proxied": false})
	d := &Subdomain{Name: "test.example.com"}
	mapped, _, _ := d.Map(src)
	conflicts, warnings := d.Check(mapped, capture(t, f))
	if len(conflicts) != 1 || !strings.Contains(conflicts[0], "A test.example.com 203.0.113.9: already there, and Truthform did not make it") {
		t.Errorf("conflicts %v", conflicts)
	}
	ws := strings.Join(warnings, "\n")
	if !strings.Contains(ws, "A *.example.com 192.0.2.1 answers for test.example.com") {
		t.Errorf("no wildcard warning in %v", warnings)
	}
	if !strings.Contains(ws, "TXT old.test.example.com \"x\": made by an earlier restore") {
		t.Errorf("no stale-record warning in %v", warnings)
	}
	if u := d.Unmapped(mapped); !slices.Equal(u, []string{"A *.test.example.com 192.0.2.1", "A test.example.com 192.0.2.1", "CNAME docs.test.example.com pages.example.net"}) {
		t.Errorf("unmapped %v", u)
	}

	g, gz := dnsZone(t)
	g.seed(t, "/zones/"+gz+"/dns_records", map[string]any{"type": "NS", "name": "test.example.com", "content": "ns1.example.net", "ttl": 1, "proxied": false})
	if c, _ := d.Check(mapped, capture(t, g)); len(c) != 1 || !strings.Contains(c[0], "delegated") {
		t.Errorf("a delegated subdomain: %v", c)
	}
	var none snapshot.Snapshot
	if c, _ := d.Check(mapped, none); len(c) != 1 || !strings.Contains(c[0], "not in the target account") {
		t.Errorf("no zone in the target: %v", c)
	}
}

// The guard refuses what Check should have stopped: a change to a record
// Truthform did not make, a record outside the subdomain, the zone.
func TestASubdomainRestoreWritesOnlyItsOwnRecords(t *testing.T) {
	f, zid := dnsZone(t)
	src := capture(t, f)
	d := &Subdomain{Name: "test.example.com", Addresses: map[string]string{"192.0.2.1": "198.51.100.7"}}
	mapped, _, _ := d.Map(src)
	// Someone's record at a planned name and content: only the comment
	// differs, so an update would claim it.
	f.seed(t, "/zones/"+zid+"/dns_records", map[string]any{"type": "A", "name": "test.example.com", "content": "198.51.100.7", "ttl": 1, "proxied": false, "comment": "theirs"})
	f.writes = 0
	for _, r := range subRestore(f, d, mapped, RestoreOptions{Update: true}) {
		if strings.Contains(r.Key, "A test.example.com") && (r.OK || !strings.Contains(r.Detail, "Truthform did not make it")) {
			t.Errorf("someone's record: ok=%v %s", r.OK, r.Detail)
		}
	}
	if f.writes != 3 {
		t.Errorf("%d writes, want the other 3 records", f.writes)
	}
	outside := snapshot.Object{Body: map[string]any{"kind": recordKind, "spec": map[string]any{"name": "www.example.com"}}}
	if d.Allow(outside, nil) == "" {
		t.Error("a record outside the subdomain allowed")
	}
	zone := snapshot.Object{Body: map[string]any{"kind": zoneKind, "spec": map[string]any{"name": "test.example.com"}}}
	if d.Allow(zone, nil) == "" {
		t.Error("a zone write allowed")
	}
}

// A subdomain restore uses the zone that is there and never makes one.
func TestASubdomainRestoreNeverMakesTheZone(t *testing.T) {
	f, _ := dnsZone(t)
	d := &Subdomain{Name: "test.example.com"}
	mapped, _, _ := d.Map(capture(t, f))
	empty := newFake(t, Cloudflare, spec(t, "cloudflare.json"), "acct-1111")
	cloudflare(empty)
	for _, r := range subRestore(empty, d, mapped, RestoreOptions{}) {
		if r.OK {
			t.Errorf("%s restored without its zone: %s", r.Key, r.Detail)
		}
	}
	if empty.writes != 0 {
		t.Errorf("%d writes into an account without the zone", empty.writes)
	}
}

// A conflict stops the restore before any write; a dry run still lists
// what it would write.
func TestAConflictStopsTheRestoreBeforeItWrites(t *testing.T) {
	f, zid := dnsZone(t)
	src := capture(t, f)
	f.seed(t, "/zones/"+zid+"/dns_records", map[string]any{"type": "A", "name": "test.example.com", "content": "203.0.113.9", "ttl": 1, "proxied": false})
	d := &Subdomain{Name: "test.example.com", Addresses: map[string]string{"192.0.2.1": "198.51.100.7"}, Targets: map[string]string{"pages.example.net": "pages.example.net"}}
	mapped, _, _ := d.Map(src)
	f.writes = 0
	conflicts, _, results, err := f.client(false).RestoreUnder(context.Background(), d, mapped, RestoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(conflicts) != 1 || len(results) != 0 || f.writes != 0 {
		t.Errorf("%d conflicts, %d results, %d writes; want 1, 0, 0", len(conflicts), len(results), f.writes)
	}
	conflicts, _, results, _ = f.client(true).RestoreUnder(context.Background(), d, mapped, RestoreOptions{DryRun: true})
	if len(conflicts) != 1 || len(results) != 5 || f.writes != 0 {
		t.Errorf("dry run: %d conflicts, %d results, %d writes; want 1, 5, 0", len(conflicts), len(results), f.writes)
	}
	// A source address left as it is stops it too.
	d.Addresses = nil
	g, _ := dnsZone(t)
	mapped, _, _ = d.Map(capture(t, g))
	g.writes = 0
	if c, _, r, _ := g.client(false).RestoreUnder(context.Background(), d, mapped, RestoreOptions{}); len(c) != 2 || len(r) != 0 || g.writes != 0 {
		t.Errorf("unmapped addresses: %v, %d results, %d writes", c, len(r), g.writes)
	}
}

// The guard holds inside the restore itself: given records outside the
// subdomain (a snapshot not mapped), it writes none of them.
func TestTheGuardRefusesRecordsOutsideTheSubdomain(t *testing.T) {
	f, _ := dnsZone(t)
	src := capture(t, f)
	empty := newFake(t, Cloudflare, spec(t, "cloudflare.json"), "acct-1111")
	cloudflare(empty)
	empty.seed(t, "/zones", map[string]any{"name": "example.com", "type": "full", "account": map[string]any{"id": "acct-1111"}})
	empty.writes = 0
	d := &Subdomain{Name: "test.example.com"}
	if _, _, err := d.Map(src); err != nil {
		t.Fatal(err)
	}
	for _, r := range subRestore(empty, d, src, RestoreOptions{}) {
		if strings.Contains(r.Key, "dns_record") && (r.OK || !strings.Contains(r.Detail, "is not under test.example.com")) {
			t.Errorf("%s: ok=%v %s", r.Key, r.OK, r.Detail)
		}
	}
	if empty.writes != 0 {
		t.Errorf("%d writes outside the subdomain", empty.writes)
	}
}

// A dry run with --update reports a change to one of its own records
// and sends it not.
func TestADryRunReportsAnUpdateAndSendsNone(t *testing.T) {
	f, _ := dnsZone(t)
	d := &Subdomain{Name: "test.example.com", Addresses: map[string]string{"192.0.2.1": "198.51.100.7"}}
	mapped, _, _ := d.Map(capture(t, f))
	subRestore(f, d, mapped, RestoreOptions{})
	for _, o := range mapped.Objects {
		if spec, _ := o.Body["spec"].(map[string]any); o.Kind() == recordKind {
			spec["ttl"] = float64(600)
		}
	}
	f.writes = 0
	would := 0
	for _, r := range subRestore(f, d, mapped, RestoreOptions{Update: true, DryRun: true}) {
		if strings.HasPrefix(r.Detail, "would update (ttl)") {
			would++
		}
	}
	if would != 4 || f.writes != 0 {
		t.Errorf("%d would update, %d writes; want 4 and 0", would, f.writes)
	}
}

// A kind the restore only finds is used as it is, even when it differs
// and --update is set, and is not made when missing: on its own, without
// the subdomain's guard behind it.
func TestAPresentKindIsNeverWritten(t *testing.T) {
	f, _ := dnsZone(t)
	src := capture(t, f)
	var zones snapshot.Snapshot
	for _, o := range src.Objects {
		if o.Kind() == zoneKind {
			o = snapshot.Object{Body: deepCopy(o.Body)}
			o.Body["spec"].(map[string]any)["paused"] = true
			zones.Objects = append(zones.Objects, o)
		}
	}
	empty := newFake(t, Cloudflare, spec(t, "cloudflare.json"), "acct-1111")
	cloudflare(empty)
	opt := RestoreOptions{Update: true, Present: map[string]bool{zoneKind: true}}
	for _, target := range []*fake{f, empty} {
		target.writes = 0
		(&Adapter{Client: target.client(false), Options: opt}).Restore(context.Background(), zones)
		if target.writes != 0 {
			t.Errorf("%d writes to a kind the restore only finds", target.writes)
		}
	}
}

// A CNAME to a host outside the zone (the source's app service or load
// balancer) would send the new name to the source, as a source address
// would: the restore stops until --target names the target's host, or
// the same host to keep it.
func TestACNAMEOutOfTheZoneMustBeNamed(t *testing.T) {
	f, _ := dnsZone(t)
	src := capture(t, f)
	addr := map[string]string{"192.0.2.1": "198.51.100.7"}
	for _, tc := range []struct {
		targets map[string]string
		content string
		stops   bool
	}{
		{nil, "pages.example.net", true},
		{map[string]string{"pages.example.net": "pages-test.example.net"}, "pages-test.example.net", false},
		{map[string]string{"pages.example.net": "pages.example.net"}, "pages.example.net", false},
	} {
		d := &Subdomain{Name: "test.example.com", Addresses: addr, Targets: tc.targets}
		mapped, _, _ := d.Map(src)
		if !slices.Contains(names(mapped), "example.com/CNAME docs.test.example.com "+tc.content) {
			t.Errorf("%v: docs not mapped to %s: %v", tc.targets, tc.content, names(mapped))
		}
		f.writes = 0
		c, _, r, _ := f.client(false).RestoreUnder(context.Background(), d, mapped, RestoreOptions{DryRun: true})
		if stopped := len(c) > 0; stopped != tc.stops || (tc.stops && !strings.Contains(c[0], "CNAME docs.test.example.com pages.example.net: still points at the source")) {
			t.Errorf("%v: conflicts %v", tc.targets, c)
		}
		if f.writes != 0 || len(r) != 5 {
			t.Errorf("%v: %d writes, %d results", tc.targets, f.writes, len(r))
		}
	}
}

// A record a first run made, at a name the snapshot now gives other
// content (a wrong --address the first time, a source that moved), would
// answer beside the new one: the restore stops and names it.
func TestAStaleRecordOfOursAtAPlannedNameStops(t *testing.T) {
	f, _ := dnsZone(t)
	src := capture(t, f)
	keep := map[string]string{"pages.example.net": "pages.example.net"}
	first := &Subdomain{Name: "test.example.com", Addresses: map[string]string{"192.0.2.1": "198.51.100.7"}, Targets: keep}
	mapped, _, _ := first.Map(src)
	if c, _, _, _ := f.client(false).RestoreUnder(context.Background(), first, mapped, RestoreOptions{}); len(c) > 0 {
		t.Fatal(c)
	}
	again := &Subdomain{Name: "test.example.com", Addresses: map[string]string{"192.0.2.1": "198.51.100.8"}, Targets: keep}
	mapped, _, _ = again.Map(src)
	f.writes = 0
	c, _, r, _ := f.client(false).RestoreUnder(context.Background(), again, mapped, RestoreOptions{})
	want := []string{
		"A *.test.example.com 198.51.100.7: made by an earlier restore with other content",
		"A test.example.com 198.51.100.7: made by an earlier restore with other content",
	}
	if len(c) != 2 || !strings.HasPrefix(c[0], want[0]) || !strings.HasPrefix(c[1], want[1]) {
		t.Errorf("conflicts %v", c)
	}
	if f.writes != 0 || len(r) != 0 {
		t.Errorf("%d writes, %d results after a conflict", f.writes, len(r))
	}
}

// A CNAME moved onto a name the restore leaves out points at nothing; an
// SRV, HTTPS or SVCB target is copied as it is. Both are reported.
func TestARestoreReportsWhatItCannotFollow(t *testing.T) {
	f, zid := dnsZone(t)
	f.seed(t, "/zones/"+zid+"/dns_records", map[string]any{"type": "CNAME", "name": "autodiscover.example.com", "content": "autodiscover.mail.example.net", "ttl": 1, "proxied": false})
	f.seed(t, "/zones/"+zid+"/dns_records", map[string]any{"type": "CNAME", "name": "webmail.example.com", "content": "autodiscover.example.com", "ttl": 1, "proxied": false})
	f.seed(t, "/zones/"+zid+"/dns_records", map[string]any{"type": "SRV", "name": "_sip._tcp.example.com", "content": "5 5060 sip.example.net", "priority": 10, "ttl": 1, "proxied": false})
	src := capture(t, f)
	d := &Subdomain{Name: "test.example.com"}
	mapped, _, _ := d.Map(src)
	_, w := d.Check(mapped, src)
	ws := strings.Join(w, "\n")
	if !strings.Contains(ws, "CNAME webmail.test.example.com autodiscover.test.example.com: points at a name the restore leaves out") {
		t.Errorf("no dangling-CNAME warning in %v", w)
	}
	if !strings.Contains(ws, "SRV _sip._tcp.test.example.com 5 5060 sip.example.net: its target is copied as it is") {
		t.Errorf("no SRV warning in %v", w)
	}
}

// Cloudflare's free plan refuses a comment over 100 characters, so a mark
// that long would fail every create; Map refuses it first.
func TestAMarkTooLongForACommentIsRefused(t *testing.T) {
	f, _ := dnsZone(t)
	src := capture(t, f)
	long := strings.Repeat("a", 80) + ".test.example.com"
	if _, _, err := (&Subdomain{Name: long}).Map(src); err == nil || !strings.Contains(err.Error(), "100") {
		t.Errorf("a %d-character mark accepted: %v", len("truthform: "+long), err)
	}
	ok := strings.Repeat("a", 60) + ".test.example.com"
	if _, _, err := (&Subdomain{Name: ok}).Map(src); err != nil {
		t.Errorf("a %d-character mark refused: %v", len("truthform: "+ok), err)
	}
}

// A record written before the tool was renamed carries the mark under the
// old name. It is still ours: read as someone else's, a restore would stop
// on it as a conflict and --update would refuse to change it.
func TestARecordMarkedUnderTheOldNameIsStillOurs(t *testing.T) {
	f, zid := dnsZone(t)
	src := capture(t, f)
	f.seed(t, "/zones/"+zid+"/dns_records", map[string]any{"type": "TXT", "name": "old.test.example.com", "content": `"x"`, "comment": "stackdna: test.example.com", "ttl": 1, "proxied": false})
	d := &Subdomain{Name: "test.example.com"}
	mapped, _, _ := d.Map(src)
	conflicts, warnings := d.Check(mapped, capture(t, f))
	if len(conflicts) != 0 {
		t.Errorf("conflicts %v", conflicts)
	}
	if ws := strings.Join(warnings, " | "); !strings.Contains(ws, `TXT old.test.example.com "x": made by an earlier restore`) {
		t.Errorf("not recognised as ours in %v", warnings)
	}
	rec := snapshot.Object{Body: map[string]any{"kind": recordKind, "spec": map[string]any{"name": "old.test.example.com"}}}
	if why := d.Allow(rec, map[string]any{"comment": "stackdna: test.example.com"}); why != "" {
		t.Errorf("a change to it was refused: %s", why)
	}
	if why := d.Allow(rec, map[string]any{"comment": "stackdna: other.example.com"}); why == "" {
		t.Error("a record marked for another subdomain was taken as ours")
	}
}
