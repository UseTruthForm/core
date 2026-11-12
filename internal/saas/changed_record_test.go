package saas

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

// snapshotOf is a snapshot with its restore results by object name.
type snapshotOf struct{ s snapshot.Snapshot }

func (s snapshotOf) restore(f *fake, opt RestoreOptions) map[string]snapshot.Result {
	out := map[string]snapshot.Result{}
	for _, r := range f.client(false).Restore(context.Background(), s.s, opt) {
		out[r.Key[strings.LastIndex(r.Key, "|")+1:]] = r
	}
	return out
}

// driftedZone is a zone captured, then changed by hand:
//
//	www   its one A record now holds another address (the common case: an
//	      address changed since the capture)
//	app   had two A records; one was replaced and a third added
//	old   the snapshot's record is gone and nothing took its place
//	extra a record the snapshot never had
func driftedZone(t *testing.T) (*fake, snapshotOf, string) {
	t.Helper()
	f := newFake(t, Cloudflare, spec(t, "cloudflare.json"), "acct-1111")
	cloudflare(f)
	zone := f.seed(t, "/zones", map[string]any{"name": "example.com", "type": "full", "account": map[string]any{"id": "acct-1111"}})
	recs := "/zones/" + stringOf(zone["id"]) + "/dns_records"
	ids := map[string]string{}
	for _, r := range []map[string]any{
		{"type": "A", "name": "www.example.com", "content": "192.0.2.1", "ttl": 300, "proxied": false},
		{"type": "A", "name": "app.example.com", "content": "192.0.2.10", "ttl": 300, "proxied": false},
		{"type": "A", "name": "app.example.com", "content": "192.0.2.11", "ttl": 300, "proxied": false},
		{"type": "A", "name": "old.example.com", "content": "192.0.2.20", "ttl": 300, "proxied": false},
	} {
		ids[stringOf(r["name"])+" "+stringOf(r["content"])] = stringOf(f.seed(t, recs, r)["id"])
	}
	snap := capture(t, f)

	c := f.client(false)
	patch := func(key, content string) {
		t.Helper()
		if _, _, err := c.do(t.Context(), "PATCH", recs+"/"+ids[key], map[string]any{"content": content}); err != nil {
			t.Fatalf("changing %s: %v", key, err)
		}
	}
	patch("www.example.com 192.0.2.1", "192.0.2.9")
	patch("app.example.com 192.0.2.11", "192.0.2.12")
	f.seed(t, recs, map[string]any{"type": "A", "name": "app.example.com", "content": "192.0.2.13", "ttl": 300, "proxied": false})
	f.seed(t, recs, map[string]any{"type": "A", "name": "extra.example.com", "content": "198.51.100.1", "ttl": 300, "proxied": false})
	// "old" is removed outright: the fake has no delete, so drop it here.
	f.mu.Lock()
	kept := f.colls[recs][:0]
	for _, it := range f.colls[recs] {
		if stringOf(it["name"]) != "old.example.com" {
			kept = append(kept, it)
		}
	}
	f.colls[recs] = kept
	f.mu.Unlock()
	return f, snapshotOf{snap}, recs
}

// at lists the contents of the A records at a name, sorted.
func at(f *fake, recs, name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, it := range f.colls[recs] {
		if stringOf(it["name"]) == name {
			out = append(out, stringOf(it["content"]))
		}
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// A record whose content changed since the capture is the same record
// changed, not a new one: a restore reports it, and --update changes it
// where it is.
//
// The failure this pins: a record is named by its type, name and content,
// so the snapshot's www -> 192.0.2.1 was simply "missing" from a zone
// holding www -> 192.0.2.9. A restore created it beside the old one, with
// or without --update, reported success, and DNS then answered with both
// addresses, the stale one included.
func TestARecordWhoseContentChangedIsNotRestoredBesideTheOldOne(t *testing.T) {
	f, snap, recs := driftedZone(t)
	const www = "example.com/A www.example.com 192.0.2.1"
	const app = "example.com/A app.example.com 192.0.2.11"
	const old = "example.com/A old.example.com 192.0.2.20"

	// Without --update: reported, and left as it is.
	res := snap.restore(f, RestoreOptions{})
	if r := res[www]; r.OK || !strings.Contains(r.Detail, "192.0.2.9") || !strings.Contains(r.Detail, "--update") {
		t.Errorf("without --update, www: ok=%v %q; want it not applied, naming the address there and --update", r.OK, r.Detail)
	}
	if got := at(f, recs, "www.example.com"); got != "192.0.2.9" {
		t.Errorf("without --update, www holds %s; want only the address it had", got)
	}
	// A record that is simply gone is created, as before.
	if r := res[old]; !r.OK || r.Detail != "created" {
		t.Errorf("old: ok=%v %q; want created", r.OK, r.Detail)
	}

	// A dry run of --update says what it would do and sends nothing.
	writes := f.writes
	dry := snap.restore(f, RestoreOptions{Update: true, DryRun: true})
	if r := dry[www]; !r.OK || !strings.Contains(r.Detail, "would update (content)") {
		t.Errorf("dry run, www: ok=%v %q; want would update (content)", r.OK, r.Detail)
	}
	if f.writes != writes {
		t.Errorf("the dry run sent %d writes", f.writes-writes)
	}

	// With --update: changed where it is.
	res = snap.restore(f, RestoreOptions{Update: true})
	if r := res[www]; !r.OK || !strings.Contains(r.Detail, "updated (content)") {
		t.Errorf("with --update, www: ok=%v %q; want updated (content)", r.OK, r.Detail)
	}
	if got := at(f, recs, "www.example.com"); got != "192.0.2.1" {
		t.Errorf("with --update, www holds %s; want only 192.0.2.1", got)
	}
	// Run again: nothing left to do for it.
	if r := snap.restore(f, RestoreOptions{Update: true})[www]; !r.OK || r.Detail != "already present and identical" {
		t.Errorf("second --update, www: ok=%v %q", r.OK, r.Detail)
	}

	// Two records at app that the snapshot does not have, and one of the
	// snapshot's missing: which one it replaces cannot be known, so
	// nothing is written there, even with --update (res is that run).
	if r := res[app]; r.OK || !strings.Contains(r.Detail, "192.0.2.12") || !strings.Contains(r.Detail, "192.0.2.13") {
		t.Errorf("app: ok=%v %q; want it not applied, naming both records there", r.OK, r.Detail)
	}
	if got := at(f, recs, "app.example.com"); got != "192.0.2.10,192.0.2.12,192.0.2.13" {
		t.Errorf("app holds %s; want it left as it was", got)
	}
	// A record the snapshot never had is not touched.
	if got := at(f, recs, "extra.example.com"); got != "198.51.100.1" {
		t.Errorf("extra holds %s", got)
	}
}

// A second record at a name that already holds only the snapshot's other
// records is new, and is created: several A records at one name is
// ordinary DNS, and must not read as a change.
func TestAnotherRecordAtANameIsStillCreated(t *testing.T) {
	f := newFake(t, Cloudflare, spec(t, "cloudflare.json"), "acct-1111")
	cloudflare(f)
	zone := f.seed(t, "/zones", map[string]any{"name": "example.com", "type": "full", "account": map[string]any{"id": "acct-1111"}})
	recs := "/zones/" + stringOf(zone["id"]) + "/dns_records"
	f.seed(t, recs, map[string]any{"type": "A", "name": "www.example.com", "content": "192.0.2.1", "ttl": 300, "proxied": false})
	second := f.seed(t, recs, map[string]any{"type": "A", "name": "www.example.com", "content": "192.0.2.2", "ttl": 300, "proxied": false})
	// A TXT record at the same name is another type: not the A record changed.
	f.seed(t, recs, map[string]any{"type": "TXT", "name": "www.example.com", "content": "\"note\"", "ttl": 300, "proxied": false})
	snap := snapshotOf{capture(t, f)}
	// So is an AAAA record added since: one record of another type that
	// the snapshot does not have is not the missing A record changed.
	f.seed(t, recs, map[string]any{"type": "AAAA", "name": "www.example.com", "content": "2001:db8::1", "ttl": 300, "proxied": false})

	f.mu.Lock()
	kept := f.colls[recs][:0]
	for _, it := range f.colls[recs] {
		if stringOf(it["id"]) != stringOf(second["id"]) {
			kept = append(kept, it)
		}
	}
	f.colls[recs] = kept
	f.mu.Unlock()

	res := snap.restore(f, RestoreOptions{})
	if r := res["example.com/A www.example.com 192.0.2.2"]; !r.OK || r.Detail != "created" {
		t.Errorf("the second record: ok=%v %q; want created", r.OK, r.Detail)
	}
	if got := at(f, recs, "www.example.com"); got != "\"note\",192.0.2.1,192.0.2.2,2001:db8::1" {
		t.Errorf("www holds %s", got)
	}
}

// A TXT record missing from a name that holds another TXT record is new,
// not that record changed: a domain's root holds unrelated TXT values (SPF
// beside a site verification), and --update must not turn one into the
// other. It is created, and the restore says what is beside it.
func TestATXTRecordIsNotTakenForAnotherOneChanged(t *testing.T) {
	f := newFake(t, Cloudflare, spec(t, "cloudflare.json"), "acct-1111")
	cloudflare(f)
	zone := f.seed(t, "/zones", map[string]any{"name": "example.com", "type": "full", "account": map[string]any{"id": "acct-1111"}})
	recs := "/zones/" + stringOf(zone["id"]) + "/dns_records"
	spf := f.seed(t, recs, map[string]any{"type": "TXT", "name": "example.com", "content": "\"v=spf1 -all\"", "ttl": 300, "proxied": false})
	snap := snapshotOf{capture(t, f)}
	if _, _, err := f.client(false).do(t.Context(), "PATCH", recs+"/"+stringOf(spf["id"]), map[string]any{"content": "\"site-verification=abc\""}); err != nil {
		t.Fatal(err)
	}

	const key = "example.com/TXT example.com \"v=spf1 -all\""
	if r := snap.restore(f, RestoreOptions{Update: true, DryRun: true})[key]; !r.OK || !strings.HasPrefix(r.Detail, "would create; the target also holds") {
		t.Errorf("dry run: ok=%v %q", r.OK, r.Detail)
	}
	r := snap.restore(f, RestoreOptions{Update: true})[key]
	if !r.OK || !strings.HasPrefix(r.Detail, "created; the target also holds") || !strings.Contains(r.Detail, "site-verification=abc") {
		t.Errorf("ok=%v %q; want created, naming the record beside it", r.OK, r.Detail)
	}
	if got := at(f, recs, "example.com"); got != "\"site-verification=abc\",\"v=spf1 -all\"" {
		t.Errorf("the root holds %s; want both", got)
	}
}

// zoneWith is a zone holding the given records, and the path of its
// records with each record's ID by "TYPE name".
func zoneWith(t *testing.T, records ...map[string]any) (*fake, string, map[string]string) {
	t.Helper()
	f := newFake(t, Cloudflare, spec(t, "cloudflare.json"), "acct-1111")
	cloudflare(f)
	zone := f.seed(t, "/zones", map[string]any{"name": "example.com", "type": "full", "account": map[string]any{"id": "acct-1111"}})
	recs := "/zones/" + stringOf(zone["id"]) + "/dns_records"
	ids := map[string]string{}
	for _, r := range records {
		r["ttl"], r["proxied"] = 300, false
		ids[stringOf(r["type"])+" "+stringOf(r["name"])] = stringOf(f.seed(t, recs, r)["id"])
	}
	return f, recs, ids
}

// set changes one field of a record in place, as the provider's own
// dashboard would.
func set(t *testing.T, f *fake, recs, id, content string) {
	t.Helper()
	if _, _, err := f.client(false).do(t.Context(), "PATCH", recs+"/"+id, map[string]any{"content": content}); err != nil {
		t.Fatal(err)
	}
}

// An alias and an IPv6 address are changed where they are too, and a
// refusal from the caller's Allow is honoured before any write.
func TestAChangedAliasAndIPv6AddressAreUpdatedInPlace(t *testing.T) {
	f, recs, ids := zoneWith(t,
		map[string]any{"type": "CNAME", "name": "docs.example.com", "content": "pages.example.net"},
		map[string]any{"type": "AAAA", "name": "v6.example.com", "content": "2001:db8::1"})
	snap := snapshotOf{capture(t, f)}
	set(t, f, recs, ids["CNAME docs.example.com"], "elsewhere.example.net")
	set(t, f, recs, ids["AAAA v6.example.com"], "2001:db8::9")
	const docs = "example.com/CNAME docs.example.com pages.example.net"
	const v6 = "example.com/AAAA v6.example.com 2001:db8::1"

	// The caller may refuse a change to a record (a subdomain restore
	// does, for one it did not make): nothing is sent.
	writes := f.writes
	no := func(o snapshot.Object, existing map[string]any) string {
		if existing != nil {
			return "not ours"
		}
		return ""
	}
	if r := snap.restore(f, RestoreOptions{Update: true, Allow: no})[docs]; r.OK || !strings.Contains(r.Detail, "not modified: not ours") {
		t.Errorf("refused by Allow: ok=%v %q", r.OK, r.Detail)
	}
	if f.writes != writes {
		t.Errorf("%d writes sent although Allow refused", f.writes-writes)
	}

	res := snap.restore(f, RestoreOptions{Update: true})
	for _, k := range []string{docs, v6} {
		if r := res[k]; !r.OK || r.Detail != "updated (content)" {
			t.Errorf("%s: ok=%v %q; want updated (content)", k, r.OK, r.Detail)
		}
	}
	if got := at(f, recs, "docs.example.com") + " " + at(f, recs, "v6.example.com"); got != "pages.example.net 2001:db8::1" {
		t.Errorf("the zone holds %s", got)
	}
}

// Two of the snapshot's records missing at a name that holds one record
// the snapshot does not have: either could be the one that changed, so
// neither is written.
func TestTwoMissingAndOneUnknownIsNotGuessed(t *testing.T) {
	f, recs, ids := zoneWith(t,
		map[string]any{"type": "A", "name": "app.example.com", "content": "192.0.2.10"},
		map[string]any{"type": "A", "name": "app.example.com", "content": "192.0.2.11"})
	snap := snapshotOf{capture(t, f)}
	// Both records share a name, so ids holds the second; the first is
	// dropped, and the second changed.
	f.mu.Lock()
	f.colls[recs] = f.colls[recs][1:]
	f.mu.Unlock()
	set(t, f, recs, ids["A app.example.com"], "192.0.2.99")

	writes := f.writes
	res := snap.restore(f, RestoreOptions{Update: true})
	for _, k := range []string{"example.com/A app.example.com 192.0.2.10", "example.com/A app.example.com 192.0.2.11"} {
		if r := res[k]; r.OK || !strings.Contains(r.Detail, "192.0.2.99") || !strings.Contains(r.Detail, "2 of the snapshot's are missing") {
			t.Errorf("%s: ok=%v %q", k, r.OK, r.Detail)
		}
	}
	if f.writes != writes || at(f, recs, "app.example.com") != "192.0.2.99" {
		t.Errorf("%d writes sent; app holds %s", f.writes-writes, at(f, recs, "app.example.com"))
	}
}

// A provider that stores an alias's host or an IPv6 address in another
// case than the snapshot has it still holds the same record.
//
// The failure this pins (review of the change above): the record was
// looked up by its exact name, content included, so the snapshot's
// "Pages.Example.net" was missing from a zone holding
// "pages.example.net". It was reported as changed, and --update sent the
// same write on every run without the two ever matching.
func TestContentThatDiffersOnlyByCaseIsTheSameRecord(t *testing.T) {
	f, recs, ids := zoneWith(t,
		map[string]any{"type": "CNAME", "name": "docs.example.com", "content": "Pages.Example.net"},
		map[string]any{"type": "AAAA", "name": "v6.example.com", "content": "2001:DB8::1"},
		map[string]any{"type": "TXT", "name": "example.com", "content": "\"Key=AbC\""})
	snap := snapshotOf{capture(t, f)}
	set(t, f, recs, ids["CNAME docs.example.com"], "pages.example.net")
	set(t, f, recs, ids["AAAA v6.example.com"], "2001:db8::1")

	writes := f.writes
	for k, r := range snap.restore(f, RestoreOptions{Update: true}) {
		if !r.OK || r.Detail != "already present and identical" {
			t.Errorf("%s: ok=%v %q; want identical", k, r.OK, r.Detail)
		}
	}
	if f.writes != writes {
		t.Errorf("%d writes sent for records that only differ by case", f.writes-writes)
	}

	// A TXT record's content is not folded: its case is its meaning.
	set(t, f, recs, ids["TXT example.com"], "\"key=abc\"")
	if r := snap.restore(f, RestoreOptions{})["example.com/TXT example.com \"Key=AbC\""]; !r.OK || !strings.HasPrefix(r.Detail, "created; the target also holds") {
		t.Errorf("TXT differing by case: ok=%v %q; want it created beside", r.OK, r.Detail)
	}
}
