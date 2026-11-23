package translate

import (
	"strings"
	"testing"
)

// Azure makes a ledger digest upload setting for every database, off: it
// says nothing. On, the target's ledger cannot be verified as the
// source's could, which is less protected and named.
func TestLedgerDigestUploads(t *testing.T) {
	const kind = typSQL + "/databases/ledgerDigestUploads"
	for name, m := range dbMaps() {
		for what, c := range map[string]struct {
			props  map[string]any
			widens bool
		}{
			"as Azure makes it": {map[string]any{}, false},
			"disabled":          {map[string]any{"state": "Disabled"}, false},
			"enabled":           {map[string]any{"state": "Enabled", "digestStorageEndpoint": "https://digests.blob.core.windows.net"}, true},
			"an endpoint alone": {map[string]any{"digestStorageEndpoint": "https://digests.blob.core.windows.net"}, true},
		} {
			s := dbFixture()
			s.Objects = append(s.Objects, az(kind, "data", "shop-sql/orders/current", pr(c.props)))
			e := entry(t, runDB(t, s, m), kind+" data/shop-sql/orders/current")
			if e.State == NotLooked || e.State == Refused {
				t.Fatalf("%s, %s: %s %s", name, what, e.State, e.Reason)
			}
			l := lossAbout(e, "digestStorageEndpoint")
			if c.widens != (l != nil && l.Widens) {
				t.Errorf("%s, %s: widens %v, want %v: %+v", name, what, l != nil && l.Widens, c.widens, e)
			}
			if !c.widens && (len(e.Losses) != 0 || !strings.Contains(e.Reason, "off on the source")) {
				t.Errorf("%s, %s: off, yet %q %+v", name, what, e.Reason, e.Losses)
			}
		}
		// A setting no rule reads is named, not passed over.
		s := dbFixture()
		s.Objects = append(s.Objects, az(kind, "data", "shop-sql/orders/current", pr(map[string]any{"other": true})))
		found := false
		for _, l := range entry(t, runDB(t, s, m), kind+" data/shop-sql/orders/current").Losses {
			found = found || (l.Unread && l.Field == "properties.other")
		}
		if !found {
			t.Errorf("%s: an unknown setting is not unread", name)
		}
	}
}
