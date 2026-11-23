package translate

import (
	"strings"
	"testing"
)

// A server the map gives no size is refused with what Azure sized: a
// PostgreSQL server's own SKU, or, for an Azure SQL server, which has
// none, that its databases are sized each. It read "its Azure SKU, ,
// names" for every Azure SQL server.
func TestSizeRefusalSaysWhatAzureSized(t *testing.T) {
	for name, m := range dbMaps() {
		m.Databases = map[string]DatabaseMap{}
		r := runDB(t, dbFixture(), m)
		sql := entry(t, r, typSQL+" data/shop-sql")
		if sql.State != Refused || !strings.Contains(sql.Reason, "Azure sizes each of its databases and not the server") || strings.Contains(sql.Reason, ", ,") {
			t.Errorf("%s: an Azure SQL server: %s %q", name, sql.State, sql.Reason)
		}
		pg := entry(t, r, "Microsoft.DBforPostgreSQL/flexibleServers data/shop-pg")
		if pg.State != Refused || !strings.Contains(pg.Reason, "its Azure SKU, Standard_") || strings.Contains(pg.Reason, ", ,") {
			t.Errorf("%s: a PostgreSQL server: %s %q", name, pg.State, pg.Reason)
		}
	}
}
