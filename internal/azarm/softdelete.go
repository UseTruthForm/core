package azarm

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// heldName is a type whose deleted resources keep their name for a time: a
// restore of one by that name is refused until Azure frees it or it is purged.
// A destroy-and-restore drill of a real estate lost a run to this: both SQL
// servers were held, and Azure does not let a deleted server be purged.
type heldName struct {
	typ, path, version string
	// byLocation lists per region (path has a %s for it).
	byLocation bool
	// purge is the command that frees the name; "" when none does.
	purge string
}

var heldNames = []heldName{
	{"Microsoft.KeyVault/vaults", "/providers/Microsoft.KeyVault/deletedVaults", "2023-07-01", false, "az keyvault purge --name %s"},
	{"Microsoft.CognitiveServices/accounts", "/providers/Microsoft.CognitiveServices/deletedAccounts", "2023-05-01", false, "az cognitiveservices account purge --name %s --resource-group %s --location %s"},
	{"Microsoft.Sql/servers", "/providers/Microsoft.Sql/locations/%s/deletedServers", "2023-08-01", true, ""},
	{"Microsoft.ApiManagement/service", "/providers/Microsoft.ApiManagement/deletedservices", "2022-08-01", false, "az apim deletedservice purge --service-name %s --location %s"},
	{"Microsoft.AppConfiguration/configurationStores", "/providers/Microsoft.AppConfiguration/deletedConfigurationStores", "2023-03-01", false, "az appconfig purge --name %s --location %s"},
}

// NamesHeld lists the snapshot's resources whose names a deleted one holds in
// the target subscription, with how to free each, and the lists it could not
// read. Read-only: what a restore would be refused, said before it is sent.
func NamesHeld(ctx context.Context, api ARM, s snapshot.Snapshot) (held, unread []string) {
	lists := map[string]map[string]map[string]any{} // path -> lower name -> what the list says of it
	read := func(path, version string) map[string]map[string]any {
		if got, ok := lists[path]; ok {
			return got
		}
		items, err := api.List(ctx, "/subscriptions/"+api.Subscription()+path, version)
		if err != nil {
			unread = append(unread, path+": "+err.Error())
			lists[path] = nil
			return nil
		}
		names := map[string]map[string]any{}
		for _, it := range items {
			n, _ := it["name"].(string)
			if id, _ := it["id"].(string); n == "" && id != "" {
				n = id[strings.LastIndex(id, "/")+1:]
			}
			props, _ := it["properties"].(map[string]any)
			if props == nil {
				props = map[string]any{}
			}
			names[strings.ToLower(n)] = props
		}
		lists[path] = names
		return names
	}
	for _, o := range s.Objects {
		for _, h := range heldNames {
			if !strings.EqualFold(o.Kind(), h.typ) {
				continue
			}
			spec, _ := o.Body["spec"].(map[string]any)
			loc, _ := spec["location"].(string)
			path := h.path
			if h.byLocation {
				if loc == "" {
					continue
				}
				path = fmt.Sprintf(h.path, strings.ToLower(strings.ReplaceAll(loc, " ", "")))
			}
			props, ok := read(path, h.version)[strings.ToLower(o.Name())]
			if !ok {
				continue
			}
			how := "Azure frees it when its retention ends, and no purge does: rename it with --rename, or wait"
			// A vault with purge protection cannot be purged before its
			// date (review of #75: the advice said to purge it).
			if props["purgeProtectionEnabled"] == true {
				how = "it has purge protection, so no purge frees it: rename it with --rename, or wait"
				if when, _ := props["scheduledPurgeDate"].(string); when != "" {
					how += " until " + when
				}
			} else if h.purge != "" {
				args := []any{o.Name(), o.Namespace(), loc}[:strings.Count(h.purge, "%s")]
				how = "purge it (" + fmt.Sprintf(h.purge, args...) + "), or rename it with --rename"
			}
			held = append(held, h.typ+"/"+o.Namespace()+"/"+o.Name()+": the name is held by a deleted one; "+how)
		}
	}
	sort.Strings(held)
	sort.Strings(unread)
	return held, unread
}

// HeldElsewhere says the snapshot has a type whose names are unique across
// Azure and held by a deleted one in any subscription: one deleted in another
// subscription holds the name too, and NamesHeld cannot see it (review of
// #75), so "none held" is not "all clear".
func HeldElsewhere(s snapshot.Snapshot) bool {
	for _, o := range s.Objects {
		switch strings.ToLower(o.Kind()) {
		case "microsoft.keyvault/vaults", "microsoft.apimanagement/service", "microsoft.appconfiguration/configurationstores", "microsoft.cognitiveservices/accounts":
			return true
		}
	}
	return false
}
