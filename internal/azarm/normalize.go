package azarm

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

// envelope keys ARM returns on every resource that are not configuration.
// They are dropped by name because some definitions do not mark them
// read-only: systemData (who changed it and when) differs on every write
// and would be drift in every diff; name, id and type are the identity,
// which the snapshot keeps in metadata.
var envelope = map[string]bool{"id": true, "name": true, "type": true, "systemData": true, "etag": true, "apiVersion": true}

// serverSet are properties ARM's resource-provider contract has the server
// set wherever they appear. When a definition does not declare one, it is
// still read-only: the first real drill (2026-10-21) diffed a restored VNet
// on subnets[0].properties.resourceGuid, which Azure returns but the subnet
// definition (2026-03-01) does not declare. Any other undeclared field is
// kept, see normalize.
var serverSet = map[string]bool{"provisioningState": true, "resourceGuid": true}

// setByAzure are declared writable and are not configuration. A renamed key
// vault kept its old vaultUri, so a diff showed it changed forever; a node image
// changes when AKS upgrades a pool, and a private zone's SOA serial when any
// record changes, so each would read as drift no one made. A peering's state and
// the far side's address space come from the far side: one still Initiated, on
// the way to Connected, read as differing. By type: elsewhere these names are
// settings (an HDInsight cluster's vaultUri is required configuration).
var setByAzure = map[string]map[string]bool{
	"microsoft.keyvault/vaults":                                {"vaultUri": true},
	"microsoft.containerservice/managedclusters":               {"nodeImageVersion": true},
	"microsoft.containerservice/managedclusters/agentpools":    {"nodeImageVersion": true},
	"microsoft.network/privatednszones/soa":                    {"serialNumber": true},
	"microsoft.network/dnszones/soa":                           {"serialNumber": true},
	"microsoft.network/virtualnetworks/virtualnetworkpeerings": {"peeringState": true, "peeringSyncLevel": true, "remoteAddressSpace": true, "remoteVirtualNetworkAddressSpace": true},
}

// defaultOutboundAccess unset on a subnet means it has Azure's default outbound
// access, under the API versions released before 31 March 2026. Under later ones
// an unset subnet is made private, so a restore, which writes at a newer version
// (2026-03-01 in the drill), turned a subnet that reached the internet into one
// that does not, and VMs with no NAT gateway or load balancer lost it. Found by
// the first real drill to reach a diff. What it means is written down, so a
// restore says it. Not on a delegated subnet: private subnets do not apply there,
// so unset is no risk, and a value Azure may not take is not sent.
func defaultOutboundAsMeant(typ string, spec map[string]any) {
	props, _ := spec["properties"].(map[string]any)
	set := func(p map[string]any) {
		delegated, _ := p["delegations"].([]any)
		if _, ok := p["defaultOutboundAccess"]; !ok && p != nil && len(delegated) == 0 {
			p["defaultOutboundAccess"] = true
		}
	}
	switch {
	case strings.EqualFold(typ, vnetType):
		subnets, _ := props["subnets"].([]any)
		for _, x := range subnets {
			sn, _ := x.(map[string]any)
			sp, _ := sn["properties"].(map[string]any)
			set(sp)
		}
	case strings.EqualFold(typ, vnetType+"/subnets"):
		set(props)
	}
}

// A VNet's peerings name other VNets, so two peered ones each waited for the
// other: "its references form a cycle", for them and for all that needed them,
// on every run. They are captured as the children they also are, and those come
// after both networks.
const vnetType = "Microsoft.Network/virtualNetworks"

// split is what normalize removed from a resource body.
type split struct {
	readOnly map[string]any // scalar read-only values by dotted path; status keeps those that are not observations
	secrets  []string       // paths of properties Azure never returns
}

// normalize returns the configured part of a GET response, walking it
// together with the type definition: read-only values are removed (scalars
// are kept in split.readOnly), secret and write-only values are removed and
// their paths listed. A property the definition does not know is kept: an
// API returning a field its definition lacks is newer than the definition,
// and dropping the field would lose configuration without a word.
func (s *Schema) normalize(body map[string]any) (map[string]any, split) {
	sp := split{readOnly: map[string]any{}}
	spec := deepCopy(body)
	for k := range envelope {
		delete(spec, k)
	}
	if strings.EqualFold(s.Type, vnetType) {
		if props, _ := spec["properties"].(map[string]any); props != nil {
			delete(props, "virtualNetworkPeerings")
		}
	}
	s.clean(spec, s.body, "", &sp)
	spec = walkStrings(spec, canonicalNever).(map[string]any)
	defaultOutboundAsMeant(s.Type, spec)
	sort.Strings(sp.secrets)
	return spec, sp
}

// neverRE is a duration within a day of .NET's TimeSpan.MaxValue
// (10675199.02:48:05.4775807), which Azure uses for "never" (a Service Bus
// entity's autoDeleteOnIdle, defaultMessageTimeToLive). Azure returns it
// rounded in several ways: in a real subscription, four spellings across
// 357 entities (P10675199DT2H48M5.4775807S, P10675199DT2H48M5.477S,
// P10675198DT2H48M5.477S, P10675198DT2H48M5S), so an unchanged entity
// could read as changed.
var neverRE = regexp.MustCompile(`^P1067519[89]DT2H48M5(\.\d+)?S$`)

// never is the spelling Azure documents as the default for "never", and
// accepts back on a write.
const never = "P10675199DT2H48M5.4775807S"

func canonicalNever(v string) string {
	if neverRE.MatchString(v) {
		return never
	}
	return v
}

func (s *Schema) clean(v any, t int, path string, sp *split) {
	switch c := v.(type) {
	case map[string]any:
		props, add, ok := s.object(t, c)
		if !ok {
			return
		}
		for _, k := range sortedKeys(c) {
			p, known := props[k]
			full := join(path, k)
			switch {
			case !known && add != nil:
				s.clean(c[k], add.index(), join(path, "*"), sp)
			case !known && serverSet[k]:
				if isScalar(c[k]) {
					sp.readOnly[full] = c[k]
				}
				delete(c, k)
			case !known && isEmptyObject(c[k]):
				// No settings in it, so nothing is lost. Azure returns some
				// of these only sometimes: a Service Bus rule's
				// sqlFilter.parameters came and went between two captures
				// of a real subscription a minute apart.
				delete(c, k)
			case setByAzure[strings.ToLower(s.Type)][k]:
				delete(c, k)
			case !known:
				// kept, see normalize
			case p.Flags&flagReadOnly != 0:
				// A read-only object (a managed identity's whole properties
				// block) keeps its scalars for status. Dropping them lost
				// the identity's principalId, so a role assignment for it
				// could never be remapped to the restored identity.
				recordScalars(c[k], full, sp)
				delete(c, k)
			case s.secret(p):
				if s.credential(k, p) {
					sp.secrets = append(sp.secrets, full)
				}
				delete(c, k)
			default:
				before := -1
				if m, ok := c[k].(map[string]any); ok {
					before = s.settings(m, p.Type.index())
				}
				s.clean(c[k], p.Type.index(), full, sp)
				// An object emptied by stripping (properties whose every
				// field is read-only) is removed, so a restore does not send
				// an empty object Azure never received. One that arrived
				// empty is kept as it was, and so is one that held only an
				// undeclared empty object: otherwise {x: {}} in one capture
				// and {} in the next would still differ (review of #31).
				if m, ok := c[k].(map[string]any); ok && before > 0 && len(m) == 0 {
					delete(c, k)
				}
			}
		}
	case []any:
		if e := s.file[t]; e.Kind == "ArrayType" && e.ItemType != nil {
			for _, x := range c {
				s.clean(x, e.ItemType.index(), path+"[]", sp)
			}
		}
	}
}

// secretPaths lists every secret property the definition declares at any
// depth reachable from the body, whether or not a value is present. These
// are what a restore must be given; Azure returns none of them.
func (s *Schema) secretPaths() []string {
	var out []string
	var walk func(i int, prefix string, depth int, seen map[int]bool)
	walk = func(i int, prefix string, depth int, seen map[int]bool) {
		if seen[i] || depth > maxDepth {
			return
		}
		seen = copySet(seen)
		seen[i] = true
		e := s.file[i]
		if e.Kind == "ArrayType" && e.ItemType != nil {
			walk(e.ItemType.index(), prefix+"[]", depth+1, seen)
			return
		}
		props, _, ok := s.object(i, nil)
		if !ok {
			return
		}
		for _, k := range sortedKeys(props) {
			p := props[k]
			if p.Flags&flagReadOnly != 0 {
				continue
			}
			if s.secret(p) {
				if s.credential(k, p) {
					out = append(out, join(prefix, k))
				}
				continue
			}
			walk(p.Type.index(), join(prefix, k), depth+1, seen)
		}
	}
	walk(s.body, "", 0, map[int]bool{})
	sort.Strings(out)
	return out
}

// recordScalars keeps every scalar under v by dotted path. Arrays are not
// followed: their positions are not stable names.
func recordScalars(v any, path string, sp *split) {
	if isScalar(v) {
		sp.readOnly[path] = v
		return
	}
	if m, ok := v.(map[string]any); ok {
		for _, k := range sortedKeys(m) {
			recordScalars(m[k], join(path, k), sp)
		}
	}
}

// settings counts the entries of an object that clean does not drop as
// undeclared and empty.
func (s *Schema) settings(m map[string]any, t int) int {
	props, add, ok := s.object(t, m)
	n := 0
	for k, v := range m {
		if _, known := props[k]; ok && !known && add == nil && !serverSet[k] && isEmptyObject(v) {
			continue
		}
		n++
	}
	return n
}

// auditRE names who created or last changed a resource (a role
// assignment's createdBy and updatedBy). That is an observation, like when,
// not something a reference can point at: kept in status, it owned the
// object IDs of the people it names, so a role assignment for one of them
// was rewritten as "whoever created that other assignment", which on a
// restore is whoever runs the restore.
var auditRE = regexp.MustCompile(`(?i)(^|\.)(createdBy|updatedBy|lastModifiedBy|modifiedBy|createdByType|lastModifiedByType|updatedByType)$`)

func audit(path string) bool { return auditRE.MatchString(path) }

func isEmptyObject(v any) bool {
	m, ok := v.(map[string]any)
	return ok && len(m) == 0
}

// timeRE matches the forms Azure returns times in: ISO 8601 with a T or a
// space, a bare date, and the US form some older APIs use
// (10/21/2026 8:15:00 AM).
var timeRE = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}|$)|\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{2})`)

// observed reports a read-only value that records what happened rather than
// what was made: a time (a queue's accessedAt, a database's
// earliestRestoreDate), or a number or flag (message counts, sizes). Status
// is kept for what a reference can point at, and that is always a string
// that is not a time: an ID, a GUID, a host name. Observations change on
// their own; kept, they made two captures of an unchanged real subscription
// differ in over a hundred files.
func observed(v any) bool {
	switch x := v.(type) {
	case float64, bool:
		return true
	case string:
		return timeRE.MatchString(x)
	}
	return false
}

func isScalar(v any) bool {
	switch v.(type) {
	case string, float64, bool, nil:
		return true
	}
	return false
}

func deepCopy(m map[string]any) map[string]any {
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return out
}

// rewriteAll is walkStrings for map keys too. Azure keys some maps by
// resource ID (a site's identity.userAssignedIdentities), so a subscription
// left in a key would point a restored resource at the source subscription.
func rewriteAll(v any, fn func(string) string) any {
	switch c := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(c))
		for k, x := range c {
			out[fn(k)] = rewriteAll(x, fn)
		}
		return out
	case []any:
		for i, x := range c {
			c[i] = rewriteAll(x, fn)
		}
		return c
	case string:
		return fn(c)
	}
	return v
}

// walkStrings calls fn for every string in v and replaces it with the result.
func walkStrings(v any, fn func(string) string) any {
	switch c := v.(type) {
	case map[string]any:
		for k, x := range c {
			c[k] = walkStrings(x, fn)
		}
		return c
	case []any:
		for i, x := range c {
			c[i] = walkStrings(x, fn)
		}
		return c
	case string:
		return fn(c)
	}
	return v
}
