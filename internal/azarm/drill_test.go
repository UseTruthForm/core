package azarm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackdna/core/internal/drilltest"
	"github.com/stackdna/core/internal/platform"
	"github.com/stackdna/core/internal/snapshot"
)

var _ platform.Platform = (*Adapter)(nil)

const (
	srcSub    = "11111111-1111-1111-1111-111111111111"
	dstSub    = "22222222-2222-2222-2222-222222222222"
	srcTenant = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	dstTenant = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	password  = "Not-On-Disk-9f3!"
)

func id(sub, rg, typ, name string) string {
	return ResourceID{Subscription: sub, ResourceGroup: rg, Type: typ, Name: name}.String()
}

func put(t *testing.T, f *Fake, rg, typ, name string, body map[string]any) string {
	t.Helper()
	i := id(f.sub, rg, typ, name)
	if typ == groupType {
		i = id(f.sub, name, groupType, name)
	}
	v := stable(f.w.reg, typ)
	if _, err := f.Put(context.Background(), i, v, body); err != nil {
		t.Fatalf("seed %s: %v", i, err)
	}
	return i
}

const (
	assignmentID = "6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b"
	customRoleID = "0d1c2b3a-4f5e-4d6c-8b7a-6f5e4d3c2b1a"
	builtInID    = "acdd72a7-3385-48ef-bd42-f606fba81ae7" // Reader
)

// stable is the version a person (and capture) would use: the newest
// non-preview one.
func stable(r *Registry, typ string) string {
	for _, v := range r.Versions(typ) {
		if !strings.Contains(v, "preview") {
			return v
		}
	}
	return r.Versions(typ)[0]
}

// rawPut seeds any ID, extension resources included.
func rawPut(t *testing.T, f *Fake, i, typ string, body map[string]any) {
	t.Helper()
	if _, err := f.Put(context.Background(), i, stable(f.w.reg, typ), body); err != nil {
		t.Fatalf("seed %s: %v", i, err)
	}
}

// seedBuiltInRole adds what every subscription lists: one of Azure's own roles.
func seedBuiltInRole(t *testing.T, f *Fake) {
	rawPut(t, f, "/subscriptions/"+f.sub+"/providers/Microsoft.Authorization/roleDefinitions/"+builtInID, "Microsoft.Authorization/roleDefinitions", map[string]any{
		"properties": map[string]any{"roleName": "Reader", "type": "BuiltInRole", "assignableScopes": []any{"/"}}})
}

// networkWatcher is what Azure creates in every subscription that uses
// networking: a resource group of its own.
// azureBehaviour makes a fake subscription do what Azure does on create
// beyond the definitions: an NSG gets default rules no one can write.
func azureBehaviour(f *Fake) {
	f.AfterCreate = func(id string, body map[string]any) {
		if rid, _ := ParseID(id); rid.Type == "Microsoft.Network/networkSecurityGroups" {
			f.SeedAzure(id+"/defaultSecurityRules/AllowVnetInBound", "2025-07-01", map[string]any{
				"properties": map[string]any{"access": "Allow", "direction": "Inbound", "priority": 65000, "protocol": "*"}})
		}
	}
}

func networkWatcher(t *testing.T, f *Fake) {
	put(t, f, "", groupType, "NetworkWatcherRG", map[string]any{"location": "eastus"})
	seedBuiltInRole(t, f)
}

// seedShop builds a small application the way a person or Bicep would,
// wiring references with the subscription's real resource IDs.
func seedShop(t *testing.T, f *Fake) {
	networkWatcher(t, f)
	put(t, f, "", groupType, "shop-rg", map[string]any{"location": "eastus", "tags": map[string]any{"team": "shop"}})
	nsg := put(t, f, "shop-rg", "Microsoft.Network/networkSecurityGroups", "shop-nsg", map[string]any{
		"location": "eastus",
		"properties": map[string]any{"securityRules": []any{map[string]any{"name": "allow-https", "properties": map[string]any{
			"protocol": "Tcp", "access": "Allow", "direction": "Inbound", "priority": 100,
			"sourcePortRange": "*", "destinationPortRange": "443", "sourceAddressPrefix": "*", "destinationAddressPrefix": "*"}}}},
	})
	put(t, f, "shop-rg", "Microsoft.Network/virtualNetworks", "shop-vnet", map[string]any{
		"location": "eastus",
		"properties": map[string]any{
			"addressSpace": map[string]any{"addressPrefixes": []any{"10.20.0.0/16"}},
			"subnets": []any{map[string]any{"name": "app", "properties": map[string]any{
				"addressPrefix": "10.20.1.0/24", "networkSecurityGroup": map[string]any{"id": nsg}}}},
		},
	})
	ident := put(t, f, "shop-rg", "Microsoft.ManagedIdentity/userAssignedIdentities", "shop-id", map[string]any{"location": "eastus"})
	put(t, f, "shop-rg", "Microsoft.Storage/storageAccounts", "shopassets01", map[string]any{
		"location": "eastus", "kind": "StorageV2", "sku": map[string]any{"name": "Standard_LRS"},
		"properties": map[string]any{"minimumTlsVersion": "TLS1_2"},
	})
	plan := put(t, f, "shop-rg", "Microsoft.Web/serverfarms", "shop-plan", map[string]any{
		"location": "eastus", "sku": map[string]any{"name": "F1", "tier": "Free"},
	})
	// The identity is a map keyed by resource ID: the key must be remapped.
	put(t, f, "shop-rg", "Microsoft.Web/sites", "shop-web", map[string]any{
		"location":   "eastus",
		"identity":   map[string]any{"type": "UserAssigned", "userAssignedIdentities": map[string]any{ident: map[string]any{}}},
		"properties": map[string]any{"serverFarmId": plan, "httpsOnly": true},
	})
	put(t, f, "shop-rg", "Microsoft.Compute/virtualMachines", "shop-vm", map[string]any{
		"location": "eastus",
		"properties": map[string]any{
			"hardwareProfile": map[string]any{"vmSize": "Standard_B1s"},
			"osProfile":       map[string]any{"computerName": "shop-vm", "adminUsername": "shopadmin", "adminPassword": password},
		},
	})
	// What the subscription's resource list does not return.
	storage := id(f.sub, "shop-rg", "Microsoft.Storage/storageAccounts", "shopassets01")
	principal := f.Stored(ident)["properties"].(map[string]any)["principalId"]
	rawPut(t, f, storage+"/providers/Microsoft.Authorization/roleAssignments/"+assignmentID, "Microsoft.Authorization/roleAssignments", map[string]any{
		"properties": map[string]any{"principalId": principal, "principalType": "ServicePrincipal",
			"roleDefinitionId": "/subscriptions/" + f.sub + "/providers/Microsoft.Authorization/roleDefinitions/ba92f5b4-2d11-453d-a403-e96b0029c9fe"}})
	rawPut(t, f, "/subscriptions/"+f.sub+"/providers/Microsoft.Authorization/roleDefinitions/"+customRoleID, "Microsoft.Authorization/roleDefinitions", map[string]any{
		"properties": map[string]any{"roleName": "Shop reader", "type": "CustomRole",
			"permissions": []any{map[string]any{"actions": []any{"Microsoft.Storage/storageAccounts/read"}}}, "assignableScopes": []any{"/subscriptions/" + f.sub}}})
	rawPut(t, f, "/subscriptions/"+f.sub+"/resourceGroups/shop-rg/providers/Microsoft.Authorization/locks/no-delete", "Microsoft.Authorization/locks", map[string]any{
		"properties": map[string]any{"level": "CanNotDelete", "notes": "shop data"}})
	rawPut(t, f, storage+"/blobServices/default", "Microsoft.Storage/storageAccounts/blobServices", map[string]any{"properties": map[string]any{}})
	rawPut(t, f, storage+"/blobServices/default/containers/assets", "Microsoft.Storage/storageAccounts/blobServices/containers", map[string]any{
		"properties": map[string]any{"publicAccess": "None"}})
	nsgID := id(f.sub, "shop-rg", "Microsoft.Network/networkSecurityGroups", "shop-nsg")
	rawPut(t, f, nsgID+"/providers/Microsoft.Insights/diagnosticSettings/to-storage", "Microsoft.Insights/diagnosticSettings", map[string]any{
		// The 2016-09-01 definition requires a location on diagnostic settings.
		"location":   "eastus",
		"properties": map[string]any{"storageAccountId": storage, "logs": []any{map[string]any{"categoryGroup": "allLogs", "enabled": true}}}})

	// A group another resource manages (an AKS node group): skipped.
	mc := put(t, f, "", groupType, "MC_shop_aks_eastus", map[string]any{"location": "eastus"})
	f.ManagedBy[strings.ToLower(mc)] = "/subscriptions/" + f.sub + "/resourceGroups/shop-rg/providers/Microsoft.ContainerService/managedClusters/aks"
}

var shopKeys = []string{
	groupType + "||shop-rg",
	"Microsoft.Network/networkSecurityGroups|shop-rg|shop-nsg",
	"Microsoft.Network/virtualNetworks|shop-rg|shop-vnet",
	"Microsoft.ManagedIdentity/userAssignedIdentities|shop-rg|shop-id",
	"Microsoft.Storage/storageAccounts|shop-rg|shopassets01",
	"Microsoft.Web/serverfarms|shop-rg|shop-plan",
	"Microsoft.Web/sites|shop-rg|shop-web",
	"Microsoft.Compute/virtualMachines|shop-rg|shop-vm",
	"Microsoft.Authorization/roleAssignments|shop-rg|providers/Microsoft.Storage/storageAccounts/shopassets01/providers/Microsoft.Authorization/roleAssignments/" + assignmentID,
	"Microsoft.Authorization/roleDefinitions||providers/Microsoft.Authorization/roleDefinitions/" + customRoleID,
	"Microsoft.Authorization/locks|shop-rg|no-delete",
	"Microsoft.Storage/storageAccounts/blobServices|shop-rg|shopassets01/default",
	"Microsoft.Storage/storageAccounts/blobServices/containers|shop-rg|shopassets01/default/assets",
	"Microsoft.Insights/diagnosticSettings|shop-rg|providers/Microsoft.Network/networkSecurityGroups/shop-nsg/providers/Microsoft.Insights/diagnosticSettings/to-storage",
}

type env struct {
	reg      *Registry
	src, dst *Fake
	pol      Policy
	vals     map[string]map[string]any
}

func newEnv(t *testing.T) env {
	reg := fixtures(t)
	w := NewWorld(reg)
	fresh := w.Subscription("33333333-3333-3333-3333-333333333333", "cccccccc-cccc-cccc-cccc-cccccccccccc")
	networkWatcher(t, fresh)
	base, err := Capture(context.Background(), fresh, reg, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	e := env{reg: reg, src: w.Subscription(srcSub, srcTenant), dst: w.Subscription(dstSub, dstTenant)}
	azureBehaviour(e.src)
	azureBehaviour(e.dst)
	e.pol = Policy{}.WithBaseline(base, "sha256:test-baseline")
	seedShop(t, e.src)
	networkWatcher(t, e.dst)
	e.vals = map[string]map[string]any{
		"Microsoft.Compute/virtualMachines/shop-rg/shop-vm": {"properties": map[string]any{"osProfile": map[string]any{"adminPassword": password}}},
	}
	return e
}

func (e env) adapter(f *Fake) *Adapter {
	return &Adapter{API: f, Registry: e.reg, Policy: e.pol, Options: RestoreOptions{Values: e.vals}}
}

func keys() []string {
	var out []string
	for _, k := range shopKeys {
		out = append(out, APIVersion+"|"+k)
	}
	return out
}

func TestDrillOnFakeSubscriptions(t *testing.T) {
	e := newEnv(t)
	snap := drilltest.Run(t, drilltest.Spec{Source: e.adapter(e.src), Target: e.adapter(e.dst), ExpectKeys: keys()})

	vnet := e.dst.Stored(id(dstSub, "shop-rg", "Microsoft.Network/virtualNetworks", "shop-vnet"))
	subnet := vnet["properties"].(map[string]any)["subnets"].([]any)[0].(map[string]any)
	if got := subnet["properties"].(map[string]any)["networkSecurityGroup"].(map[string]any)["id"]; !strings.Contains(got.(string), dstSub) {
		t.Errorf("subnet NSG reference not remapped: %v", got)
	}
	site := e.dst.Stored(id(dstSub, "shop-rg", "Microsoft.Web/sites", "shop-web"))
	for k := range site["identity"].(map[string]any)["userAssignedIdentities"].(map[string]any) {
		if !strings.Contains(k, dstSub) {
			t.Errorf("identity map key not remapped: %s", k)
		}
	}
	// The role assignment must name the identity the target created: its
	// principal is a new GUID there (the fake refuses the source's).
	dstIdent := e.dst.Stored(id(dstSub, "shop-rg", "Microsoft.ManagedIdentity/userAssignedIdentities", "shop-id"))
	ra := e.dst.Stored(id(dstSub, "shop-rg", "Microsoft.Storage/storageAccounts", "shopassets01") + "/providers/Microsoft.Authorization/roleAssignments/" + assignmentID)
	if got, want := ra["properties"].(map[string]any)["principalId"], dstIdent["properties"].(map[string]any)["principalId"]; got != want || got == nil {
		t.Errorf("role assignment principal %v, want the target identity's %v", got, want)
	}
	vm := e.dst.Stored(id(dstSub, "shop-rg", "Microsoft.Compute/virtualMachines", "shop-vm"))
	if vm["properties"].(map[string]any)["osProfile"].(map[string]any)["adminPassword"] != password {
		t.Error("VM admin password did not arrive")
	}
	for _, o := range snap.Objects {
		s := canon(o.Body["spec"])
		for _, bad := range []string{srcSub, srcTenant, password} {
			if strings.Contains(s, bad) {
				t.Errorf("%s spec contains %q", o.Key(), bad)
			}
		}
	}
	before := e.dst.Count()
	for _, r := range e.adapter(e.dst).Restore(context.Background(), snap) {
		if !r.OK || r.Detail != "already present and identical" {
			t.Errorf("second restore: %s: ok=%v %s", r.Key, r.OK, r.Detail)
		}
	}
	if e.dst.Count() != before {
		t.Error("second restore created resources")
	}
}

func TestSnapshotOnDisk(t *testing.T) {
	e := newEnv(t)
	snap, err := e.adapter(e.src).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := snap.Write(dir); err != nil {
		t.Fatal(err)
	}
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			if b, _ := os.ReadFile(p); strings.Contains(string(b), password) {
				t.Errorf("%s contains the password", p)
			}
		}
		return err
	})
	reasons := map[string]bool{}
	for _, s := range snap.Skips {
		reasons[s.Name+": "+strings.SplitN(s.Reason, ",", 2)[0]] = true
	}
	for _, want := range []string{
		"MC_shop_aks_eastus/MC_shop_aks_eastus: managed by /subscriptions/" + srcSub + "/resourceGroups/shop-rg/providers/Microsoft.ContainerService/managedClusters/aks",
		"NetworkWatcherRG/NetworkWatcherRG: identical to the baseline snapshot (already there",
	} {
		if !reasons[want] {
			t.Errorf("missing skip %q; have %v", want, reasons)
		}
	}
	for _, o := range snap.Objects {
		if o.Kind() == "Microsoft.Compute/virtualMachines" {
			ann := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
			if !strings.Contains(ann[annSecrets].(string), "properties.osProfile.adminPassword") {
				t.Errorf("VM secrets annotation %v", ann[annSecrets])
			}
		}
	}
}

// Without the password, the VM is created but the result says what was
// not supplied: a VM restored without its credential must not read as done.
func TestRestoreNamesUnsuppliedSecrets(t *testing.T) {
	e := newEnv(t)
	snap, _ := e.adapter(e.src).Capture(context.Background())
	a := e.adapter(e.dst)
	a.Options = RestoreOptions{}
	for _, r := range a.Restore(context.Background(), snap) {
		if strings.Contains(r.Key, "virtualMachines") && !strings.Contains(r.Detail, "secret, not supplied: properties.osProfile.adminPassword") {
			t.Errorf("vm: ok=%v %s", r.OK, r.Detail)
		}
	}
}

// The fake refuses another subscription's IDs, in values and in keys.
func TestFakeRefusesForeignSubscription(t *testing.T) {
	reg := fixtures(t)
	w := NewWorld(reg)
	a, b := w.Subscription(srcSub, srcTenant), w.Subscription(dstSub, dstTenant)
	put(t, a, "", groupType, "rg", map[string]any{"location": "eastus"})
	put(t, b, "", groupType, "rg", map[string]any{"location": "eastus"})
	ident := put(t, a, "rg", "Microsoft.ManagedIdentity/userAssignedIdentities", "id1", map[string]any{"location": "eastus"})
	_, err := b.Put(context.Background(), id(dstSub, "rg", "Microsoft.Web/sites", "web"), reg.Versions("Microsoft.Web/sites")[0], map[string]any{
		"location": "eastus", "identity": map[string]any{"type": "UserAssigned", "userAssignedIdentities": map[string]any{ident: map[string]any{}}},
	})
	if err == nil || !strings.Contains(err.Error(), "LinkedAuthorizationFailed") {
		t.Fatalf("want a refusal for a foreign key, got %v", err)
	}
	_ = snapshot.Object{}
}

// An unchanged subscription captures to the same digest when only Azure's
// observations move between two reads: a time, a counter, an undeclared
// empty object that comes and goes.
func TestObservationsLeaveTheDigestAlone(t *testing.T) {
	e := newEnv(t)
	digest := func() string {
		t.Helper()
		snap, err := e.adapter(e.src).Capture(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		if err := snap.Write(dir); err != nil {
			t.Fatal(err)
		}
		d, err := snapshot.Digest(dir)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	first := digest()
	vm := id(srcSub, "shop-rg", "Microsoft.Compute/virtualMachines", "shop-vm")
	body := e.src.Stored(vm)
	props := body["properties"].(map[string]any)
	props["timeCreated"] = "2026-10-22T09:00:00Z"
	props["instanceView"] = map[string]any{"platformFaultDomain": 2.0}
	props["futureEmpty"] = map[string]any{}
	e.src.SeedAzure(vm, stable(e.reg, "Microsoft.Compute/virtualMachines"), body)
	if second := digest(); second != first {
		t.Errorf("digest moved with observations only: %s, then %s", first, second)
	}
}

// A resource reachable two ways (tracked, and its parent's child) is
// captured once; a duplicate object would make the snapshot unwritable.
func TestReachableTwiceIsCapturedOnce(t *testing.T) {
	e := newEnv(t)
	e.src.AlsoTracked = map[string]bool{"Microsoft.Storage/storageAccounts/blobServices/containers": true}
	snap, err := e.adapter(e.src).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, o := range snap.Objects {
		if o.Kind() == "Microsoft.Storage/storageAccounts/blobServices/containers" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("container captured %d times", n)
	}
	if err := snap.Write(t.TempDir()); err != nil {
		t.Fatal(err)
	}
}
