package azarm

import (
	"strings"
	"testing"
)

func fixtures(t *testing.T) *Registry {
	t.Helper()
	reg, err := LoadDefinitions("../../testdata/azure/types")
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func schema(t *testing.T, reg *Registry, typ string) *Schema {
	t.Helper()
	v := reg.Versions(typ)
	if len(v) == 0 {
		t.Fatalf("no versions for %s", typ)
	}
	s, err := reg.Schema(typ, v[0])
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// These definitions are Azure's, trimmed but unmodified. The assertions pin
// what the adapter relies on, so a format change Azure makes shows up here.
func TestDefinitionFacts(t *testing.T) {
	reg := fixtures(t)
	vnet := schema(t, reg, "Microsoft.Network/virtualNetworks")
	if vnet.Version != "2025-07-01" {
		t.Errorf("vnet version %s", vnet.Version)
	}
	f := vnet.Fields()
	for _, want := range []string{"location", "tags.*", "properties.addressSpace.addressPrefixes", "properties.subnets[].properties.addressPrefix", "properties.provisioningState"} {
		if !contains(f, want) {
			t.Errorf("vnet fields missing %q", want)
		}
	}
	if FieldsDigest(f) != FieldsDigest(vnet.Fields()) {
		t.Error("fields digest not stable")
	}
	// A VM's admin password is not flagged write-only; its string type is
	// marked sensitive. Missing that would treat the password as ordinary.
	vm := schema(t, reg, "Microsoft.Compute/virtualMachines")
	if !contains(vm.secretPaths(), "properties.osProfile.adminPassword") {
		t.Errorf("adminPassword not found as a secret: %v", vm.secretPaths())
	}
	if !contains(schema(t, reg, "Microsoft.Web/serverfarms").Required(), "location") {
		t.Error("location should be required on an App Service plan")
	}
}

func TestNormalize(t *testing.T) {
	reg := fixtures(t)
	vm := schema(t, reg, "Microsoft.Compute/virtualMachines")
	spec, sp := vm.normalize(map[string]any{
		"id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1", "name": "vm1",
		"type": "Microsoft.Compute/virtualMachines", "location": "eastus",
		"systemData": map[string]any{"createdAt": "2026-10-21T00:00:00Z"},
		"properties": map[string]any{
			"provisioningState": "Succeeded", "vmId": "1111",
			"osProfile":       map[string]any{"computerName": "vm1", "adminUsername": "alex", "adminPassword": "hunter2"},
			"hardwareProfile": map[string]any{"vmSize": "Standard_B1s"},
			"futureField":     "kept",
		},
	})
	props := spec["properties"].(map[string]any)
	if _, ok := props["osProfile"].(map[string]any)["adminPassword"]; ok {
		t.Error("adminPassword survived normalize")
	}
	if !contains(sp.secrets, "properties.osProfile.adminPassword") {
		t.Errorf("secret not listed: %v", sp.secrets)
	}
	if _, ok := props["provisioningState"]; ok || sp.readOnly["properties.provisioningState"] != "Succeeded" {
		t.Errorf("read-only value not moved: spec %v readOnly %v", props, sp.readOnly)
	}
	for _, k := range []string{"id", "name", "type", "systemData"} {
		if _, ok := spec[k]; ok {
			t.Errorf("envelope key %s kept in spec", k)
		}
	}
	// A field the definition does not know is newer than the definition:
	// kept, never dropped without a word.
	if props["futureField"] != "kept" {
		t.Error("unknown field was dropped")
	}
	// Except what ARM always sets: a subnet's resourceGuid is undeclared in
	// the 2026-03-01 definition and showed as drift after a real restore.
	vnet := schema(t, reg, "Microsoft.Network/virtualNetworks")
	vspec, _ := vnet.normalize(map[string]any{"location": "eastus", "properties": map[string]any{
		"subnets": []any{map[string]any{"name": "app", "properties": map[string]any{"addressPrefix": "10.0.1.0/24", "resourceGuid": "g-1", "undeclaredSetting": true}}}}})
	sub := vspec["properties"].(map[string]any)["subnets"].([]any)[0].(map[string]any)["properties"].(map[string]any)
	if _, ok := sub["resourceGuid"]; ok || sub["undeclaredSetting"] != true {
		t.Errorf("subnet properties after normalize: %v", sub)
	}
	if strings.Contains(canon(spec), "hunter2") {
		t.Error("password present somewhere in spec")
	}
}

// Two captures of an unchanged subscription must be identical. Read-only
// times and counters change on their own, so status keeps only what a
// reference can point at; an undeclared empty object Azure returns only
// sometimes is dropped.
func TestCaptureLeavesOutObservations(t *testing.T) {
	reg := fixtures(t)
	vm := schema(t, reg, "Microsoft.Compute/virtualMachines")
	api := NewWorld(reg).Subscription("00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-0000000000aa")
	id := "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"
	rid, err := ParseID(id)
	if err != nil {
		t.Fatal(err)
	}
	c := process(api, "00000000-0000-0000-0000-0000000000aa", rid, vm.Version, vm, map[string]any{
		"id": id, "name": "vm1", "location": "eastus",
		"properties": map[string]any{
			"provisioningState": "Succeeded", "vmId": "22223333-4444-4555-8666-777788889999",
			"timeCreated": "2026-10-21T08:15:00.1234567+00:00",
			"instanceView": map[string]any{"platformFaultDomain": 1.0, "isVMInStandbyPool": false, "hyperVGeneration": "V2",
				"lastBoot": "2026-10-21", "statusTime": "10/21/2026 8:15:00 AM", "spaced": "2026-10-21 08:15:00"},
			"hardwareProfile": map[string]any{},
			"osProfile":       map[string]any{"futureEmpty": map[string]any{}},
			"networkProfile": map[string]any{"networkInterfaces": []any{map[string]any{
				"id": "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic1", "futureEmpty": map[string]any{}}}},
			"futureEmpty":   map[string]any{},
			"futureSetting": map[string]any{"mode": "on"},
		},
	})
	for _, k := range []string{"properties.vmId", "properties.provisioningState", "properties.instanceView.hyperVGeneration"} {
		if _, ok := c.status[k]; !ok {
			t.Errorf("status lost %s: %v", k, c.status)
		}
	}
	for _, k := range []string{"properties.timeCreated", "properties.instanceView.platformFaultDomain", "properties.instanceView.isVMInStandbyPool",
		"properties.instanceView.lastBoot", "properties.instanceView.statusTime", "properties.instanceView.spaced"} {
		if _, ok := c.status[k]; ok {
			t.Errorf("status kept the observation %s", k)
		}
	}
	props := c.spec["properties"].(map[string]any)
	if _, ok := props["futureEmpty"]; ok {
		t.Error("undeclared empty object kept")
	}
	if _, ok := props["futureSetting"]; !ok {
		t.Error("undeclared setting dropped")
	}
	// A declared object that arrived empty is kept as it was, and so is
	// one that held only an undeclared empty object (review of #31): it
	// must read the same as when Azure leaves the inner object out.
	if _, ok := props["hardwareProfile"]; !ok {
		t.Error("declared empty object dropped")
	}
	if os, ok := props["osProfile"].(map[string]any); !ok || len(os) != 0 {
		t.Errorf("osProfile after normalize: %v", props["osProfile"])
	}
	nic := props["networkProfile"].(map[string]any)["networkInterfaces"].([]any)[0].(map[string]any)
	if _, ok := nic["futureEmpty"]; ok {
		t.Error("undeclared empty object kept inside an array element")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// Azure returns "never" (TimeSpan.MaxValue) rounded several ways; each
// spelling seen in a real subscription reads as the one Azure documents,
// so an unchanged entity never reads as changed. Other durations are left
// as they are.
func TestNeverHasOneSpelling(t *testing.T) {
	vm := schema(t, fixtures(t), "Microsoft.Compute/virtualMachines")
	for in, want := range map[string]string{
		"P10675199DT2H48M5.4775807S": never,
		"P10675199DT2H48M5.477S":     never,
		"P10675198DT2H48M5.477S":     never,
		"P10675198DT2H48M5S":         never,
		"P1D":                        "P1D",
		"P10675199DT2H48M4S":         "P10675199DT2H48M4S",
		"PT10675199S":                "PT10675199S",
	} {
		spec, _ := vm.normalize(map[string]any{"location": "eastus", "properties": map[string]any{"futureDuration": in}})
		if got := spec["properties"].(map[string]any)["futureDuration"]; got != want {
			t.Errorf("%s became %v, want %s", in, got, want)
		}
	}
}
