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
	if strings.Contains(canon(spec), "hunter2") {
		t.Error("password present somewhere in spec")
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
