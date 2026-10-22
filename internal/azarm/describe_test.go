package azarm

import (
	"strings"
	"testing"
)

func TestDescribe(t *testing.T) {
	reg := fixtures(t)
	d, err := reg.Describe("microsoft.compute/virtualmachines", "", 3)
	if err != nil {
		t.Fatal(err)
	}
	has := func(path string) (ro, req, secret bool) {
		for _, f := range d.Fields {
			if f.Path == path {
				return f.ReadOnly, f.Required, f.Secret
			}
		}
		t.Errorf("no field %s", path)
		return
	}
	if _, _, s := has("properties.osProfile.adminPassword"); !s {
		t.Error("adminPassword must be secret")
	}
	if ro, _, _ := has("id"); !ro {
		t.Error("id is read-only")
	}
	if _, req, _ := has("location"); !req {
		t.Error("location is required")
	}
	if d.Name != "Microsoft.Compute/virtualMachines" || !strings.Contains(d.Docs[0], "/azure/templates/microsoft.compute/"+d.Version+"/virtualmachines") {
		t.Errorf("name %s, docs %v", d.Name, d.Docs)
	}
	found := false
	for _, n := range reg.Names() {
		found = found || n == "Microsoft.Compute/virtualMachines"
	}
	if !found {
		t.Error("Names lost Azure's spelling")
	}
}
